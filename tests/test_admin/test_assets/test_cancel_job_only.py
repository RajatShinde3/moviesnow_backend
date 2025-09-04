import pytest

BASE = "/api/v1/admin"


# ─────────────────────────────────────────────────────────────────────────────
# Lightweight fake Redis wrapper used only by these tests
# ─────────────────────────────────────────────────────────────────────────────
class _FakeRedisWrapper:
    def __init__(self):
        self._json = {}
        self._sets = {}

        class _Client:
            def __init__(self, sets):
                self._sets = sets

            async def sadd(self, key, member):
                self._sets.setdefault(key, set()).add(member)

            async def smembers(self, key):
                return set(self._sets.get(key, set()))

        self.client = _Client(self._sets)

    async def json_get(self, key, default=None):
        return self._json.get(key, default)

    async def json_set(self, key, value, ttl_seconds=None):
        self._json[key] = value


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures mirroring your other admin tests
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def _fake_redis(monkeypatch):
    import app.api.v1.routers.admin.assets.bulk as bulk_mod
    fake = _FakeRedisWrapper()
    monkeypatch.setattr(bulk_mod, "redis_wrapper", fake, raising=False)
    return fake


@pytest.fixture
def _bulk_consts():
    # Pull route constants so tests don't hardcode keys or TTLs
    import app.api.v1.routers.admin.assets.bulk as bulk_mod
    return {
        "JOB_KEY_T": bulk_mod.JOB_KEY_T,
        "CANCEL_SET_KEY": bulk_mod.CANCEL_SET_KEY,
        "DEFAULT_TTL": bulk_mod.DEFAULT_TTL,
    }


@pytest.fixture(autouse=True)
def _mock_admin_mfa(monkeypatch):
    import app.dependencies.admin as admin_deps

    async def _noop(*args, **kwargs):
        return None

    monkeypatch.setattr(admin_deps, "ensure_admin", _noop)
    monkeypatch.setattr(admin_deps, "ensure_mfa", _noop)


@pytest.fixture(autouse=True)
async def _override_current_user(app):
    from app.core.security import get_current_user
    import uuid as _uuid

    async def _test_user_dep():
        class _U:
            id = _uuid.uuid4()
            is_superuser = True
        return _U()

    app.dependency_overrides[get_current_user] = _test_user_dep
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_current_user, None)


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_cancel_success_marks_status_and_sets_cancel_set(async_client, _fake_redis, _bulk_consts):
    jid = "abc123"
    key = _bulk_consts["JOB_KEY_T"].format(job_id=jid)

    # Seed a queued job envelope in Redis
    await _fake_redis.json_set(key, {
        "id": jid,
        "status": "QUEUED",
        "submitted_at_ms": 1234,
        "submitted_by": "tester",
    }, ttl_seconds=_bulk_consts["DEFAULT_TTL"])

    r = await async_client.post(f"{BASE}/bulk/jobs/{jid}/cancel")
    assert r.status_code == 200, r.text
    assert r.json() == {"status": "CANCEL_REQUESTED"}

    # Envelope updated
    env = await _fake_redis.json_get(key)
    assert env and env["status"] == "CANCEL_REQUESTED"

    # Job id added to cancel set
    members = await _fake_redis.client.smembers(_bulk_consts["CANCEL_SET_KEY"])
    assert jid in members


@pytest.mark.anyio
async def test_cancel_404_when_job_missing(async_client, _fake_redis):
    # Nothing seeded for this id
    r = await async_client.post(f"{BASE}/bulk/jobs/does-not-exist/cancel")
    assert r.status_code == 404
    assert "Job not found" in r.text


@pytest.mark.anyio
async def test_cancel_redis_error_on_json_set_returns_503(async_client, _fake_redis, _bulk_consts, monkeypatch):
    jid = "fail-on-set"
    key = _bulk_consts["JOB_KEY_T"].format(job_id=jid)

    await _fake_redis.json_set(key, {"id": jid, "status": "RUNNING"}, ttl_seconds=_bulk_consts["DEFAULT_TTL"])

    async def _boom_json_set(_key, value, ttl_seconds=None):
        assert _key == key
        raise RuntimeError("redis write failed")

    monkeypatch.setattr(_fake_redis, "json_set", _boom_json_set, raising=True)

    r = await async_client.post(f"{BASE}/bulk/jobs/{jid}/cancel")
    assert r.status_code == 503
    assert "Could not update job" in r.text

    # Envelope should remain unchanged
    env = await _fake_redis.json_get(key)
    assert env["status"] == "RUNNING"


@pytest.mark.anyio
async def test_cancel_redis_error_on_sadd_returns_503(async_client, _fake_redis, _bulk_consts, monkeypatch):
    jid = "fail-on-sadd"
    key = _bulk_consts["JOB_KEY_T"].format(job_id=jid)

    await _fake_redis.json_set(key, {"id": jid, "status": "QUEUED"}, ttl_seconds=_bulk_consts["DEFAULT_TTL"])

    async def _boom_sadd(keyname, member):
        assert keyname == _bulk_consts["CANCEL_SET_KEY"]
        assert member == jid
        raise RuntimeError("set add failed")

    monkeypatch.setattr(_fake_redis.client, "sadd", _boom_sadd, raising=True)

    r = await async_client.post(f"{BASE}/bulk/jobs/{jid}/cancel")
    assert r.status_code == 503
    assert "Could not update job" in r.text

    # Envelope should not be persisted to CANCEL_REQUESTED (both ops are in same try)
    env = await _fake_redis.json_get(key)
    # We did set data["status"] before the failing try, but because json_set is also in that try,
    # the stored envelope must still be the original "QUEUED".
    assert env["status"] == "QUEUED"


@pytest.mark.anyio
async def test_cancel_is_idempotent_repeated_calls(async_client, _fake_redis, _bulk_consts):
    jid = "idem"
    key = _bulk_consts["JOB_KEY_T"].format(job_id=jid)

    await _fake_redis.json_set(key, {"id": jid, "status": "QUEUED"}, ttl_seconds=_bulk_consts["DEFAULT_TTL"])

    r1 = await async_client.post(f"{BASE}/bulk/jobs/{jid}/cancel")
    assert r1.status_code == 200
    assert r1.json() == {"status": "CANCEL_REQUESTED"}

    r2 = await async_client.post(f"{BASE}/bulk/jobs/{jid}/cancel")
    assert r2.status_code == 200
    assert r2.json() == {"status": "CANCEL_REQUESTED"}

    env = await _fake_redis.json_get(key)
    assert env["status"] == "CANCEL_REQUESTED"

    members = await _fake_redis.client.smembers(_bulk_consts["CANCEL_SET_KEY"])
    # Set membership is unique; still present once
    assert jid in members


@pytest.mark.anyio
async def test_cancel_redis_exception_on_json_get_bubbles_or_500(async_client, _fake_redis, _bulk_consts, monkeypatch):
    # If Redis json_get raises, the route doesn't catch it.
    # Depending on middleware, this may bubble or convert to a 5xx response.
    jid = "boom"
    key = _bulk_consts["JOB_KEY_T"].format(job_id=jid)

    async def _boom_json_get(_key, default=None):
        assert _key == key
        raise RuntimeError("redis down")

    monkeypatch.setattr(_fake_redis, "json_get", _boom_json_get, raising=True)

    try:
        r = await async_client.post(f"{BASE}/bulk/jobs/{jid}/cancel")
        # If the exception is handled upstream, we should see a 500-ish
        assert r.status_code >= 500
    except RuntimeError as exc:
        # In other stacks, it bubbles out directly.
        assert "redis down" in str(exc)
