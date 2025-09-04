import pytest

BASE = "/api/v1/admin"


# ─────────────────────────────────────────────────────────────────────────────
# Minimal fake Redis wrapper for these tests
# ─────────────────────────────────────────────────────────────────────────────
class _FakeRedisWrapper:
    def __init__(self):
        self._json = {}   # key -> python object
        self._sets = {}   # key -> set()

        class _Client:
            def __init__(self, outer):
                self._outer = outer

            async def sadd(self, key, member):
                self._outer._sets.setdefault(key, set()).add(member)

            async def smembers(self, key):
                return set(self._outer._sets.get(key, set()))

            async def srem(self, key, member):
                self._outer._sets.setdefault(key, set()).discard(member)

            async def delete(self, key):
                # emulate Redis: return count of keys removed, but don't error if missing
                return 1 if self._outer._json.pop(key, None) is not None else 0

        self.client = _Client(self)

    async def json_get(self, key, default=None):
        return self._json.get(key, default)

    async def json_set(self, key, value, ttl_seconds=None):
        self._json[key] = value


# ─────────────────────────────────────────────────────────────────────────────
# Shared fixtures
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def _fake_redis(monkeypatch):
    import app.api.v1.routers.admin.assets.bulk as bulk_mod
    fake = _FakeRedisWrapper()
    monkeypatch.setattr(bulk_mod, "redis_wrapper", fake, raising=False)
    return fake


@pytest.fixture
def _bulk_consts():
    import app.api.v1.routers.admin.assets.bulk as bulk_mod
    return {
        "JOB_KEY_T": bulk_mod.JOB_KEY_T,
        "ITEMS_KEY_T": bulk_mod.ITEMS_KEY_T,
        "ERRORS_KEY_T": bulk_mod.ERRORS_KEY_T,
        "JOBS_SET_KEY": bulk_mod.JOBS_SET_KEY,
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
# Happy paths
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_purge_success_terminal_completed(async_client, _fake_redis, _bulk_consts):
    job_id = "done-1"
    job_key = _bulk_consts["JOB_KEY_T"].format(job_id=job_id)
    items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=job_id)
    errs_key = _bulk_consts["ERRORS_KEY_T"].format(job_id=job_id)
    jobs_set = _bulk_consts["JOBS_SET_KEY"]

    # Seed job + artifacts
    await _fake_redis.json_set(job_key, {"id": job_id, "status": "COMPLETED"})
    await _fake_redis.json_set(items_key, [{"id": "i1"}])
    await _fake_redis.json_set(errs_key, [{"id": "e1"}])
    await _fake_redis.client.sadd(jobs_set, job_id)

    r = await async_client.delete(f"{BASE}/bulk/jobs/{job_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "PURGED" and body["job_id"] == job_id

    # Keys deleted
    assert await _fake_redis.json_get(job_key) is None
    assert await _fake_redis.json_get(items_key) is None
    assert await _fake_redis.json_get(errs_key) is None
    # Removed from index set
    members = await _fake_redis.client.smembers(jobs_set)
    assert job_id not in members


@pytest.mark.anyio
async def test_purge_success_force_overrides_non_terminal(async_client, _fake_redis, _bulk_consts):
    job_id = "running-1"
    job_key = _bulk_consts["JOB_KEY_T"].format(job_id=job_id)
    items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=job_id)
    errs_key = _bulk_consts["ERRORS_KEY_T"].format(job_id=job_id)

    await _fake_redis.json_set(job_key, {"id": job_id, "status": "RUNNING"})
    await _fake_redis.json_set(items_key, [{"id": "i1"}])
    await _fake_redis.json_set(errs_key, [])

    r = await async_client.delete(f"{BASE}/bulk/jobs/{job_id}?force=true")
    assert r.status_code == 200
    assert await _fake_redis.json_get(job_key) is None
    assert await _fake_redis.json_get(items_key) is None
    assert await _fake_redis.json_get(errs_key) is None


# ─────────────────────────────────────────────────────────────────────────────
# 404 / 409 behaviors
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_purge_404_when_job_missing_calls_srem(async_client, _fake_redis, _bulk_consts, monkeypatch):
    job_id = "nope"
    jobs_set = _bulk_consts["JOBS_SET_KEY"]
    called = {"srem": False}

    async def _spy_srem(key, member):
        called["srem"] = True
        # default behavior: just discard
        await _FakeRedisWrapper().client.srem(key, member)

    monkeypatch.setattr(_fake_redis.client, "srem", _spy_srem, raising=True)

    r = await async_client.delete(f"{BASE}/bulk/jobs/{job_id}")
    assert r.status_code == 404
    assert "Job not found" in r.text
    assert called["srem"] is True  # best-effort cleanup attempted


@pytest.mark.anyio
async def test_purge_409_when_not_terminal_without_force(async_client, _fake_redis, _bulk_consts):
    job_id = "not-done"
    job_key = _bulk_consts["JOB_KEY_T"].format(job_id=job_id)
    await _fake_redis.json_set(job_key, {"id": job_id, "status": "RUNNING"})

    r = await async_client.delete(f"{BASE}/bulk/jobs/{job_id}")
    assert r.status_code == 409
    assert "terminal state" in r.text.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Redis error propagation / handling
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_purge_redis_exception_on_json_get_bubbles(async_client, _fake_redis, _bulk_consts, monkeypatch):
    job_id = "boom"
    job_key = _bulk_consts["JOB_KEY_T"].format(job_id=job_id)

    async def _boom(_key, default=None):
        assert _key == job_key
        raise RuntimeError("redis down")

    monkeypatch.setattr(_fake_redis, "json_get", _boom, raising=True)

    # Depending on middleware, this may bubble (RuntimeError) or return 5xx.
    try:
        r = await async_client.delete(f"{BASE}/bulk/jobs/{job_id}")
        assert r.status_code >= 500
    except RuntimeError as exc:
        assert "redis down" in str(exc)


@pytest.mark.anyio
async def test_purge_returns_503_when_delete_fails(async_client, _fake_redis, _bulk_consts, monkeypatch):
    job_id = "del-fail"
    job_key = _bulk_consts["JOB_KEY_T"].format(job_id=job_id)
    items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=job_id)
    errs_key = _bulk_consts["ERRORS_KEY_T"].format(job_id=job_id)

    await _fake_redis.json_set(job_key, {"id": job_id, "status": "FAILED"})
    await _fake_redis.json_set(items_key, [{"id": "x"}])
    await _fake_redis.json_set(errs_key, [{"id": "e"}])

    async def _boom_delete(key):
        raise RuntimeError("cannot delete")

    monkeypatch.setattr(_fake_redis.client, "delete", _boom_delete, raising=True)

    r = await async_client.delete(f"{BASE}/bulk/jobs/{job_id}")
    assert r.status_code == 503
    assert "Could not purge job" in r.text


@pytest.mark.anyio
async def test_purge_returns_503_when_srem_fails(async_client, _fake_redis, _bulk_consts, monkeypatch):
    job_id = "srem-fail"
    job_key = _bulk_consts["JOB_KEY_T"].format(job_id=job_id)

    await _fake_redis.json_set(job_key, {"id": job_id, "status": "FAILED"})

    async def _boom_srem(key, member):
        raise RuntimeError("srem broke")

    monkeypatch.setattr(_fake_redis.client, "srem", _boom_srem, raising=True)

    r = await async_client.delete(f"{BASE}/bulk/jobs/{job_id}")
    assert r.status_code == 503
    assert "Could not purge job" in r.text


# ─────────────────────────────────────────────────────────────────────────────
# Edge: deleting when some keys are already missing should still succeed
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_purge_succeeds_when_items_or_errors_missing(async_client, _fake_redis, _bulk_consts):
    job_id = "partial"
    job_key = _bulk_consts["JOB_KEY_T"].format(job_id=job_id)
    # Seed only the main job key; items/errors absent
    await _fake_redis.json_set(job_key, {"id": job_id, "status": "FAILED"})

    r = await async_client.delete(f"{BASE}/bulk/jobs/{job_id}")
    assert r.status_code == 200
