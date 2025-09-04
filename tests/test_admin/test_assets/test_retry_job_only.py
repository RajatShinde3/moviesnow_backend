import pytest

BASE = "/api/v1/admin"


# ─────────────────────────────────────────────────────────────────────────────
# Lightweight fake Redis wrapper just for these tests
# ─────────────────────────────────────────────────────────────────────────────
class _FakeRedisWrapper:
    def __init__(self):
        self._json = {}      # key -> python object
        self._sets = {}      # key -> set()
        self._lists = {}     # key -> [values]

        class _Client:
            def __init__(self, sets, lists):
                self._sets = sets
                self._lists = lists

            async def sadd(self, key, member):
                self._sets.setdefault(key, set()).add(member)

            async def smembers(self, key):
                return set(self._sets.get(key, set()))

            async def rpush(self, key, value):
                self._lists.setdefault(key, []).append(value)

        self.client = _Client(self._sets, self._lists)

    async def json_get(self, key, default=None):
        return self._json.get(key, default)

    async def json_set(self, key, value, ttl_seconds=None):
        self._json[key] = value


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures aligned with your existing admin test setup
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
        "JOBS_SET_KEY": bulk_mod.JOBS_SET_KEY,
        "QUEUE_LIST_KEY": bulk_mod.QUEUE_LIST_KEY,
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
# Happy paths + filtering
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_retry_success_only_failed(async_client, _fake_redis, _bulk_consts):
    src_id = "job-src1"
    src_key = _bulk_consts["JOB_KEY_T"].format(job_id=src_id)
    items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=src_id)

    # Seed source job + items (mix of statuses)
    await _fake_redis.json_set(src_key, {"id": src_id, "status": "FAILED", "submitted_at_ms": 1, "items_count": 4})
    items = [
        {"id": "i1", "status": "failed"},
        {"id": "i2", "status": "error"},
        {"id": "i3", "status": "completed"},
        {"id": "i4", "status": "queued"},
    ]
    await _fake_redis.json_set(items_key, items)

    payload = {"only_failed": True, "include_pending": False}
    r = await async_client.post(f"{BASE}/bulk/jobs/{src_id}/retry", json=payload)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["status"] == "QUEUED"
    new_id = body["job_id"]
    assert body["requeued_items"] == 2  # i1 + i2

    # New job envelope exists
    new_key = _bulk_consts["JOB_KEY_T"].format(job_id=new_id)
    new_env = await _fake_redis.json_get(new_key)
    assert new_env and new_env["id"] == new_id and new_env["status"] == "QUEUED"
    assert new_env["retry_of"] == src_id
    assert new_env["items_count"] == 2

    # New job items list was written
    new_items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=new_id)
    new_items = await _fake_redis.json_get(new_items_key)
    assert isinstance(new_items, list) and len(new_items) == 2

    # Added to jobs set
    members = await _fake_redis.client.smembers(_bulk_consts["JOBS_SET_KEY"])
    assert new_id in members

    # Source bookkeeping updated
    updated_src = await _fake_redis.json_get(src_key)
    assert updated_src["retries"] == 1
    assert updated_src["last_retry_job_id"] == new_id
    # Status was already set on source; code preserves existing status if present
    assert updated_src["status"] == "FAILED"


@pytest.mark.anyio
async def test_retry_success_include_pending(async_client, _fake_redis, _bulk_consts):
    src_id = "job-src2"
    src_key = _bulk_consts["JOB_KEY_T"].format(job_id=src_id)
    items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=src_id)

    await _fake_redis.json_set(src_key, {"id": src_id, "status": "FAILED", "submitted_at_ms": 2})
    items = [
        {"id": "i1", "status": "failed"},
        {"id": "i2", "status": "running"},
        {"id": "i3", "status": "pending"},
        {"id": "i4", "status": "queued"},
        {"id": "i5", "status": "completed"},
    ]
    await _fake_redis.json_set(items_key, items)

    payload = {"only_failed": True, "include_pending": True}
    r = await async_client.post(f"{BASE}/bulk/jobs/{src_id}/retry", json=payload)
    assert r.status_code == 202
    body = r.json()
    # failed + running + pending + queued = 4
    assert body["requeued_items"] == 4


@pytest.mark.anyio
async def test_retry_success_all_items_when_only_failed_false(async_client, _fake_redis, _bulk_consts):
    src_id = "job-src3"
    src_key = _bulk_consts["JOB_KEY_T"].format(job_id=src_id)
    items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=src_id)

    await _fake_redis.json_set(src_key, {"id": src_id, "status": "COMPLETED", "submitted_at_ms": 3})
    items = [{"id": f"i{i}", "status": s} for i, s in enumerate(["queued", "running", "completed", "failed", "error"], 1)]
    await _fake_redis.json_set(items_key, items)

    payload = {"only_failed": False, "include_pending": False}
    r = await async_client.post(f"{BASE}/bulk/jobs/{src_id}/retry", json=payload)
    assert r.status_code == 202
    assert r.json()["requeued_items"] == len(items)


@pytest.mark.anyio
async def test_retry_success_when_no_items_present_manifest_based(async_client, _fake_redis, _bulk_consts):
    # No :items key; worker is manifest_url-driven; items_count should carry over.
    src_id = "job-src4"
    src_key = _bulk_consts["JOB_KEY_T"].format(job_id=src_id)

    await _fake_redis.json_set(src_key, {
        "id": src_id,
        "status": "FAILED",
        "submitted_at_ms": 4,
        "manifest_url": "s3://bucket/path.json",
        "items_count": 42
    })

    payload = {"only_failed": True, "include_pending": False}
    r = await async_client.post(f"{BASE}/bulk/jobs/{src_id}/retry", json=payload)
    assert r.status_code == 202
    body = r.json()
    assert body["requeued_items"] == 0  # retry_pool empty
    new_id = body["job_id"]
    new_env = await _fake_redis.json_get(_bulk_consts["JOB_KEY_T"].format(job_id=new_id))
    assert new_env["manifest_url"] == "s3://bucket/path.json"
    assert new_env["items_count"] == 42  # carried over from source


# ─────────────────────────────────────────────────────────────────────────────
# Error cases
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_retry_404_when_source_missing(async_client):
    r = await async_client.post(f"{BASE}/bulk/jobs/nope/retry", json={"only_failed": True, "include_pending": False})
    assert r.status_code == 404
    assert "Job not found" in r.text


@pytest.mark.anyio
async def test_retry_redis_exception_on_source_json_get(async_client, _fake_redis, _bulk_consts, monkeypatch):
    src_id = "boom-source"
    src_key = _bulk_consts["JOB_KEY_T"].format(job_id=src_id)

    async def _boom(_key, default=None):
        assert _key == src_key
        raise RuntimeError("redis down")

    monkeypatch.setattr(_fake_redis, "json_get", _boom, raising=True)

    try:
        r = await async_client.post(f"{BASE}/bulk/jobs/{src_id}/retry", json={"only_failed": True, "include_pending": False})
        assert r.status_code >= 500
    except RuntimeError as exc:
        assert "redis down" in str(exc)


@pytest.mark.anyio
async def test_retry_fails_when_new_job_env_json_set_fails(async_client, _fake_redis, _bulk_consts, monkeypatch):
    src_id = "fail-new-env"
    src_key = _bulk_consts["JOB_KEY_T"].format(job_id=src_id)
    items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=src_id)

    await _fake_redis.json_set(src_key, {"id": src_id, "status": "FAILED", "submitted_at_ms": 5})
    await _fake_redis.json_set(items_key, [{"id": "i1", "status": "failed"}])

    async def _json_set_maybe_boom(key, value, ttl_seconds=None):
        # First json_set in route is for the *new job* envelope and includes "retry_of"
        if isinstance(value, dict) and value.get("retry_of") == src_id:
            raise RuntimeError("cannot write new env")
        # otherwise pass through
        return await _FakeRedisWrapper.json_set(_fake_redis, key, value, ttl_seconds)

    monkeypatch.setattr(_fake_redis, "json_set", _json_set_maybe_boom, raising=True)

    r = await async_client.post(f"{BASE}/bulk/jobs/{src_id}/retry", json={"only_failed": True, "include_pending": False})
    assert r.status_code == 503
    assert "Could not enqueue retry job" in r.text


@pytest.mark.anyio
async def test_retry_fails_when_jobs_set_sadd_fails(async_client, _fake_redis, _bulk_consts, monkeypatch):
    src_id = "fail-sadd"
    src_key = _bulk_consts["JOB_KEY_T"].format(job_id=src_id)
    items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=src_id)

    await _fake_redis.json_set(src_key, {"id": src_id, "status": "FAILED", "submitted_at_ms": 6})
    await _fake_redis.json_set(items_key, [{"id": "i1", "status": "failed"}])

    async def _boom_sadd(keyname, member):
        assert keyname == _bulk_consts["JOBS_SET_KEY"]
        raise RuntimeError("sadd failed")

    monkeypatch.setattr(_fake_redis.client, "sadd", _boom_sadd, raising=True)

    r = await async_client.post(f"{BASE}/bulk/jobs/{src_id}/retry", json={"only_failed": True, "include_pending": False})
    assert r.status_code == 503
    assert "Could not enqueue retry job" in r.text


@pytest.mark.anyio
async def test_retry_fails_when_items_json_set_fails(async_client, _fake_redis, _bulk_consts, monkeypatch):
    src_id = "fail-items-set"
    src_key = _bulk_consts["JOB_KEY_T"].format(job_id=src_id)
    items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=src_id)

    await _fake_redis.json_set(src_key, {"id": src_id, "status": "FAILED", "submitted_at_ms": 7})
    await _fake_redis.json_set(items_key, [{"id": "i1", "status": "failed"}, {"id": "i2", "status": "error"}])

    async def _json_set_boom_on_list(key, value, ttl_seconds=None):
        if isinstance(value, list):
            raise RuntimeError("list write failed")
        return await _FakeRedisWrapper.json_set(_fake_redis, key, value, ttl_seconds)

    monkeypatch.setattr(_fake_redis, "json_set", _json_set_boom_on_list, raising=True)

    r = await async_client.post(f"{BASE}/bulk/jobs/{src_id}/retry", json={"only_failed": True, "include_pending": False})
    assert r.status_code == 503
    assert "Could not enqueue retry job" in r.text


@pytest.mark.anyio
async def test_retry_fails_when_source_bookkeeping_update_fails(async_client, _fake_redis, _bulk_consts, monkeypatch):
    src_id = "fail-src-update"
    src_key = _bulk_consts["JOB_KEY_T"].format(job_id=src_id)
    items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=src_id)

    await _fake_redis.json_set(src_key, {"id": src_id, "status": "FAILED", "submitted_at_ms": 8})
    await _fake_redis.json_set(items_key, [{"id": "i1", "status": "failed"}])

    async def _json_set_boom_on_src_key(key, value, ttl_seconds=None):
        if key == src_key:
            raise RuntimeError("cannot update src")
        return await _FakeRedisWrapper.json_set(_fake_redis, key, value, ttl_seconds)

    monkeypatch.setattr(_fake_redis, "json_set", _json_set_boom_on_src_key, raising=True)

    r = await async_client.post(f"{BASE}/bulk/jobs/{src_id}/retry", json={"only_failed": True, "include_pending": False})
    assert r.status_code == 503
    assert "Could not enqueue retry job" in r.text


@pytest.mark.anyio
async def test_retry_still_works_when_rpush_fails(async_client, _fake_redis, _bulk_consts, monkeypatch):
    src_id = "rpush-fail"
    src_key = _bulk_consts["JOB_KEY_T"].format(job_id=src_id)
    items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=src_id)

    await _fake_redis.json_set(src_key, {"id": src_id, "status": "FAILED", "submitted_at_ms": 9})
    await _fake_redis.json_set(items_key, [{"id": "i1", "status": "failed"}])

    async def _boom_rpush(keyname, value):
        assert keyname == _bulk_consts["QUEUE_LIST_KEY"]
        raise RuntimeError("queue push failed")

    monkeypatch.setattr(_fake_redis.client, "rpush", _boom_rpush, raising=True)

    r = await async_client.post(f"{BASE}/bulk/jobs/{src_id}/retry", json={"only_failed": True, "include_pending": False})
    # rpush failure is swallowed → still 202
    assert r.status_code == 202
    assert r.json()["status"] == "QUEUED"
