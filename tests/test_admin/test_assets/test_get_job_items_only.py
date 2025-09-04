import pytest
from types import SimpleNamespace

BASE = "/api/v1/admin"


# --- Test Fixtures ------------------------------------------------------------

@pytest.fixture
def _bulk_consts():
    # Pull real constants from the router so tests don't drift.
    from app.api.v1.routers.admin.assets import bulk as mod
    return {
        "JOB_KEY_T": getattr(mod, "JOB_KEY_T"),
        "ITEMS_KEY_T": getattr(mod, "ITEMS_KEY_T"),
        "ERRORS_KEY_T": getattr(mod, "ERRORS_KEY_T"),
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


class _FakeRedisWrapper:
    """Tiny in-memory stand-in for redis_wrapper used by this test file."""
    def __init__(self):
        # Simple key-value store for JSON payloads
        self._json = {}

    async def json_get(self, key, default=None):
        return self._json.get(key, default)

    async def json_set(self, key, value, ttl_seconds=None):
        self._json[key] = value
        return True


@pytest.fixture
def _fake_redis(monkeypatch):
    from app.api.v1.routers.admin.assets import bulk as mod
    fake = _FakeRedisWrapper()
    # Swap the module-level redis_wrapper with our fake for the duration
    monkeypatch.setattr(mod, "redis_wrapper", fake, raising=True)
    return fake


# --- Tests --------------------------------------------------------------------

@pytest.mark.anyio
async def test_items_404_when_job_missing(async_client, _fake_redis, _bulk_consts):
    jid = "nope"
    r = await async_client.get(f"{BASE}/bulk/jobs/{jid}/items")
    assert r.status_code == 404
    assert "Job not found" in r.text


@pytest.mark.anyio
async def test_items_returns_empty_when_no_items_or_errors(async_client, _fake_redis, _bulk_consts):
    jid = "j1"
    job_key = _bulk_consts["JOB_KEY_T"].format(job_id=jid)

    # Only envelope present
    await _fake_redis.json_set(job_key, {"id": jid, "status": "QUEUED"})

    r = await async_client.get(f"{BASE}/bulk/jobs/{jid}/items")
    assert r.status_code == 200

    data = r.json()
    assert data["job"] == {"id": jid, "status": "QUEUED"}
    assert data["items"] == []
    assert data["items_total"] == 0
    assert data["next_offset"] is None
    # errors should be None unless only_errors=true
    assert data["errors"] is None
    assert data["errors_total"] == 0


@pytest.mark.anyio
async def test_items_only_errors_includes_errors(async_client, _fake_redis, _bulk_consts):
    jid = "j2"
    job_key = _bulk_consts["JOB_KEY_T"].format(job_id=jid)
    items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=jid)
    errors_key = _bulk_consts["ERRORS_KEY_T"].format(job_id=jid)

    await _fake_redis.json_set(job_key, {"id": jid, "status": "RUNNING"})
    await _fake_redis.json_set(items_key, [{"id": "a", "status": "success"}])
    await _fake_redis.json_set(errors_key, [{"id": "e1", "error": "boom"}])

    r = await async_client.get(f"{BASE}/bulk/jobs/{jid}/items", params={"only_errors": "true"})
    assert r.status_code == 200
    data = r.json()

    # items still paginate/return as usual; errors are included when only_errors=true
    assert data["items"] == [{"id": "a", "status": "success"}]
    assert data["errors"] == [{"id": "e1", "error": "boom"}]
    assert data["errors_total"] == 1


@pytest.mark.anyio
async def test_items_pagination(async_client, _fake_redis, _bulk_consts):
    jid = "j3"
    job_key = _bulk_consts["JOB_KEY_T"].format(job_id=jid)
    items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=jid)

    await _fake_redis.json_set(job_key, {"id": jid, "status": "RUNNING"})
    items = [{"i": i, "status": "success"} for i in range(5)]
    await _fake_redis.json_set(items_key, items)

    # page 1 (limit 2)
    r = await async_client.get(f"{BASE}/bulk/jobs/{jid}/items", params={"offset": 0, "limit": 2})
    assert r.status_code == 200
    data = r.json()
    assert data["items"] == items[0:2]
    assert data["items_total"] == 5
    assert data["next_offset"] == 2

    # page 2
    r = await async_client.get(f"{BASE}/bulk/jobs/{jid}/items", params={"offset": 2, "limit": 2})
    data = r.json()
    assert data["items"] == items[2:4]
    assert data["next_offset"] == 4

    # last page
    r = await async_client.get(f"{BASE}/bulk/jobs/{jid}/items", params={"offset": 4, "limit": 2})
    data = r.json()
    assert data["items"] == items[4:5]
    assert data["next_offset"] is None


@pytest.mark.anyio
async def test_items_status_filter_variants(async_client, _fake_redis, _bulk_consts):
    jid = "j4"
    job_key = _bulk_consts["JOB_KEY_T"].format(job_id=jid)
    items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=jid)

    await _fake_redis.json_set(job_key, {"id": jid, "status": "RUNNING"})
    # Include variants that map to your buckets:
    items = [
        {"id": "a", "status": "failed"},
        {"id": "b", "status": "error"},
        {"id": "c", "status": "success"},
        {"id": "d", "status": "succeeded"},
        {"id": "e", "status": "done"},
        {"id": "f", "status": "queued"},
        {"id": "g", "status": "pending"},
        {"id": "h", "status": "running"},
        {"id": "i", "status": "mystery"},
    ]
    await _fake_redis.json_set(items_key, items)

    # failed → failed or error
    r = await async_client.get(f"{BASE}/bulk/jobs/{jid}/items", params={"status": "failed"})
    assert [x["id"] for x in r.json()["items"]] == ["a", "b"]

    # succeeded → success/succeeded/done
    r = await async_client.get(f"{BASE}/bulk/jobs/{jid}/items", params={"status": "succeeded"})
    assert [x["id"] for x in r.json()["items"]] == ["c", "d", "e"]

    # pending → queued/pending/running
    r = await async_client.get(f"{BASE}/bulk/jobs/{jid}/items", params={"status": "pending"})
    assert [x["id"] for x in r.json()["items"]] == ["f", "g", "h"]

    # error → strictly "error"
    r = await async_client.get(f"{BASE}/bulk/jobs/{jid}/items", params={"status": "error"})
    assert [x["id"] for x in r.json()["items"]] == ["b"]

    # all (default) returns everything
    r = await async_client.get(f"{BASE}/bulk/jobs/{jid}/items")
    assert len(r.json()["items"]) == len(items)


@pytest.mark.anyio
async def test_items_defensive_normalization(async_client, _fake_redis, _bulk_consts):
    jid = "j5"
    job_key = _bulk_consts["JOB_KEY_T"].format(job_id=jid)
    items_key = _bulk_consts["ITEMS_KEY_T"].format(job_id=jid)
    errors_key = _bulk_consts["ERRORS_KEY_T"].format(job_id=jid)

    await _fake_redis.json_set(job_key, {"id": jid, "status": "RUNNING"})
    await _fake_redis.json_set(items_key, [{"ok": 1}, "bad", 123, None, {"ok": 2}])
    await _fake_redis.json_set(errors_key, [{"err": 1}, "nope"])

    r = await async_client.get(f"{BASE}/bulk/jobs/{jid}/items", params={"only_errors": "true"})
    assert r.status_code == 200
    data = r.json()

    # Only dict entries survive normalization
    assert data["items"] == [{"ok": 1}, {"ok": 2}]
    assert data["errors"] == [{"err": 1}]
    assert data["errors_total"] == 1


@pytest.mark.anyio
async def test_items_redis_exception_bubbles(async_client, _fake_redis, _bulk_consts, monkeypatch):
    """If Redis raises during json_get, the route should bubble to a 500."""
    jid = "boom"
    job_key = _bulk_consts["JOB_KEY_T"].format(job_id=jid)

    # Ensure we patch *after* inserting anything (we want job read to raise)
    await _fake_redis.json_set(job_key, {"id": jid, "status": "RUNNING"})

    async def _boom_json_get(key, default=None):
        # Fail only when fetching the job envelope
        if key == job_key:
            raise RuntimeError("redis down")
        return await _fake_redis.json_get(key, default=default)

    from app.api.v1.routers.admin.assets import bulk as mod
    monkeypatch.setattr(mod.redis_wrapper, "json_get", _boom_json_get, raising=True)

    r = await async_client.get(f"{BASE}/bulk/jobs/{jid}/items")
    assert r.status_code == 500
