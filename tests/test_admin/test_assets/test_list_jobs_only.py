# tests/test_admin/test_bulk/test_list_jobs_only.py
import uuid
import pytest
from typing import Any, Dict, List

BASE = "/api/v1/admin"

# ─────────────────────────────────────────────────────────────────────────────
# Minimal in-memory Redis fakes used by the route
# ─────────────────────────────────────────────────────────────────────────────

class _FakeRedisClient:
    def __init__(self):
        self.kv: Dict[str, Any] = {}
        self.sets: Dict[str, set] = {}
        self.lists: Dict[str, List[str]] = {}

    async def sadd(self, key: str, member: str) -> int:
        s = self.sets.setdefault(key, set())
        before = len(s)
        s.add(member)
        return 1 if len(s) > before else 0

    async def smembers(self, key: str):
        return self.sets.get(key, set())

    async def rpush(self, key: str, value: str) -> int:
        self.lists.setdefault(key, []).append(value)
        return len(self.lists[key])

    async def delete(self, key: str) -> int:
        deleted = 0
        if key in self.kv:
            del self.kv[key]; deleted += 1
        if key in self.sets:
            del self.sets[key]; deleted += 1
        if key in self.lists:
            del self.lists[key]; deleted += 1
        return deleted


class _FakeRedisWrapper:
    def __init__(self):
        self.client = _FakeRedisClient()
        self._idem: Dict[str, Any] = {}

    async def json_set(self, key: str, value: Any, ttl_seconds: int | None = None):
        self.client.kv[key] = value

    async def json_get(self, key: str, default: Any | None = None):
        return self.client.kv.get(key, default)

    async def idempotency_get(self, key: str):
        return self._idem.get(key)

    async def idempotency_set(self, key: str, value: Any, ttl_seconds: int | None = None):
        self._idem[key] = value


# ─────────────────────────────────────────────────────────────────────────────
# Global fixtures: admin/MFA no-ops, user override, audit no-op, Redis fake
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _mock_admin_mfa(monkeypatch):
    import app.dependencies.admin as admin_deps
    async def _noop(*_a, **_k): return None
    monkeypatch.setattr(admin_deps, "ensure_admin", _noop)
    monkeypatch.setattr(admin_deps, "ensure_mfa", _noop)


@pytest.fixture(autouse=True)
async def _override_current_user(app):
    from app.core.security import get_current_user
    async def _dep():
        class _U:
            id = uuid.UUID("00000000-0000-0000-0000-000000000001")
            is_superuser = True
        return _U()
    app.dependency_overrides[get_current_user] = _dep
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch):
    import app.services.audit_log_service as als
    async def _noop(**_k): return None
    monkeypatch.setattr(als, "log_audit_event", _noop)


@pytest.fixture(autouse=True)
def _fake_redis(monkeypatch):
    fake = _FakeRedisWrapper()
    # Bind both where it's defined and where it's imported into the router
    import app.core.redis_client as rc
    monkeypatch.setattr(rc, "redis_wrapper", fake, raising=True)

    import app.api.v1.routers.admin.assets.bulk as bulk_mod
    monkeypatch.setattr(bulk_mod, "redis_wrapper", fake, raising=True)
    return fake


@pytest.fixture(scope="module")
def _bulk_consts():
    import app.api.v1.routers.admin.assets.bulk as bulk_mod
    return {
        "JOBS_SET_KEY": bulk_mod.JOBS_SET_KEY,
        "JOB_KEY_T": bulk_mod.JOB_KEY_T,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _add_job(fake, consts, *, job_id: str, status: str, submitted_at_ms: int, **extra):
    """Create a job envelope and register its id in the jobs set."""
    JOBS_SET_KEY = consts["JOBS_SET_KEY"]
    JOB_KEY_T = consts["JOB_KEY_T"]
    await fake.client.sadd(JOBS_SET_KEY, job_id)
    env = {
        "id": job_id,
        "status": status,
        "submitted_at_ms": submitted_at_ms,
        **extra,
    }
    await fake.json_set(JOB_KEY_T.format(job_id=job_id), env)


# ─────────────────────────────────────────────────────────────────────────────
# Tests — GET /bulk/jobs
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_jobs_empty_when_redis_empty(async_client):
    r = await async_client.get(f"{BASE}/bulk/jobs")
    assert r.status_code == 200
    data = r.json()
    assert data["jobs"] == []
    assert data["total"] == 0
    assert data["next_offset"] is None


@pytest.mark.anyio
async def test_jobs_lists_sorted_desc(async_client, _fake_redis, _bulk_consts):
    # Newest first by submitted_at_ms
    await _add_job(_fake_redis, _bulk_consts, job_id="a", status="QUEUED",    submitted_at_ms=1000)
    await _add_job(_fake_redis, _bulk_consts, job_id="b", status="RUNNING",   submitted_at_ms=3000)
    await _add_job(_fake_redis, _bulk_consts, job_id="c", status="COMPLETED", submitted_at_ms=2000)

    r = await async_client.get(f"{BASE}/bulk/jobs")
    assert r.status_code == 200
    jobs = r.json()["jobs"]
    ids = [j["id"] for j in jobs]
    assert ids == ["b", "c", "a"]


@pytest.mark.anyio
async def test_jobs_filter_by_status_all_buckets(async_client, _fake_redis, _bulk_consts):
    # Clear out anything from previous tests
    _fake_redis.client.sets.clear()
    _fake_redis.client.kv.clear()

    pairs = [
        ("q1", "QUEUED",       1000),
        ("q2", "RETRY_QUEUED", 1100),  # should be included in "queued"
        ("r1", "RUNNING",      1200),
        ("c1", "COMPLETED",    1300),
        ("f1", "FAILED",       1400),
        ("x1", "CANCELLED",    1500),
        ("a1", "ABORTED",      1600),
    ]
    for jid, st, ts in pairs:
        await _add_job(_fake_redis, _bulk_consts, job_id=jid, status=st, submitted_at_ms=ts)

    async def _ids_for(filter_value: str):
        r = await async_client.get(f"{BASE}/bulk/jobs", params={"status_filter": filter_value})
        assert r.status_code == 200
        return {j["id"] for j in r.json()["jobs"]}

    assert await _ids_for("all")       == {"q1", "q2", "r1", "c1", "f1", "x1", "a1"}
    assert await _ids_for("queued")    == {"q1", "q2"}
    assert await _ids_for("running")   == {"r1"}
    assert await _ids_for("completed") == {"c1"}
    assert await _ids_for("failed")    == {"f1"}
    assert await _ids_for("cancelled") == {"x1"}
    assert await _ids_for("aborted")   == {"a1"}


@pytest.mark.anyio
async def test_jobs_pagination(async_client, _fake_redis, _bulk_consts):
    # Clear & seed 5 jobs with descending timestamps
    _fake_redis.client.sets.clear()
    _fake_redis.client.kv.clear()

    # Newest has largest ts
    for i, ts in enumerate([5000, 4000, 3000, 2000, 1000], start=1):
        await _add_job(_fake_redis, _bulk_consts, job_id=f"j{i}", status="QUEUED", submitted_at_ms=ts)

    # page 1
    r1 = await async_client.get(f"{BASE}/bulk/jobs", params={"offset": 0, "limit": 2})
    d1 = r1.json()
    assert [j["id"] for j in d1["jobs"]] == ["j1", "j2"]
    assert d1["total"] == 5
    assert d1["next_offset"] == 2

    # page 2
    r2 = await async_client.get(f"{BASE}/bulk/jobs", params={"offset": 2, "limit": 2})
    d2 = r2.json()
    assert [j["id"] for j in d2["jobs"]] == ["j3", "j4"]
    assert d2["total"] == 5
    assert d2["next_offset"] == 4

    # page 3 (last)
    r3 = await async_client.get(f"{BASE}/bulk/jobs", params={"offset": 4, "limit": 2})
    d3 = r3.json()
    assert [j["id"] for j in d3["jobs"]] == ["j5"]
    assert d3["total"] == 5
    assert d3["next_offset"] is None


@pytest.mark.anyio
async def test_jobs_handles_smembers_failure(async_client, _fake_redis, monkeypatch):
    async def _boom(*_a, **_k):
        raise RuntimeError("nope")
    monkeypatch.setattr(_fake_redis.client, "smembers", _boom)

    r = await async_client.get(f"{BASE}/bulk/jobs")
    assert r.status_code == 200
    d = r.json()
    assert d["jobs"] == []
    assert d["total"] == 0
    assert d["next_offset"] is None


@pytest.mark.anyio
async def test_jobs_skips_corrupt_envelopes(async_client, _fake_redis, _bulk_consts, monkeypatch):
    # Seed two ids; make one json_get fail
    _fake_redis.client.sets.clear()
    _fake_redis.client.kv.clear()

    await _add_job(_fake_redis, _bulk_consts, job_id="ok", status="QUEUED", submitted_at_ms=1000)
    await _add_job(_fake_redis, _bulk_consts, job_id="bad", status="QUEUED", submitted_at_ms=2000)

    original_json_get = _fake_redis.json_get

    async def _json_get_conditional(key: str, default=None):
        if key.endswith(":bad"):
            raise RuntimeError("corrupt")
        return await original_json_get(key, default)

    monkeypatch.setattr(_fake_redis, "json_get", _json_get_conditional)

    r = await async_client.get(f"{BASE}/bulk/jobs")
    assert r.status_code == 200
    ids = [j["id"] for j in r.json()["jobs"]]
    # 'bad' skipped, only 'ok' remains
    assert ids == ["ok"]
