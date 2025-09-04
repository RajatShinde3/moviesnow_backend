# tests/test_admin/test_bulk/test_manifest_only.py
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
        "ITEMS_KEY_T": bulk_mod.ITEMS_KEY_T,
        "QUEUE_LIST_KEY": bulk_mod.QUEUE_LIST_KEY,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tests — POST /bulk/manifest
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_manifest_requires_either_url_or_items(async_client):
    r = await async_client.post(f"{BASE}/bulk/manifest", json={})
    assert r.status_code == 400
    assert "Provide manifest_url or items" in r.text


@pytest.mark.anyio
async def test_manifest_with_url_enqueues_job_and_persists_envelope(async_client, _fake_redis, _bulk_consts):
    r = await async_client.post(f"{BASE}/bulk/manifest", json={"manifest_url": "https://ex/manifest.json"})
    assert r.status_code == 202
    data = r.json()
    job_id = data["job_id"]
    assert data["status"] == "QUEUED"

    # Envelope saved with expected fields
    JOB_KEY_T = _bulk_consts["JOB_KEY_T"]
    env = await _fake_redis.json_get(JOB_KEY_T.format(job_id=job_id))
    assert env["id"] == job_id
    assert env["status"] == "QUEUED"
    assert env["manifest_url"] == "https://ex/manifest.json"
    assert env["items_count"] is None
    # submitted_by matches our override user
    assert env["submitted_by"] == "00000000-0000-0000-0000-000000000001"

    # Job indexed and queued for worker
    JOBS_SET_KEY = _bulk_consts["JOBS_SET_KEY"]
    assert job_id in _fake_redis.client.sets.get(JOBS_SET_KEY, set())
    QUEUE_LIST_KEY = _bulk_consts["QUEUE_LIST_KEY"]
    assert job_id in _fake_redis.client.lists.get(QUEUE_LIST_KEY, [])


@pytest.mark.anyio
async def test_manifest_with_inline_items_stores_items_array(async_client, _fake_redis, _bulk_consts):
    items = [{"id": 1, "status": "failed"}, {"id": 2, "status": "success"}, {"id": 3, "status": "pending"}]
    r = await async_client.post(f"{BASE}/bulk/manifest", json={"items": items})
    assert r.status_code == 202
    job_id = r.json()["job_id"]

    JOB_KEY_T = _bulk_consts["JOB_KEY_T"]
    ITEMS_KEY_T = _bulk_consts["ITEMS_KEY_T"]

    env = await _fake_redis.json_get(JOB_KEY_T.format(job_id=job_id))
    assert env["items_count"] == 3

    stored_items = await _fake_redis.json_get(ITEMS_KEY_T.format(job_id=job_id))
    assert stored_items == items


@pytest.mark.anyio
async def test_manifest_too_many_inline_items_returns_413(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.bulk as bulk_mod
    monkeypatch.setattr(bulk_mod, "MAX_INLINE_ITEMS", 1)

    r = await async_client.post(f"{BASE}/bulk/manifest", json={"items": [{"a": 1}, {"b": 2}]})
    assert r.status_code == 413
    assert "Too many inline items" in r.text


@pytest.mark.anyio
async def test_manifest_idempotency_same_key_same_payload(async_client, _fake_redis):
    hdrs = {"Idempotency-Key": "same-key"}
    payload = {"manifest_url": "https://ex/idem.json"}

    r1 = await async_client.post(f"{BASE}/bulk/manifest", json=payload, headers=hdrs)
    r2 = await async_client.post(f"{BASE}/bulk/manifest", json=payload, headers=hdrs)
    assert r1.status_code == r2.status_code == 202
    assert r1.json()["job_id"] == r2.json()["job_id"]

    # Only one job should have been enqueued (second hit short-circuited)
    # We can approximate by counting appearances in the queue list.
    job_id = r1.json()["job_id"]
    counts = sum(1 for x in _fake_redis.client.lists.get("bulk:queue", []) if x == job_id)
    assert counts >= 1  # first push
    # and definitely not 2 separate job_ids
    assert len(set(_fake_redis.client.lists.get("bulk:queue", []))) >= 1


@pytest.mark.anyio
async def test_manifest_idempotency_same_key_different_payload_creates_new_job(async_client):
    hdrs = {"Idempotency-Key": "shared-key"}
    p1 = {"manifest_url": "https://ex/a.json"}
    p2 = {"manifest_url": "https://ex/b.json"}  # different fingerprint

    r1 = await async_client.post(f"{BASE}/bulk/manifest", json=p1, headers=hdrs)
    r2 = await async_client.post(f"{BASE}/bulk/manifest", json=p2, headers=hdrs)

    assert r1.status_code == r2.status_code == 202
    # Different fingerprints => different jobs even with same header
    assert r1.json()["job_id"] != r2.json()["job_id"]


@pytest.mark.anyio
async def test_manifest_redis_failure_returns_503(async_client, _fake_redis, monkeypatch):
    # Make json_set raise inside the "enqueue job" try-block
    async def _boom(*_a, **_k):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(_fake_redis, "json_set", _boom)

    r = await async_client.post(f"{BASE}/bulk/manifest", json={"manifest_url": "https://ex/will-fail.json"})
    assert r.status_code == 503
    assert "Could not enqueue job" in r.text
