import pytest
from typing import Any, Dict, List, Optional
from fastapi import HTTPException

BASE = "/api/v1/admin"


# -----------------------------
# Test Doubles / Fakes
# -----------------------------
class _FakeRedisClient:
    async def delete(self, *keys: str):  # type: ignore[no-untyped-def]
        return 1


class _FakeRedisWrapper:
    def __init__(self):
        self.client = _FakeRedisClient()
        self.last_json_set: Optional[Dict[str, Any]] = None
        self._json_get_map: Dict[str, Any] = {}

    async def json_set(self, key: str, value: Any, ttl_seconds: int):
        self.last_json_set = {"key": key, "value": value, "ttl": ttl_seconds}
        self._json_get_map[key] = value

    async def json_get(self, key: str, default=None):
        return self._json_get_map.get(key, default)


# -----------------------------
# Shared stubs
# -----------------------------
async def _noop(*args, **kwargs):
    return None


# -----------------------------
# Fixtures
# -----------------------------
@pytest.fixture
def _fake_redis():
    return _FakeRedisWrapper()


@pytest.fixture(autouse=True)
def _patch_admin_auth(monkeypatch):
    """
    Make `ensure_admin` and `ensure_mfa` no-ops so we don't need real auth/MFA in tests.
    (The route imports them at call time from app.dependencies.admin.)
    """
    import app.dependencies.admin as admin_mod

    monkeypatch.setattr(admin_mod, "ensure_admin", _noop, raising=True)
    monkeypatch.setattr(admin_mod, "ensure_mfa", _noop, raising=True)


@pytest.fixture(autouse=True)
async def _override_current_user(app):
    """Provide a valid UUID-bearing admin user for dependency-based auth."""
    import uuid as _uuid
    from app.core.security import get_current_user

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


@pytest.fixture(autouse=True)
def _patch_redis_and_audit(monkeypatch, _fake_redis):
    # Patch redis wrapper used by the route module
    import app.api.v1.routers.admin.assets.cdn_delivery as mod
    monkeypatch.setattr(mod, "redis_wrapper", _fake_redis, raising=True)

    # Make audit logging best-effort: record calls but never block tests
    calls = {"count": 0, "last": None}

    async def _audit_stub(db, user, action, status, request, meta_data=None):
        calls["count"] += 1
        calls["last"] = {"action": action, "status": status, "meta": meta_data}

    monkeypatch.setattr(mod, "log_audit_event", _audit_stub, raising=True)
    return calls  # in case a test wants to inspect it


# -----------------------------
# Tests
# -----------------------------

@pytest.mark.anyio
async def test_status_not_found_returns_404(async_client, _fake_redis):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod
    key = mod.INV_STATE_KEY_T.format(request_id="missing")
    # Ensure nothing in redis
    _fake_redis._json_get_map.pop(key, None)

    r = await async_client.get(f"{BASE}/cdn/invalidation/missing")
    assert r.status_code == 404
    assert r.json()["detail"].lower().startswith("invalidation request not found")


@pytest.mark.anyio
async def test_status_queue_provider_returns_cached(async_client, _fake_redis):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod
    req_id = "r-queue"
    key = mod.INV_STATE_KEY_T.format(request_id=req_id)
    cached = {
        "request_id": req_id,
        "provider": "queue",
        "paths": ["/a", "/b*"],
        "status": "QUEUED",
        "created_at": "2024-01-01T00:00:00Z",
    }
    _fake_redis._json_get_map[key] = cached

    r = await async_client.get(f"{BASE}/cdn/invalidation/{req_id}")
    assert r.status_code == 200
    assert r.json() == cached  # unchanged; no CloudFront call for provider=queue


@pytest.mark.anyio
async def test_status_cloudfront_refresh_success(async_client, _fake_redis, monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod
    req_id = "r-cf-ok"
    key = mod.INV_STATE_KEY_T.format(request_id=req_id)
    state = {
        "request_id": req_id,
        "provider": "cloudfront",
        "distribution_id": "D123",
        "invalidation_id": "INV-9",
        "status": "InProgress",
        "created_at": "2024-01-01T00:00:00Z",
    }
    _fake_redis._json_get_map[key] = state

    class _FakeCF:
        def get_invalidation(self, DistributionId, Id):
            assert DistributionId == "D123"
            assert Id == "INV-9"
            return {"Invalidation": {"Status": "Completed"}}

    monkeypatch.setattr(mod.boto3, "client", lambda *a, **k: _FakeCF(), raising=True)

    r = await async_client.get(f"{BASE}/cdn/invalidation/{req_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "Completed"
    assert "last_checked_at" in body
    # Verify the refresh was persisted to redis (best-effort)
    assert _fake_redis.last_json_set is not None
    assert _fake_redis.last_json_set["key"] == key
    assert _fake_redis.last_json_set["value"]["status"] == "Completed"


@pytest.mark.anyio
async def test_status_cloudfront_refresh_error_returns_cached(async_client, _fake_redis, monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod
    req_id = "r-cf-boom"
    key = mod.INV_STATE_KEY_T.format(request_id=req_id)
    cached = {
        "request_id": req_id,
        "provider": "cloudfront",
        "distribution_id": "DERR",
        "invalidation_id": "INV-ERR",
        "status": "InProgress",
        "created_at": "2024-01-01T00:00:00Z",
    }
    _fake_redis._json_get_map[key] = cached

    class _BoomCF:
        def get_invalidation(self, *a, **k):
            raise RuntimeError("CF down")

    monkeypatch.setattr(mod.boto3, "client", lambda *a, **k: _BoomCF(), raising=True)

    r = await async_client.get(f"{BASE}/cdn/invalidation/{req_id}")
    assert r.status_code == 200
    assert r.json() == cached  # falls back to cached state


@pytest.mark.anyio
async def test_status_audit_errors_are_swallowed(async_client, _fake_redis, monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod
    req_id = "r-audit"
    key = mod.INV_STATE_KEY_T.format(request_id=req_id)
    cached = {"request_id": req_id, "provider": "queue", "status": "QUEUED"}
    _fake_redis._json_get_map[key] = cached

    async def _boom_audit(*a, **k):
        raise RuntimeError("audit sink down")

    # Force audit error; response must still be OK
    monkeypatch.setattr(mod, "log_audit_event", _boom_audit, raising=True)

    r = await async_client.get(f"{BASE}/cdn/invalidation/{req_id}")
    assert r.status_code == 200
    assert r.json() == cached


@pytest.mark.anyio
async def test_status_redis_exception_bubbles(async_client, _fake_redis, monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod
    req_id = "boom"
    key = mod.INV_STATE_KEY_T.format(request_id=req_id)

    async def _boom(_key: str, default=None):
        assert _key == key
        raise RuntimeError("redis down")

    monkeypatch.setattr(_fake_redis, "json_get", _boom, raising=True)

    # Route does not catch redis errors → expect 500
    with pytest.raises(RuntimeError, match="redis down"):
        await async_client.get(f"{BASE}/cdn/invalidation/{req_id}")


@pytest.mark.anyio
async def test_status_auth_guard_kicks_in(async_client, monkeypatch, _fake_redis):
    """
    Demonstrate that if ensure_admin raises, the route returns the error (403 here).
    """
    import app.dependencies.admin as admin_mod
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    # Put something in redis so we'd normally get 200 if auth passed
    req_id = "r-auth"
    key = mod.INV_STATE_KEY_T.format(request_id=req_id)
    _fake_redis._json_get_map[key] = {"request_id": req_id, "provider": "queue", "status": "QUEUED"}

    async def _deny(*_, **__):
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(admin_mod, "ensure_admin", _deny, raising=True)

    r = await async_client.get(f"{BASE}/cdn/invalidation/{req_id}")
    assert r.status_code == 403
    assert r.json()["detail"] == "forbidden"
