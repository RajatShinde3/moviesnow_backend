# tests/test_admin/test_assets/test_cdn_invalidate.py
import importlib
from typing import Any, Dict, List, Optional

import pytest
from fastapi import HTTPException

BASE = "/api/v1/admin"


# -----------------------------
# Test Doubles / Fakes
# -----------------------------
class _FakeRedisClient:
    def __init__(self):
        self.rpush_calls: List[Dict[str, Any]] = []
        self._rpush_raises: Optional[Exception] = None

    async def rpush(self, key: str, *items: str):
        if self._rpush_raises:
            raise self._rpush_raises
        self.rpush_calls.append({"key": key, "items": list(items)})

    # Unused here but present so the wrapper looks realistic
    async def delete(self, *keys: str):  # type: ignore[no-untyped-def]
        return 1

    async def sadd(self, key: str, *members: str):  # type: ignore[no-untyped-def]
        return len(members)

    async def srem(self, key: str, *members: str):  # type: ignore[no-untyped-def]
        return len(members)


class _FakeRedisWrapper:
    def __init__(self):
        self.client = _FakeRedisClient()
        self._idem_snapshot: Optional[Dict[str, Any]] = None
        self.idem_set_calls: List[Dict[str, Any]] = []
        self.last_json_set: Optional[Dict[str, Any]] = None
        self._json_get_map: Dict[str, Any] = {}

    # Idempotency helpers
    async def idempotency_get(self, key: str):
        self.last_idem_get_key = key  # type: ignore[attr-defined]
        return self._idem_snapshot

    async def idempotency_set(self, key: str, value: Dict[str, Any], ttl_seconds: int):
        self.idem_set_calls.append({"key": key, "value": value, "ttl": ttl_seconds})

    # Simple JSON doc store
    async def json_set(self, key: str, value: Any, ttl_seconds: int):
        self.last_json_set = {"key": key, "value": value, "ttl": ttl_seconds}
        self._json_get_map[key] = value

    async def json_get(self, key: str, default=None):
        return self._json_get_map.get(key, default)

    # Lock context manager (no-op)
    class _Lock:
        async def __aenter__(self):  # pragma: no cover
            return None

        async def __aexit__(self, exc_type, exc, tb):  # pragma: no cover
            return False

    def lock(self, *_, **__):
        return self._Lock()


# -----------------------------
# Shared stubs
# -----------------------------
async def _noop(*args, **kwargs):
    return None


# -----------------------------
# Autouse: reset rate limits for EVERY test
# -----------------------------
@pytest.fixture(autouse=True)
def _reset_rate_limits_between_tests():
    """
    Clear SlowAPI/limits storage so the 6/min route budget doesn't bleed
    across tests in this module.
    """
    # Your project wires the limiter in app.core.limiter
    for modpath in ("app.core.limiter",):
        try:
            mod = importlib.import_module(modpath)
            limiter = getattr(mod, "limiter", None)
            if not limiter:
                continue
            # Try common locations where the underlying limits storage sits
            storage = getattr(limiter, "storage", None) or getattr(limiter, "_storage", None)
            if getattr(storage, "storage", None):  # some wrappers have .storage.storage
                storage = storage.storage
            if storage and hasattr(storage, "clear"):
                storage.clear()
        except Exception:
            # Keep tests resilient regardless of the backend
            pass


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
async def test_invalidate_empty_payload_400(async_client):
    r = await async_client.post(f"{BASE}/cdn/invalidate", json={"paths": [], "prefixes": []})
    assert r.status_code == 400
    assert r.json()["detail"].lower().startswith("provide at least one")


@pytest.mark.anyio
async def test_invalidate_normalizes_and_queues_when_no_cloudfront(async_client, _fake_redis, monkeypatch):
    # Ensure NO distribution id is configured
    import app.api.v1.routers.admin.assets.cdn_delivery as mod
    monkeypatch.setattr(mod.settings, "CLOUDFRONT_DISTRIBUTION_ID", None, raising=True)

    payload = {
        "paths": ["videos/a.m3u8", "/b.jpg", "b.jpg"],   # duplicates normalize to "/b.jpg"
        "prefixes": ["images", "/css/*"],                # -> "/images*", "/css/*"
    }
    r = await async_client.post(f"{BASE}/cdn/invalidate", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "QUEUED"
    assert data["paths"] == ["/videos/a.m3u8", "/b.jpg", "/images*", "/css/*"]

    # Verify queue push got those paths in order
    assert _fake_redis.client.rpush_calls, "expected a queue push"
    call = _fake_redis.client.rpush_calls[-1]
    assert call["key"] == "cdn:invalidate:queue"
    assert call["items"] == data["paths"]


@pytest.mark.anyio
async def test_invalidate_cloudfront_success(async_client, _fake_redis, monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    # Configure CloudFront, stub boto3
    monkeypatch.setattr(mod.settings, "CLOUDFRONT_DISTRIBUTION_ID", "D12345", raising=True)

    class _FakeCF:
        def create_invalidation(self, DistributionId, InvalidationBatch):
            assert DistributionId == "D12345"
            assert InvalidationBatch["Paths"]["Quantity"] == 2
            return {"Invalidation": {"Id": "INV-001"}}

    monkeypatch.setattr(mod.boto3, "client", lambda *a, **k: _FakeCF(), raising=True)

    r = await async_client.post(
        f"{BASE}/cdn/invalidate",
        json={"paths": ["/a.m3u8"], "prefixes": ["img/"]},
        headers={"Idempotency-Key": "abc123"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "SUBMITTED"
    assert body["distribution_id"] == "D12345"
    assert body["invalidation_id"] == "INV-001"
    # Idempotency snapshot should be recorded best-effort
    assert _fake_redis.idem_set_calls, "idempotency_set should be called on success"


@pytest.mark.anyio
async def test_invalidate_cloudfront_error_falls_back_to_queue(async_client, _fake_redis, monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    # Force CloudFront path but make it error → fallback to queue
    monkeypatch.setattr(mod.settings, "CLOUDFRONT_DISTRIBUTION_ID", "DERR", raising=True)

    class _BoomCF:
        def create_invalidation(self, *a, **k):
            raise RuntimeError("CF outage")

    monkeypatch.setattr(mod.boto3, "client", lambda *a, **k: _BoomCF(), raising=True)

    r = await async_client.post(f"{BASE}/cdn/invalidate", json={"paths": ["/one"], "prefixes": []})
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "QUEUED"
    # Queue should have been used
    assert _fake_redis.client.rpush_calls, "expected a queue push"
    assert _fake_redis.client.rpush_calls[-1]["items"] == ["/one"]


@pytest.mark.anyio
async def test_invalidate_idempotency_replay_short_circuits(async_client, _fake_redis, monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod
    # No CF, but we won't reach queue either due to idempotency replay
    monkeypatch.setattr(mod.settings, "CLOUDFRONT_DISTRIBUTION_ID", None, raising=True)

    snapshot = {"status": "QUEUED", "paths": ["/x", "/y"], "request_id": "prev"}
    _fake_redis._idem_snapshot = snapshot

    r = await async_client.post(
        f"{BASE}/cdn/invalidate",
        json={"paths": ["/should-not-run"], "prefixes": []},
        headers={"Idempotency-Key": "same-key"},
    )
    assert r.status_code == 200
    assert r.json() == snapshot
    # Ensure no queue push occurred (short-circuited)
    assert _fake_redis.client.rpush_calls == []


@pytest.mark.anyio
async def test_invalidate_queue_failure_returns_503(async_client, _fake_redis, monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod
    monkeypatch.setattr(mod.settings, "CLOUDFRONT_DISTRIBUTION_ID", None, raising=True)

    # Make the queue push fail
    _fake_redis.client._rpush_raises = RuntimeError("redis down")

    r = await async_client.post(f"{BASE}/cdn/invalidate", json={"paths": ["/a"], "prefixes": []})
    assert r.status_code == 503
    assert "Could not queue invalidation" in r.text


@pytest.mark.anyio
async def test_invalidate_audit_errors_are_swallowed(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    # Patch CloudFront so path succeeds (to reach audit call path),
    # and then make audit raise; response must still be 200.
    monkeypatch.setattr(mod.settings, "CLOUDFRONT_DISTRIBUTION_ID", "DOK", raising=True)

    class _OkCF:
        def create_invalidation(self, *a, **k):
            return {"Invalidation": {"Id": "INV-AUDIT"}}  # success

    monkeypatch.setattr(mod.boto3, "client", lambda *a, **k: _OkCF(), raising=True)

    async def _boom_audit(*a, **k):
        raise RuntimeError("audit sink down")

    monkeypatch.setattr(mod, "log_audit_event", _boom_audit, raising=True)

    r = await async_client.post(f"{BASE}/cdn/invalidate", json={"paths": ["/ok"], "prefixes": []})
    assert r.status_code == 200
    assert r.json()["invalidation_id"] == "INV-AUDIT"


@pytest.mark.anyio
async def test_invalidate_auth_guard_kicks_in(async_client, monkeypatch):
    """
    Demonstrate that if ensure_admin raises, the route returns the error (403 here).
    """
    import app.dependencies.admin as admin_mod

    async def _deny(*_, **__):
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(admin_mod, "ensure_admin", _deny, raising=True)

    r = await async_client.post(f"{BASE}/cdn/invalidate", json={"paths": ["/x"], "prefixes": []})
    assert r.status_code == 403
    assert r.json()["detail"] == "forbidden"
