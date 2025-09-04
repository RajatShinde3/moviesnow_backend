# tests/test_admin/test_api/test_create_api_keys.py

import uuid
import importlib
from typing import Any, Dict, List, Tuple, Optional, Callable

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


def _mk_app(monkeypatch, *,
            user_id: Optional[str] = None,
            idem_get_impl: Optional[Callable[[str], Any]] = None,
            idem_set_impl: Optional[Callable[[str, Dict[str, Any], int], Any]] = None,
            create_impl: Optional[Callable[..., Dict[str, Any]]] = None,
            audit_impl: Optional[Callable[..., Any]] = None):
    """
    Build a small FastAPI app and patch collaborators inside the module under test.
    """
    mod = importlib.import_module("app.api.v1.routers.admin.api_keys")

    # Bypass rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Admin + MFA no-ops by default
    async def _ok_admin(user): return None
    async def _ok_mfa(request): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok_admin, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok_mfa, raising=False)

    # Idempotency helpers (can be overridden per-test)
    class _Idem:
        async def idempotency_get(self, key):
            if idem_get_impl:
                return await idem_get_impl(key)
            return None

        async def idempotency_set(self, key, value, ttl_seconds=600):
            if idem_set_impl:
                return await idem_set_impl(key, value, ttl_seconds)
            return None

        class _Lock:
            def __init__(self, *a, **k): pass
            async def __aenter__(self): return self
            async def __aexit__(self, exc_type, exc, tb): return False

        def lock(self, *a, **k):  # pragma: no cover (not used on create)
            return self._Lock()

    rw = _Idem()
    monkeypatch.setattr(mod, "redis_wrapper", rw, raising=False)

    # Default create implementation that satisfies APIKeyOut schema
    async def _default_create(label: Optional[str], scopes: List[str], ttl_days: Optional[int]):
        key_id = f"key_{uuid.uuid4().hex[:8]}"
        prefix = f"ak_{key_id[:6]}"
        return {
            "id": key_id,
            "label": label or "",
            "scopes": scopes,
            "created_at": "2025-01-01T00:00:00Z",
            "expires_at": None,
            "disabled": False,
            "prefix": prefix,
            # secret must be present on create (optional in schema, required by route semantics)
            "secret": "plaintext_secret_once",
        }

    monkeypatch.setattr(mod, "create_api_key", create_impl or _default_create, raising=False)

    # Audit is best-effort
    async def _default_audit(**_): return None
    monkeypatch.setattr(mod, "log_audit_event", audit_impl or _default_audit, raising=False)

    # Deterministic current user
    class _User:
        def __init__(self, id_): self.id = id_; self.is_superuser = True
    user = _User(user_id or str(uuid.uuid4()))
    def _get_user(): return user

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    app.dependency_overrides[mod.get_current_user] = _get_user

    return app, TestClient(app), mod, user, rw


def test_create_happy_path_returns_secret_and_no_store(monkeypatch):
    app, client, mod, user, _ = _mk_app(monkeypatch)

    payload = {"label": "CI Bot", "scopes": ["read:titles"], "ttl_days": 30}
    r = client.post("/api/v1/admin/api-keys", json=payload)

    assert r.status_code == 200
    body = r.json()
    assert body["label"] == "CI Bot"
    assert body["scopes"] == ["read:titles"]
    assert body["secret"]  # plaintext secret on create
    # no-store cache hardening on this route
    assert "no-store" in (r.headers.get("cache-control", "") or "").lower()
    # Security + cache hardening step is first in the handler
    # (ensure_admin, ensure_mfa, set_sensitive_cache)
    # 


@pytest.mark.parametrize("exc,status", [
    (HTTPException(status_code=403, detail="nope"), 403),
    (HTTPException(status_code=401, detail="mfa"), 401),
])
def test_create_requires_admin_and_mfa(monkeypatch, exc, status):
    async def _fail_admin(_u):
        if status == 403: raise exc
    async def _fail_mfa(_r):
        if status == 401: raise exc

    app, client, mod, *_ = _mk_app(monkeypatch)
    monkeypatch.setattr(mod, "_ensure_admin", _fail_admin, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _fail_mfa, raising=False)

    r = client.post("/api/v1/admin/api-keys", json={"label": "X", "scopes": [], "ttl_days": None})
    assert r.status_code == status
    # Admin/MFA enforced before idempotency/creation. 


def test_idempotency_replay_uses_snapshot_and_skips_create(monkeypatch):
    # Snapshot must satisfy APIKeyOut (include created_at & prefix)
    snapshot = {
        "id": "key_abc",
        "label": "Replay",
        "scopes": ["read"],
        "created_at": "2025-01-02T00:00:00Z",
        "expires_at": None,
        "disabled": False,
        "prefix": "ak_keyabc",
        "secret": "same_secret_from_snapshot",
    }
    calls = {"get_key": None, "create_called": False}

    async def _idem_get(key):
        calls["get_key"] = key
        return snapshot

    async def _create(*a, **k):
        calls["create_called"] = True
        raise AssertionError("create_api_key should be skipped on idempotency replay")

    app, client, mod, user, _ = _mk_app(
        monkeypatch,
        idem_get_impl=_idem_get,
        create_impl=_create,
    )

    r = client.post(
        "/api/v1/admin/api-keys",
        json={"label": "Replay", "scopes": ["read"], "ttl_days": 7},
        headers={"Idempotency-Key": "abc123"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["secret"] == "same_secret_from_snapshot"
    # key format: idemp:admin:api_keys:create:{user.id}:{header}
    assert calls["get_key"] == f"idemp:admin:api_keys:create:{user.id}:abc123"  # 
    assert calls["create_called"] is False
    # replay path returns APIKeyOut(**snap) 


def test_idempotency_snapshot_is_set_with_ttl_600(monkeypatch):
    captured: List[Tuple[str, Dict[str, Any], int]] = []

    async def _idem_get(_):  # no existing snapshot
        return None

    async def _idem_set(k, v, ttl):
        captured.append((k, v, ttl))

    app, client, mod, user, _ = _mk_app(
        monkeypatch,
        idem_get_impl=_idem_get,
        idem_set_impl=_idem_set,
    )

    r = client.post(
        "/api/v1/admin/api-keys",
        json={"label": "CI", "scopes": ["read"], "ttl_days": 1},
        headers={"Idempotency-Key": "k1"},
    )
    assert r.status_code == 200

    k, rec, ttl = captured[-1]
    assert k == f"idemp:admin:api_keys:create:{user.id}:k1"  # 
    assert ttl == 600  # TTL seconds for snapshot 
    # record is valid APIKeyOut-shaped (created_at & prefix present)
    assert "created_at" in rec and "prefix" in rec


def test_idempotency_set_failure_is_swallowed(monkeypatch):
    async def _idem_get(_): return None
    async def _idem_set(*a, **k): raise RuntimeError("redis down")

    app, client, *_ = _mk_app(monkeypatch, idem_get_impl=_idem_get, idem_set_impl=_idem_set)
    r = client.post("/api/v1/admin/api-keys", json={"label": "CI", "scopes": [], "ttl_days": None},
                    headers={"Idempotency-Key": "x"})
    assert r.status_code == 200  # best-effort snapshot; errors ignored 


def test_audit_log_failure_is_swallowed(monkeypatch):
    async def _boom(**_): raise RuntimeError("audit down")
    app, client, mod, *_ = _mk_app(monkeypatch, audit_impl=_boom)

    r = client.post("/api/v1/admin/api-keys", json={"label": "CI", "scopes": [], "ttl_days": None})
    assert r.status_code == 200  # audit is best-effort 


def test_payload_fields_are_forwarded_to_service(monkeypatch):
    seen: Dict[str, Any] = {}

    async def _create(label: Optional[str], scopes: List[str], ttl_days: Optional[int]):
        seen["label"] = label
        seen["scopes"] = scopes
        seen["ttl_days"] = ttl_days
        # return a valid APIKeyOut-shaped record
        return {
            "id": "k",
            "label": label or "",
            "scopes": scopes,
            "created_at": "2025-01-01T00:00:00Z",
            "expires_at": None,
            "disabled": False,
            "prefix": "ak_k",
            "secret": "s",
        }

    app, client, *_ = _mk_app(monkeypatch, create_impl=_create)

    payload = {"label": "Ops", "scopes": ["read", "write"], "ttl_days": 90}
    r = client.post("/api/v1/admin/api-keys", json=payload)
    assert r.status_code == 200
    assert seen == payload
