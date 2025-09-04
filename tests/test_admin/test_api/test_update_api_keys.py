# tests/test_admin/test_api/test_update_api_keys.py

import uuid
import importlib
from typing import Any, Dict, List, Tuple, Optional, Callable

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# App factory with patch points for collaborators
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    update_impl: Optional[Callable[..., Dict[str, Any]]] = None,
    audit_impl: Optional[Callable[..., Any]] = None,
    ensure_admin: Optional[Callable[..., Any]] = None,
    ensure_mfa: Optional[Callable[..., Any]] = None,
):
    """
    Build a tiny FastAPI app mounting the admin API-keys router with /api/v1/admin prefix,
    and monkeypatch collaborators inside the module under test.
    """
    mod = importlib.import_module("app.api.v1.routers.admin.api_keys")

    # Bypass rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Security checks (no-ops by default)
    async def _ok_admin(user): return None
    async def _ok_mfa(request): return None
    monkeypatch.setattr(mod, "_ensure_admin", ensure_admin or _ok_admin, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", ensure_mfa or _ok_mfa, raising=False)

    # Capture Redis lock usage
    lock_calls: List[Tuple[str, int, int]] = []

    class _RecordedLock:
        def __init__(self, key: str, *, timeout: int, blocking_timeout: int):
            self.key = key
            self.timeout = timeout
            self.blocking_timeout = blocking_timeout

        async def __aenter__(self):
            lock_calls.append((self.key, self.timeout, self.blocking_timeout))
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False  # do not suppress errors

    def _fake_lock(key, *, timeout, blocking_timeout):
        return _RecordedLock(key, timeout=timeout, blocking_timeout=blocking_timeout)

    # Patch redis lock used by the route
    if hasattr(mod, "redis_wrapper"):
        monkeypatch.setattr(mod.redis_wrapper, "lock", _fake_lock, raising=False)
    else:
        # in case redis_wrapper is imported differently
        monkeypatch.setattr(mod, "redis_wrapper", type("RW", (), {"lock": _fake_lock})(), raising=False)

    # Default update implementation that satisfies APIKeyOut schema
    async def _default_update(
        *,
        key_id: str,
        label: Optional[str],
        scopes: Optional[List[str]],
        disabled: Optional[bool],
        rotate: bool,
        ttl_days: Optional[int],
    ) -> Dict[str, Any]:
        # Construct a minimal valid response matching APIKeyOut
        key = key_id or f"key_{uuid.uuid4().hex[:8]}"
        rec = {
            "id": key,
            "label": label or "",
            "scopes": scopes or [],
            "created_at": "2025-01-10T00:00:00Z",
            "expires_at": None,
            "disabled": bool(disabled) if disabled is not None else False,
            "prefix": f"ak_{key[:6]}",
        }
        if rotate:
            rec["secret"] = "new_plaintext_secret"
        return rec

    monkeypatch.setattr(mod, "update_api_key", update_impl or _default_update, raising=False)

    # Audit is best-effort
    async def _default_audit(**_): return None
    monkeypatch.setattr(mod, "log_audit_event", audit_impl or _default_audit, raising=False)

    # Deterministic current user dependency
    class _User:
        def __init__(self):
            self.id = str(uuid.uuid4())
            self.is_superuser = True

    user = _User()

    def _get_user():
        return user

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    app.dependency_overrides[mod.get_current_user] = _get_user

    return app, TestClient(app), mod, user, lock_calls


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_update_happy_path_no_rotate_no_secret_and_no_store(monkeypatch):
    app, client, mod, user, lock_calls = _mk_app(monkeypatch)

    key_id = "key_a1b2c3"
    payload = {
        "label": "Renamed",
        "scopes": ["read:titles"],
        "disabled": False,
        "rotate": False,
        "ttl_days": 30,
    }
    r = client.patch(f"/api/v1/admin/api-keys/{key_id}", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()

    # No plaintext secret on non-rotation
    assert ("secret" not in body) or (not body["secret"])

    # Cache headers: strict no-store
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # Lock was used with the correct key
    assert lock_calls and lock_calls[0][0] == f"lock:apikey:update:{key_id}"


def test_update_with_rotate_returns_plaintext_secret(monkeypatch):
    app, client, mod, user, _ = _mk_app(monkeypatch)

    key_id = "key_rotate1"
    r = client.patch(
        f"/api/v1/admin/api-keys/{key_id}",
        json={"label": None, "scopes": [], "disabled": False, "rotate": True, "ttl_days": None},
    )
    assert r.status_code == 200
    body = r.json()
    assert "secret" in body and isinstance(body["secret"], str) and body["secret"]


def test_update_404_when_service_raises_keyerror(monkeypatch):
    async def _boom(**_): raise KeyError("missing")

    app, client, mod, *_ = _mk_app(monkeypatch, update_impl=_boom)

    r = client.patch(
        "/api/v1/admin/api-keys/key_missing",
        json={"label": "X", "scopes": [], "disabled": False, "rotate": False, "ttl_days": None},
    )
    assert r.status_code == 404
    assert "API key not found" in r.text


def test_update_requires_admin(monkeypatch):
    async def _fail_admin(_u): raise HTTPException(status_code=403, detail="nope")

    app, client, mod, *_ = _mk_app(monkeypatch, ensure_admin=_fail_admin)

    r = client.patch(
        "/api/v1/admin/api-keys/key_x",
        json={"label": None, "scopes": [], "disabled": False, "rotate": False, "ttl_days": None},
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "nope"


def test_update_requires_mfa(monkeypatch):
    async def _fail_mfa(_r): raise HTTPException(status_code=401, detail="mfa")

    app, client, mod, *_ = _mk_app(monkeypatch, ensure_mfa=_fail_mfa)

    r = client.patch(
        "/api/v1/admin/api-keys/key_y",
        json={"label": None, "scopes": [], "disabled": False, "rotate": False, "ttl_days": None},
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "mfa"


def test_update_fields_forwarded_to_service(monkeypatch):
    seen: Dict[str, Any] = {}

    async def _capture(
        *,
        key_id: str,
        label: Optional[str],
        scopes: Optional[List[str]],
        disabled: Optional[bool],
        rotate: bool,
        ttl_days: Optional[int],
    ):
        seen.update(
            key_id=key_id,
            label=label,
            scopes=scopes,
            disabled=disabled,
            rotate=rotate,
            ttl_days=ttl_days,
        )
        # return a valid record
        return {
            "id": key_id,
            "label": label or "",
            "scopes": scopes or [],
            "created_at": "2025-01-10T00:00:00Z",
            "expires_at": None,
            "disabled": bool(disabled) if disabled is not None else False,
            "prefix": f"ak_{key_id[:6]}",
        }

    app, client, mod, *_ = _mk_app(monkeypatch, update_impl=_capture)

    key_id = "key_args1"
    payload = {"label": "Ops", "scopes": ["read", "write"], "disabled": True, "rotate": False, "ttl_days": 90}
    r = client.patch(f"/api/v1/admin/api-keys/{key_id}", json=payload)
    assert r.status_code == 200

    assert seen == {
        "key_id": key_id,
        "label": "Ops",
        "scopes": ["read", "write"],
        "disabled": True,
        "rotate": False,
        "ttl_days": 90,
    }


def test_update_audit_log_failure_is_swallowed(monkeypatch):
    async def _boom(**_): raise RuntimeError("audit down")

    app, client, mod, *_ = _mk_app(monkeypatch, audit_impl=_boom)

    r = client.patch(
        "/api/v1/admin/api-keys/key_audit",
        json={"label": None, "scopes": [], "disabled": False, "rotate": False, "ttl_days": None},
    )
    assert r.status_code == 200  # still succeeds even when audit logging fails
