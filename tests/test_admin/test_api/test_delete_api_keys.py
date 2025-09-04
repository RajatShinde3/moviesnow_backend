# tests/test_admin/test_api/test_delete_api_keys.py

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
    delete_impl: Optional[Callable[[str], Any]] = None,
    audit_impl: Optional[Callable[..., Any]] = None,
    ensure_admin: Optional[Callable[..., Any]] = None,
    ensure_mfa: Optional[Callable[..., Any]] = None,
):
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

    if hasattr(mod, "redis_wrapper"):
        monkeypatch.setattr(mod.redis_wrapper, "lock", _fake_lock, raising=False)
    else:
        monkeypatch.setattr(mod, "redis_wrapper", type("RW", (), {"lock": _fake_lock})(), raising=False)

    # Default delete service returns True
    async def _default_delete(key_id: str) -> bool:
        return True

    monkeypatch.setattr(mod, "delete_api_key", delete_impl or _default_delete, raising=False)

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

def test_delete_happy_path_returns_deleted_and_no_store_and_uses_lock(monkeypatch):
    called_with: List[str] = []

    async def _delete(key_id: str) -> bool:
        called_with.append(key_id)
        return True

    app, client, mod, user, lock_calls = _mk_app(monkeypatch, delete_impl=_delete)

    key_id = "key_del_123"
    r = client.delete(f"/api/v1/admin/api-keys/{key_id}")
    assert r.status_code == 200, r.text
    assert r.json() == {"deleted": True}

    # Cache headers: strict no-store
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # Lock was used with the correct key
    assert lock_calls and lock_calls[0][0] == f"lock:apikey:delete:{key_id}"

    # Service called with correct key
    assert called_with == [key_id]


def test_delete_404_when_service_returns_false(monkeypatch):
    async def _delete_false(key_id: str) -> bool:
        return False

    app, client, mod, user, lock_calls = _mk_app(monkeypatch, delete_impl=_delete_false)

    r = client.delete("/api/v1/admin/api-keys/key_missing")
    assert r.status_code == 404
    assert "API key not found" in r.text
    # Lock acquired even when 404 is returned (after service said False)
    assert lock_calls and lock_calls[0][0] == "lock:apikey:delete:key_missing"


def test_delete_requires_admin(monkeypatch):
    async def _fail_admin(_u): raise HTTPException(status_code=403, detail="nope")

    app, client, mod, user, lock_calls = _mk_app(monkeypatch, ensure_admin=_fail_admin)

    r = client.delete("/api/v1/admin/api-keys/key_x")
    assert r.status_code == 403
    assert r.json()["detail"] == "nope"
    # No lock when auth fails early
    assert lock_calls == []


def test_delete_requires_mfa(monkeypatch):
    async def _fail_mfa(_r): raise HTTPException(status_code=401, detail="mfa")

    app, client, mod, user, lock_calls = _mk_app(monkeypatch, ensure_mfa=_fail_mfa)

    r = client.delete("/api/v1/admin/api-keys/key_y")
    assert r.status_code == 401
    assert r.json()["detail"] == "mfa"
    # No lock when auth fails early
    assert lock_calls == []


def test_delete_audit_log_failure_is_swallowed(monkeypatch):
    async def _boom(**_): raise RuntimeError("audit down")

    app, client, mod, user, lock_calls = _mk_app(monkeypatch, audit_impl=_boom)

    r = client.delete("/api/v1/admin/api-keys/key_audit")
    assert r.status_code == 200  # still succeeds even when audit logging fails
