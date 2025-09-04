# tests/test_admin/test_api/test_list_api_keys.py

import uuid
import importlib
from typing import Any, Dict, List, Tuple, Optional, Callable

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


def _mk_app(
    monkeypatch,
    *,
    list_impl: Optional[Callable[[], List[Dict[str, Any]]]] = None,
    audit_impl: Optional[Callable[..., Any]] = None,
    user_id: Optional[str] = None,
):
    """
    Build a tiny FastAPI app mounting the admin API-keys router with /api/v1/admin prefix,
    and monkeypatch collaborators inside the module under test.
    """
    mod = importlib.import_module("app.api.v1.routers.admin.api_keys")

    # Bypass rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # No-op admin + MFA by default (overridden in specific tests)
    async def _ok_admin(user): return None
    async def _ok_mfa(request): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok_admin, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok_mfa, raising=False)

    # Default list implementation returns masked keys (no 'secret')
    async def _default_list():
        return [
            {
                "id": "key_a1b2c3",
                "label": "CI Bot",
                "scopes": ["read:titles"],
                "created_at": "2025-01-01T00:00:00Z",
                "expires_at": None,
                "disabled": False,
                "prefix": "ak_a1b2c3",
            },
            {
                "id": "key_d4e5f6",
                "label": "Ops",
                "scopes": ["read", "write"],
                "created_at": "2025-02-01T00:00:00Z",
                "expires_at": None,
                "disabled": False,
                "prefix": "ak_d4e5f6",
            },
        ]

    monkeypatch.setattr(mod, "list_api_keys", list_impl or _default_list, raising=False)

    # Audit is best-effort; can be made to raise
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

    return app, TestClient(app), mod, user


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_list_api_keys_happy_path_no_secrets_and_no_store(monkeypatch):
    app, client, mod, user = _mk_app(monkeypatch)

    r = client.get("/api/v1/admin/api-keys")
    assert r.status_code == 200

    data = r.json()
    assert isinstance(data, list) and len(data) == 2

    # Each item matches APIKeyOut shape and has no 'secret'
    for item in data:
        assert "id" in item
        assert "prefix" in item
        assert "created_at" in item
        assert "scopes" in item and isinstance(item["scopes"], list)
        assert ("secret" not in item) or (item["secret"] in (None, "")) or (not item["secret"])

    # strict cache headers (set_sensitive_cache(..., seconds=0))
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc or "max-age=0" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"


def test_list_api_keys_empty(monkeypatch):
    async def _list_empty(): return []

    app, client, *_ = _mk_app(monkeypatch, list_impl=_list_empty)

    r = client.get("/api/v1/admin/api-keys")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.parametrize("exc,status", [
    (HTTPException(status_code=403, detail="nope"), 403),
    (HTTPException(status_code=401, detail="mfa"), 401),
])
def test_list_api_keys_requires_admin_and_mfa(monkeypatch, exc, status):
    async def _fail_admin(_u):
        if status == 403: raise exc
    async def _fail_mfa(_r):
        if status == 401: raise exc

    app, client, mod, *_ = _mk_app(monkeypatch)
    monkeypatch.setattr(mod, "_ensure_admin", _fail_admin, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _fail_mfa, raising=False)

    r = client.get("/api/v1/admin/api-keys")
    assert r.status_code == status


def test_list_api_keys_audit_log_failure_is_swallowed(monkeypatch):
    async def _boom(**_): raise RuntimeError("audit down")
    app, client, mod, *_ = _mk_app(monkeypatch, audit_impl=_boom)

    r = client.get("/api/v1/admin/api-keys")
    assert r.status_code == 200
