# tests/test_admin/test_sessions/test_revoke_all_sessions.py

import importlib
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Minimal stubs
# ─────────────────────────────────────────────────────────────────────────────

class DummyDB:
    """No-op DB placeholder passed through to the service call."""
    pass


class UserRow:
    def __init__(self, id: Optional[Any] = None):
        import uuid
        self.id = id or uuid.uuid4()


# ─────────────────────────────────────────────────────────────────────────────
# Test app factory (builds a proxy route that calls the *unwrapped* endpoint)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    ensure_admin_ok: bool = True,
):
    """
    Build a FastAPI app that proxies to the underlying revoke_all_sessions
    function **without** the SlowAPI @rate_limit wrapper.
    """
    mod = importlib.import_module("app.api.v1.routers.admin.sessions")

    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Gate overrides
    async def _ok(*_a, **_k): return None
    async def _deny(*_a, **_k): raise HTTPException(status_code=403, detail="Insufficient permissions")
    monkeypatch.setattr(mod, "_ensure_admin", _ok if ensure_admin_ok else _deny, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Capture calls to the revoke-all service
    service_calls: List[Dict[str, Any]] = []

    async def _revoke_all_refresh_tokens(*, db, user_id):
        service_calls.append({"db": db, "user_id": user_id})

    monkeypatch.setattr(mod, "revoke_all_refresh_tokens", _revoke_all_refresh_tokens, raising=False)

    # Default: audit is a no-op; specific tests override to raise
    async def _audit(*_a, **_k): return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Unwrap the decorated endpoint (peel any wrappers using functools.wraps)
    target = mod.revoke_all_sessions
    while hasattr(target, "__wrapped__"):
        target = target.__wrapped__

    # Build app and wire deps
    app = FastAPI()
    db = DummyDB()
    user = UserRow()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Add a proxy route that calls the unwrapped function directly
    @app.post("/api/v1/admin/sessions/revoke-all")
    async def _proxy(
        request: Request,
        response: Response,
        db_dep=Depends(mod.get_async_db),
        user_dep=Depends(mod.get_current_user),
    ):
        return await target(
            request=request,
            response=response,
            db=db_dep,
            current_user=user_dep,
        )

    client = TestClient(app)
    return app, client, mod, db, {"user": user, "service_calls": service_calls}


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_revoke_all_happy_path_sets_no_store_and_calls_service(monkeypatch):
    app, client, mod, db, st = _mk_app(monkeypatch)

    r = client.post("/api/v1/admin/sessions/revoke-all")
    assert r.status_code == 200, r.text
    assert r.json() == {"revoked": "all"}

    # cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # service called once with current user's id and db
    assert len(st["service_calls"]) == 1
    call = st["service_calls"][0]
    assert call["db"] is db
    assert call["user_id"] == st["user"].id


def test_revoke_all_audit_failure_is_swallowed(monkeypatch):
    app, client, mod, db, st = _mk_app(monkeypatch)

    async def _boom(*_a, **_k): raise RuntimeError("audit down")
    monkeypatch.setattr(mod, "log_audit_event", _boom, raising=False)

    r = client.post("/api/v1/admin/sessions/revoke-all")
    assert r.status_code == 200
    assert r.json() == {"revoked": "all"}
    # still executed service
    assert len(st["service_calls"]) == 1


def test_revoke_all_403_when_not_admin(monkeypatch):
    app, client, mod, db, st = _mk_app(monkeypatch, ensure_admin_ok=False)

    r = client.post("/api/v1/admin/sessions/revoke-all")
    assert r.status_code == 403
    assert "Insufficient permissions" in r.text

    # service should not run
    assert st["service_calls"] == []
