# tests/test_admin/test_staff/test_admin_user_delete.py

import importlib
import inspect
import uuid
from typing import Any, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.routing import request_response  # robust unwrap for SlowAPI


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class FakeDB:
    """Minimal async DB stub capturing execute/commit used by the route."""
    def __init__(self):
        self.execute_calls: List[Tuple[Any, tuple, dict]] = []
        self.commit_calls = 0
    async def execute(self, query, *a, **k):
        self.execute_calls.append((query, a, k))
        return None
    async def commit(self):
        self.commit_calls += 1

class FakeUser:
    def __init__(self, *, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


# ─────────────────────────────────────────────────────────────────────────────
# App factory (version-proof SlowAPI unwrap)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, current_user: Optional[FakeUser] = None):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")

    # Disable rate limiting at call time
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Security gates → no-op
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Capture reauth token usage
    state = {"reauth_token": None}
    async def _ensure_reauth(tok: str, _user: Any):
        state["reauth_token"] = tok
    monkeypatch.setattr(mod, "_ensure_reauth", _ensure_reauth, raising=False)

    # Revoke service stub (capture args)
    svc_calls: List[Tuple[uuid.UUID, Any]] = []
    async def _revoke_all_refresh_tokens(*, db, user_id):
        svc_calls.append((user_id, db))
        return True
    monkeypatch.setattr(mod, "revoke_all_refresh_tokens", _revoke_all_refresh_tokens, raising=False)

    # Audit → no-op
    async def _audit(*_a, **_k): return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Build app + overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB()
    user_ctx = current_user or FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user_ctx

    # Robustly unwrap SlowAPI for this DELETE route
    path = "/api/v1/admin/users/{user_id}"
    for route in app.routes:
        if getattr(route, "path", None) == path and "DELETE" in getattr(route, "methods", set()):
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn
            try:
                handler = route.get_request_handler() if hasattr(route, "get_request_handler") else route.get_route_handler()
                try:
                    params = list(inspect.signature(handler).parameters.values())
                except Exception:
                    params = []
                route.app = request_response(handler) if len(params) == 1 else handler
            except Exception:
                _h = route.get_route_handler()
                try:
                    _p = list(inspect.signature(_h).parameters.values())
                except Exception:
                    _p = []
                route.app = request_response(_h) if len(_p) == 1 else _h
            break

    client = TestClient(app)
    return app, client, mod, db, state, svc_calls, user_ctx


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_delete_user_happy_path_calls_reauth_revoke_and_deletes(monkeypatch):
    app, client, mod, db, st, svc_calls, _ = _mk_app(monkeypatch)
    target_id = uuid.uuid4()

    resp = client.request("DELETE", f"/api/v1/admin/users/{target_id}", json={"reauth_token": "rt-1"})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"message": "User deleted"}

    # cache headers
    cc = (resp.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (resp.headers.get("pragma") or "").lower() == "no-cache"

    # reauth enforced and revoke called with correct user_id and db
    assert st["reauth_token"] == "rt-1"
    assert svc_calls and svc_calls[-1][0] == target_id
    assert svc_calls[-1][1] is db

    # DB delete executed and committed
    assert db.execute_calls, "expected a DELETE statement to be executed"
    assert db.commit_calls >= 1


def test_delete_user_requires_reauth_token(monkeypatch):
    app, client, mod, db, st, svc_calls, _ = _mk_app(monkeypatch)
    target_id = uuid.uuid4()

    resp = client.request("DELETE", f"/api/v1/admin/users/{target_id}", json={})
    assert resp.status_code == 400
    assert "reauth_token required" in resp.text

    # No revoke, no DB work
    assert not svc_calls
    assert not db.execute_calls
    assert db.commit_calls == 0


def test_delete_user_cannot_delete_self(monkeypatch):
    me = FakeUser()
    app, client, mod, db, st, svc_calls, _ = _mk_app(monkeypatch, current_user=me)

    resp = client.request("DELETE", f"/api/v1/admin/users/{me.id}", json={"reauth_token": "rt-self"})
    assert resp.status_code == 400
    assert "Cannot delete self" in resp.text

    # ensure no destructive ops
    assert not svc_calls
    assert not db.execute_calls
    assert db.commit_calls == 0
