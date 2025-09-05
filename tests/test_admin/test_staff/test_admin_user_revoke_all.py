# tests/test_admin/test_staff/test_revoke_all_sessions.py

import importlib
import uuid
from typing import Any, List, Optional, Tuple
import inspect

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.routing import request_response  # robust unwrap for SlowAPI


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class FakeDB:
    def __init__(self):
        self.exec_calls: List[Tuple[Any, tuple, dict]] = []
    async def execute(self, query, *a, **k):
        self.exec_calls.append((query, a, k))
        # route doesn't use results, return a dummy
        class _R:
            def scalars(self): return self
            def all(self): return []
        return _R()


class FakeUser:
    def __init__(self, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


# ─────────────────────────────────────────────────────────────────────────────
# App factory (version-proof SlowAPI unwrap)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, current_user: Optional[FakeUser] = None):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")

    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Track calls
    state = {
        "revoke_calls": [],  # list of (user_id)
        "audit_calls": [],   # list of dicts
        "ensure_admin": 0,
        "ensure_mfa": 0,
    }

    # Security gates -> no-op but counted
    async def _ensure_admin(_u):
        state["ensure_admin"] += 1
    async def _ensure_mfa(_r):
        state["ensure_mfa"] += 1
    monkeypatch.setattr(mod, "_ensure_admin", _ensure_admin, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ensure_mfa, raising=False)

    # Service: revoke_all_refresh_tokens -> capture user_id
    async def _revoke_all_refresh_tokens(*, db, user_id):
        state["revoke_calls"].append(str(user_id))
        return True
    monkeypatch.setattr(mod, "revoke_all_refresh_tokens", _revoke_all_refresh_tokens, raising=False)

    # Audit -> capture action + meta
    async def _audit(db, user, action, status, request, meta_data):
        state["audit_calls"].append({"action": action, "status": status, "meta": meta_data})
        return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Build app and dep overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB()
    user = current_user or FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Robustly unwrap SlowAPI-decorated route
    path = "/api/v1/admin/users/{user_id}/sessions/revoke-all"
    for route in app.routes:
        if getattr(route, "path", None) == path and "POST" in getattr(route, "methods", set()):
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
    return app, client, mod, db, state


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_revoke_all_happy_path_calls_service_sets_no_store_and_audits(monkeypatch):
    app, client, mod, db, st = _mk_app(monkeypatch)
    target_id = uuid.uuid4()

    resp = client.post(f"/api/v1/admin/users/{target_id}/sessions/revoke-all")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"revoked": "all"}

    # cache headers
    cc = (resp.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (resp.headers.get("pragma") or "").lower() == "no-cache"

    # service called with target user_id
    assert st["revoke_calls"] and st["revoke_calls"][-1] == str(target_id)

    # audit called with expected action + metadata
    assert st["audit_calls"], "Expected audit log call"
    last = st["audit_calls"][-1]
    assert last["action"] == "ADMIN_USERS_REVOKE_ALL"
    assert last["status"] == "SUCCESS"
    assert last["meta"].get("target_user_id") == str(target_id)

    # security gates invoked
    assert st["ensure_admin"] >= 1
    assert st["ensure_mfa"] >= 1


def test_revoke_all_different_user_ids_are_forwarded(monkeypatch):
    app, client, mod, db, st = _mk_app(monkeypatch)
    a = uuid.uuid4()
    b = uuid.uuid4()

    r1 = client.post(f"/api/v1/admin/users/{a}/sessions/revoke-all")
    r2 = client.post(f"/api/v1/admin/users/{b}/sessions/revoke-all")
    assert r1.status_code == 200 and r2.status_code == 200

    assert st["revoke_calls"][-2:] == [str(a), str(b)]
