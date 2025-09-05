# tests/test_admin/test_staff/test_deactivate_user.py

import importlib
import uuid
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone
import inspect

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.routing import request_response  # robust unwrap for SlowAPI


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class _OneResult:
    def __init__(self, row: Any | None):
        self._row = row
    def scalar_one_or_none(self):
        return self._row

class FakeDB:
    """Minimal async DB stub following the route's usage."""
    def __init__(self, row: Any | None):
        self._row = row
        self.execute_calls: List[Tuple[Any, tuple, dict]] = []
        self.flush_calls = 0
        self.commit_calls = 0
    async def execute(self, query, *a, **k):
        self.execute_calls.append((query, a, k))
        return _OneResult(self._row)
    async def flush(self):
        self.flush_calls += 1
    async def commit(self):
        self.commit_calls += 1

class FakeCurrentUser:
    def __init__(self, *, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()

class RowUser:
    """Simple user row with fields touched by the route."""
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        email: str = "user@example.com",
        is_active: bool = True,
    ):
        self.id = id or uuid.uuid4()
        self.email = email
        self.is_active = is_active
        # Helpful timestamps if serializer/audit ever touches them
        self.created_at = datetime(2025, 1, 1, tzinfo=timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# App factory (version-proof SlowAPI unwrap)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    row: Any | None,
    current_user: Optional[FakeCurrentUser] = None,
):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")

    # Disable rate limiting at call-time
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Security gates -> no-op
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Capture the reauth token
    state: Dict[str, Any] = {"reauth_token": None}
    async def _ensure_reauth(tok: str, _user: Any):
        state["reauth_token"] = tok
        return None
    monkeypatch.setattr(mod, "_ensure_reauth", _ensure_reauth, raising=False)

    # Audit: swallow
    async def _audit(*_a, **_k): return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Fake Redis lock capturing keys
    class _Lock:
        def __init__(self, key: str, *, timeout: int, blocking_timeout: int):
            self.key = key
        async def __aenter__(self): return None
        async def __aexit__(self, exc_type, exc, tb): return False

    class _Redis:
        def __init__(self):
            self.lock_keys: List[str] = []
        def lock(self, key: str, *, timeout: int, blocking_timeout: int):
            self.lock_keys.append(key)
            return _Lock(key, timeout=timeout, blocking_timeout=blocking_timeout)

    r = _Redis()
    monkeypatch.setattr(mod, "redis_wrapper", r, raising=False)

    # Build app + deps
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(row)
    user_ctx = current_user or FakeCurrentUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user_ctx

    # Robustly unwrap SlowAPI for POST /users/{user_id}/deactivate
    path = "/api/v1/admin/users/{user_id}/deactivate"
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
    return app, client, mod, db, r, state, user_ctx


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_deactivate_happy_path_deactivates_sets_no_store_and_lock(monkeypatch):
    row = RowUser(is_active=True)
    app, client, mod, db, r, st, _ = _mk_app(monkeypatch, row=row)

    resp = client.post(f"/api/v1/admin/users/{row.id}/deactivate", json={"reauth_token": "rtok"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body == {"message": "User deactivated"}

    # Row actually deactivated
    assert row.is_active is False

    # DB writes and lock
    assert db.flush_calls >= 1 and db.commit_calls >= 1
    assert r.lock_keys and r.lock_keys[-1].endswith(str(row.id))

    # Cache headers
    cc = (resp.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (resp.headers.get("pragma") or "").lower() == "no-cache"

    # Reauth enforced
    assert st["reauth_token"] == "rtok"


def test_deactivate_requires_reauth_token(monkeypatch):
    row = RowUser(is_active=True)
    app, client, mod, db, r, st, _ = _mk_app(monkeypatch, row=row)

    resp = client.post(f"/api/v1/admin/users/{row.id}/deactivate", json={})
    assert resp.status_code == 400
    assert "reauth_token required" in resp.text
    # No DB writes on failure
    assert db.flush_calls == 0 and db.commit_calls == 0


def test_deactivate_cannot_deactivate_self(monkeypatch):
    me = FakeCurrentUser()
    row = RowUser(is_active=True)
    app, client, mod, db, r, st, _ = _mk_app(monkeypatch, row=row, current_user=me)

    resp = client.post(f"/api/v1/admin/users/{me.id}/deactivate", json={"reauth_token": "t"})
    assert resp.status_code == 400
    assert "Cannot deactivate self" in resp.text
    assert db.flush_calls == 0 and db.commit_calls == 0


def test_deactivate_404_user_not_found(monkeypatch):
    app, client, mod, db, r, st, _ = _mk_app(monkeypatch, row=None)
    uid = uuid.uuid4()

    resp = client.post(f"/api/v1/admin/users/{uid}/deactivate", json={"reauth_token": "x"})
    assert resp.status_code == 404
    assert "User not found" in resp.text


def test_deactivate_already_inactive_returns_message_and_no_commit(monkeypatch):
    row = RowUser(is_active=False)
    app, client, mod, db, r, st, _ = _mk_app(monkeypatch, row=row)

    resp = client.post(f"/api/v1/admin/users/{row.id}/deactivate", json={"reauth_token": "tok"})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"message": "Already inactive"}

    # No DB writes when early-returning
    assert db.flush_calls == 0 and db.commit_calls == 0

    # Lock still used (we entered the context)
    assert r.lock_keys and r.lock_keys[-1].endswith(str(row.id))


def test_deactivate_calls_reauth_with_token(monkeypatch):
    row = RowUser(is_active=True)
    app, client, mod, db, r, st, _ = _mk_app(monkeypatch, row=row)

    resp = client.post(f"/api/v1/admin/users/{row.id}/deactivate", json={"reauth_token": "reauth-xyz"})
    assert resp.status_code == 200
    assert st["reauth_token"] == "reauth-xyz"
