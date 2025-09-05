# tests/test_admin/test_staff/test_admin_user_reactivate.py

import importlib
import uuid
import inspect
from typing import Any, List, Optional, Tuple

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
    """Minimal async DB stub covering execute/flush/commit used by the route."""
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
    """Row model with just the fields touched by the route and serializer."""
    def __init__(self, *, is_active: bool):
        self.id = uuid.uuid4()
        self.email = "user@example.com"
        self.role = "USER"
        self.full_name = None
        self.is_active = is_active
        # serializer-friendly extras (if referenced)
        self.created_at = None
        self.updated_at = None
        self.last_login_at = None
        self.mfa_enabled = False


# ─────────────────────────────────────────────────────────────────────────────
# App factory (version-proof SlowAPI unwrap)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, row: Any | None, current_user: Optional[FakeCurrentUser] = None):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")

    # Disable rate limiting (checked at call-time by our decorators)
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Security gates → no-op
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Audit is best-effort; stub to no-op
    async def _audit(*_a, **_k): return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Fake Redis with a simple lock that records keys
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

    # Build app + overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(row)
    user_ctx = current_user or FakeCurrentUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user_ctx

    # Robustly unwrap SlowAPI for this endpoint
    path = "/api/v1/admin/users/{user_id}/reactivate"
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
    return app, client, mod, db, r, user_ctx


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_reactivate_happy_path_activates_user_and_sets_no_store(monkeypatch):
    row = RowUser(is_active=False)  # inactive → should flip to True
    app, client, mod, db, r, _ = _mk_app(monkeypatch, row=row)
    uid = row.id

    resp = client.post(f"/api/v1/admin/users/{uid}/reactivate")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"message": "User reactivated"}

    # cache headers
    cc = (resp.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (resp.headers.get("pragma") or "").lower() == "no-cache"

    # row changed + DB persisted
    assert row.is_active is True
    assert db.flush_calls >= 1 and db.commit_calls >= 1

    # lock captured with user id in key
    assert r.lock_keys and r.lock_keys[-1].endswith(str(uid))


def test_reactivate_already_active_returns_message_without_mutation(monkeypatch):
    row = RowUser(is_active=True)
    app, client, mod, db, r, _ = _mk_app(monkeypatch, row=row)
    uid = row.id

    resp = client.post(f"/api/v1/admin/users/{uid}/reactivate")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"message": "Already active"}

    # no DB flush/commit on no-op branch
    assert db.flush_calls == 0 and db.commit_calls == 0

    # lock still used
    assert r.lock_keys and r.lock_keys[-1].endswith(str(uid))


def test_reactivate_404_when_user_not_found(monkeypatch):
    app, client, mod, db, r, _ = _mk_app(monkeypatch, row=None)
    uid = uuid.uuid4()

    resp = client.post(f"/api/v1/admin/users/{uid}/reactivate")
    assert resp.status_code == 404
    assert "User not found" in resp.text

    # no DB changes
    assert db.flush_calls == 0 and db.commit_calls == 0
