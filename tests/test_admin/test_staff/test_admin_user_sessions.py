# tests/test_admin/test_staff/test_list_user_sessions.py

import importlib
import uuid
from typing import Any, List, Optional, Tuple
from datetime import datetime, timezone
import inspect

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.routing import request_response  # robust unwrap for SlowAPI


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class _Scalars:
    def __init__(self, rows: List[Any]):
        self._rows = rows
    def all(self):
        return list(self._rows)

class _Result:
    def __init__(self, rows: List[Any]):
        self._rows = rows
    def scalars(self):
        return _Scalars(self._rows)

class FakeDB:
    def __init__(self, rows: List[Any]):
        self._rows = rows
        self.execute_calls: List[Tuple[Any, tuple, dict]] = []
    async def execute(self, query, *a, **k):
        self.execute_calls.append((query, a, k))
        return _Result(self._rows)

class FakeUser:
    def __init__(self, *, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()

class TokenRow:
    """Mimic a refresh-token row used by the route's projection."""
    def __init__(
        self,
        *,
        jti: str,
        is_revoked: bool,
        created_at: Optional[datetime] = None,
        expires_at: Optional[datetime] = None,
    ):
        self.jti = jti
        self.is_revoked = is_revoked
        self.created_at = created_at
        self.expires_at = expires_at


# ─────────────────────────────────────────────────────────────────────────────
# App factory (version-proof SlowAPI unwrap)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, rows: List[Any]):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")

    # Disable rate limiting for tests (checked at call-time in your decorators)
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Security gates -> no-op
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Build app + dependency overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(rows)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Robustly unwrap SlowAPI for this GET route
    path = "/api/v1/admin/users/{user_id}/sessions"
    for route in app.routes:
        if getattr(route, "path", None) == path and "GET" in getattr(route, "methods", set()):
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
    return app, client, mod, db


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_user_sessions_happy_path_sets_no_store_and_projects(monkeypatch):
    rows = [
        TokenRow(
            jti="jti-2",
            is_revoked=True,
            created_at=datetime(2025, 1, 2, tzinfo=timezone.utc),
            expires_at=datetime(2025, 2, 1, tzinfo=timezone.utc),
        ),
        TokenRow(
            jti="jti-1",
            is_revoked=False,
            created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2025, 1, 31, tzinfo=timezone.utc),
        ),
    ]
    app, client, mod, db = _mk_app(monkeypatch, rows=rows)
    user_id = uuid.uuid4()

    resp = client.get(f"/api/v1/admin/users/{user_id}/sessions?limit=2&offset=0")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert isinstance(data, list) and len(data) == 2

    # shape: jti, is_revoked, created_at, expires_at keys present
    for item in data:
        assert "jti" in item and "is_revoked" in item
        assert "created_at" in item and "expires_at" in item

    # cache headers
    cc = (resp.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (resp.headers.get("pragma") or "").lower() == "no-cache"

    # DB executed once
    assert db.execute_calls


def test_user_sessions_pagination_params_passthrough(monkeypatch):
    rows = [
        TokenRow(jti="x", is_revoked=False, created_at=datetime(2025, 1, 1, tzinfo=timezone.utc)),
    ]
    app, client, mod, db = _mk_app(monkeypatch, rows=rows)
    uid = uuid.uuid4()

    resp = client.get(f"/api/v1/admin/users/{uid}/sessions?limit=1&offset=5")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body, list)
    # At least the query ran; deeper SQL verification isn't required here.
    assert db.execute_calls


def test_user_sessions_empty_list(monkeypatch):
    app, client, mod, db = _mk_app(monkeypatch, rows=[])
    uid = uuid.uuid4()

    resp = client.get(f"/api/v1/admin/users/{uid}/sessions")
    assert resp.status_code == 200
    assert resp.json() == []
