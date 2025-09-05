# tests/test_admin/test_staff/test_list_admins_only.py

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

class UserRow:
    """Row object compatible with _serialize_user() fields."""
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        email: str,
        role: str,
        is_active: bool = True,
        is_verified: bool = True,
        mfa_enabled: bool = True,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
        last_login_at: Optional[datetime] = None,
        name: Optional[str] = None,
    ):
        self.id = id or uuid.uuid4()
        self.email = email
        self.role = role
        self.is_active = is_active
        self.is_verified = is_verified
        self.mfa_enabled = mfa_enabled
        self.created_at = created_at or datetime(2025, 1, 1, tzinfo=timezone.utc)
        self.updated_at = updated_at
        self.last_login_at = last_login_at
        self.name = name


# ─────────────────────────────────────────────────────────────────────────────
# App factory (version-proof SlowAPI unwrap)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, rows: List[Any]):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")

    # Disable rate limiting
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Security gates no-op
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(rows)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap SlowAPI decorator robustly
    path = "/api/v1/admin/staff/admins"
    for route in app.routes:
        if getattr(route, "path", None) == path and "GET" in getattr(route, "methods", set()):
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn

            # Build a compatible ASGI app regardless of Starlette/FastAPI version:
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

def test_admins_happy_path_no_store(monkeypatch):
    rows = [
        UserRow(email="admin2@example.com", role="ADMIN", created_at=datetime(2025, 1, 2, tzinfo=timezone.utc)),
        UserRow(email="admin1@example.com", role="ADMIN", created_at=datetime(2025, 1, 1, tzinfo=timezone.utc)),
    ]
    app, client, mod, db = _mk_app(monkeypatch, rows=rows)

    resp = client.get("/api/v1/admin/staff/admins?limit=2&offset=0")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert isinstance(data, list) and len(data) == 2
    assert all(item.get("role") == "ADMIN" for item in data)

    # cache headers
    cc = (resp.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (resp.headers.get("pragma") or "").lower() == "no-cache"

    # DB was hit
    assert db.execute_calls

def test_admins_pagination_params_passthrough(monkeypatch):
    rows = [UserRow(email="only@example.com", role="ADMIN")]
    app, client, mod, db = _mk_app(monkeypatch, rows=rows)

    resp = client.get("/api/v1/admin/staff/admins?limit=1&offset=5")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert isinstance(data, list) and len(data) == 1
    assert data[0]["role"] == "ADMIN"

def test_admins_empty_list_allowed(monkeypatch):
    app, client, mod, db = _mk_app(monkeypatch, rows=[])

    resp = client.get("/api/v1/admin/staff/admins")
    assert resp.status_code == 200, resp.text
    assert resp.json() == []
