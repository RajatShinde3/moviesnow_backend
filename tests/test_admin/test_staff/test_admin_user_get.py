# tests/test_admin/test_staff/test_get_user_by_id.py

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

class _OneResult:
    def __init__(self, row: Any | None):
        self._row = row
    def scalar_one_or_none(self):
        return self._row

class FakeDB:
    def __init__(self, row: Any | None):
        self._row = row
        self.execute_calls: List[Tuple[Any, tuple, dict]] = []
    async def execute(self, query, *a, **k):
        self.execute_calls.append((query, a, k))
        return _OneResult(self._row)

class FakeUserCtx:
    def __init__(self, *, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()

class RowUser:
    """Row object compatible with _serialize_user() used by the route."""
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        email: str = "user@example.com",
        role: str = "USER",
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

def _mk_app(monkeypatch, *, row: Any | None):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")

    # Disable rate limiting for tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Security gates no-op
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB(row)
    user_ctx = FakeUserCtx()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user_ctx

    # Robustly unwrap SlowAPI rate_limit for this path
    path = "/api/v1/admin/users/{user_id}"
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

def test_get_user_happy_path_returns_projection_and_no_store(monkeypatch):
    target_id = uuid.uuid4()
    row = RowUser(
        id=target_id,
        email="alice@example.com",
        role="ADMIN",
        is_active=True,
        is_verified=True,
        mfa_enabled=True,
        created_at=datetime(2025, 1, 2, tzinfo=timezone.utc),
    )
    app, client, mod, db = _mk_app(monkeypatch, row=row)

    r = client.get(f"/api/v1/admin/users/{target_id}")
    assert r.status_code == 200, r.text
    body = r.json()

    # basic shape from _serialize_user
    assert body["id"] == str(target_id)
    assert body["email"] == "alice@example.com"
    assert body["role"] == "ADMIN"
    assert isinstance(body.get("is_active"), bool)

    # cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # DB was hit
    assert db.execute_calls


def test_get_user_404_when_not_found(monkeypatch):
    app, client, mod, db = _mk_app(monkeypatch, row=None)
    uid = uuid.uuid4()

    r = client.get(f"/api/v1/admin/users/{uid}")
    assert r.status_code == 404
    assert "User not found" in r.text
