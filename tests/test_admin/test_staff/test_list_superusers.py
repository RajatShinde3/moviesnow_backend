# tests/test_admin/test_staff/test_list_superusers.py

import importlib
import uuid
from typing import Any, List, Optional, Tuple
from datetime import datetime, timezone

import inspect
from fastapi import FastAPI, HTTPException
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

def _mk_app(monkeypatch, *, rows: List[Any], cached: Optional[List[dict]] = None):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")

    # Disable rate limiting
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Security gates no-op
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Fake Redis with knobs
    class _Redis:
        def __init__(self):
            self.get_calls: List[str] = []
            self.set_calls: List[Tuple[str, Any, int]] = []
            self.fail_get = False
            self.fail_set = False
            self.cached = cached
        async def json_get(self, key: str):
            self.get_calls.append(key)
            if self.fail_get:
                raise RuntimeError("redis get boom")
            return self.cached
        async def json_set(self, key: str, val: Any, *, ttl_seconds: int):
            self.set_calls.append((key, val, ttl_seconds))
            if self.fail_set:
                raise RuntimeError("redis set boom")
            return True

    r = _Redis()
    monkeypatch.setattr(mod, "redis_wrapper", r, raising=False)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(rows)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap SlowAPI decorator robustly
    path = "/api/v1/admin/staff/superusers"
    for route in app.routes:
        if getattr(route, "path", None) == path and "GET" in getattr(route, "methods", set()):
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn
            # Build a compatible ASGI app regardless of Starlette/FastAPI version:
            # - Some versions: get_request_handler() returns a request->response callable.
            # - Others: it returns an ASGI app (scope, receive, send).
            try:
                if hasattr(route, "get_request_handler"):
                    handler = route.get_request_handler()
                else:
                    handler = route.get_route_handler()

                # Detect if handler is request->response (1 param) or ASGI (3 params)
                try:
                    params = list(inspect.signature(handler).parameters.values())
                except Exception:
                    params = []

                if len(params) == 1:
                    route.app = request_response(handler)
                else:
                    route.app = handler
            except Exception:
                # Fallback to route.get_route_handler in case of any incompatibilities
                _h = route.get_route_handler()
                try:
                    _p = list(inspect.signature(_h).parameters.values())
                except Exception:
                    _p = []
                route.app = request_response(_h) if len(_p) == 1 else _h
            break

    client = TestClient(app)
    return app, client, mod, db, r


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_superusers_cache_miss_hits_db_sets_cache_and_no_store(monkeypatch):
    rows = [
        UserRow(email="root1@example.com", role="SUPERUSER", created_at=datetime(2025, 1, 2, tzinfo=timezone.utc)),
        UserRow(email="root2@example.com", role="SUPERUSER", created_at=datetime(2025, 1, 1, tzinfo=timezone.utc)),
    ]
    app, client, mod, db, r = _mk_app(monkeypatch, rows=rows, cached=None)

    resp = client.get("/api/v1/admin/staff/superusers?limit=2&offset=0")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert isinstance(data, list) and len(data) == 2
    assert all(item.get("role") == "SUPERUSER" for item in data)

    # cache headers
    cc = (resp.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (resp.headers.get("pragma") or "").lower() == "no-cache"

    # DB was hit; cache set with TTL=300
    assert db.execute_calls, "DB should be executed on cache miss"
    assert r.set_calls and r.set_calls[-1][2] == 300

def test_superusers_cache_hit_skips_db(monkeypatch):
    cached = [
        {"id": "u1", "email": "root@example.com", "role": "SUPERUSER", "created_at": "2025-01-01T00:00:00Z"}
    ]
    app, client, mod, db, r = _mk_app(monkeypatch, rows=[], cached=cached)

    resp = client.get("/api/v1/admin/staff/superusers")
    assert resp.status_code == 200, resp.text
    assert resp.json() == cached

    # On cache hit, DB isn't touched and we don't set cache again
    assert not db.execute_calls
    assert not r.set_calls

def test_superusers_redis_get_error_is_swallowed(monkeypatch):
    rows = [UserRow(email="x@example.com", role="SUPERUSER")]
    app, client, mod, db, r = _mk_app(monkeypatch, rows=rows, cached=None)
    r.fail_get = True

    resp = client.get("/api/v1/admin/staff/superusers")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body, list) and len(body) == 1

def test_superusers_redis_set_error_is_swallowed(monkeypatch):
    rows = [UserRow(email="x@example.com", role="SUPERUSER")]
    app, client, mod, db, r = _mk_app(monkeypatch, rows=rows, cached=None)
    r.fail_set = True

    resp = client.get("/api/v1/admin/staff/superusers?limit=1&offset=1")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body, list) and len(body) == 1

def test_superusers_cache_key_includes_limit_and_offset(monkeypatch):
    rows = [UserRow(email="y@example.com", role="SUPERUSER")]
    app, client, mod, db, r = _mk_app(monkeypatch, rows=rows, cached=None)

    resp = client.get("/api/v1/admin/staff/superusers?limit=7&offset=3")
    assert resp.status_code == 200
    # First call is json_get
    assert r.get_calls and r.get_calls[0].endswith(":7:3")
    # Subsequent json_set uses the same key
    assert r.set_calls and r.set_calls[-1][0].endswith(":7:3")

def test_superusers_empty_list_allowed(monkeypatch):
    app, client, mod, db, r = _mk_app(monkeypatch, rows=[], cached=None)

    resp = client.get("/api/v1/admin/staff/superusers")
    assert resp.status_code == 200
    assert resp.json() == []
