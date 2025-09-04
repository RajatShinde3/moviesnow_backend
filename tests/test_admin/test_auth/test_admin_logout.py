# tests/test_admin/test_auth/test_admin_logout.py

import importlib
import uuid
from typing import Any, Dict, List, Optional, Tuple, Callable

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Minimal async DB stub
# ─────────────────────────────────────────────────────────────────────────────

class _Result:
    def __init__(self, row: Any | None): self._row = row
    def scalar_one_or_none(self): return self._row

class FakeDB:
    def __init__(self, row: Any | None = None):
        self._row = row
    async def execute(self, query, *_a, **_k): return _Result(self._row)


# Simple current user stub
class UserRow:
    def __init__(self, *, is_superuser: bool = True):
        self.id = str(uuid.uuid4())
        self.is_superuser = is_superuser
        # keep fields the router might check (for _is_admin)
        self.role = "admin" if is_superuser else "user"


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    is_admin_impl: Optional[Callable[[Any], bool]] = None,
    logout_impl: Optional[Callable[[str, Any, Any], Dict[str, Any]]] = None,
    current_user: Optional[UserRow] = None,
):
    mod = importlib.import_module("app.api.v1.routers.admin.auth")

    # Bypass SlowAPI in env and unwrap the endpoint after mounting
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # _is_admin (sync)
    monkeypatch.setattr(mod, "_is_admin", is_admin_impl or (lambda u: True), raising=False)

    # logout_user (async) — capture calls
    calls: List[Tuple[str, str]] = []  # (token, path)

    async def _default_logout_user(refresh_token: str, db, request):
        # capture token and path
        calls.append((refresh_token, str(getattr(request, "url", ""))))
        return {"revoked": True}

    monkeypatch.setattr(mod, "logout_user", logout_impl or _default_logout_user, raising=False)

    # Build app + overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(None)
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: (current_user or UserRow())

    # Unwrap SlowAPI decorator to avoid 429s
    path = "/api/v1/admin/logout"
    for route in app.routes:
        if getattr(route, "path", None) == path and "POST" in getattr(route, "methods", set()):
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn
            if hasattr(route, "app") and hasattr(route, "get_route_handler"):
                route.app = route.get_route_handler()
            break

    client = TestClient(app)
    return app, client, mod, db, calls


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_logout_happy_path_returns_service_payload_and_no_store(monkeypatch):
    payload = {"revoked": True, "message": "ok"}
    seen = []  # capture (token, url) here

    async def _logout_user(refresh_token, db, request):
        seen.append((refresh_token, str(request.url)))
        return payload

    app, client, mod, db, _ = _mk_app(monkeypatch, logout_impl=_logout_user)

    r = client.post("/api/v1/admin/logout", json={"refresh_token": "r1"})
    assert r.status_code == 200, r.text
    assert r.json() == payload

    # cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # service called with token and request path
    assert seen and seen[0][0] == "r1"
    assert seen[0][1].endswith("/api/v1/admin/logout")



def test_logout_requires_admin_and_skips_service(monkeypatch):
    app, client, mod, db, calls = _mk_app(monkeypatch, is_admin_impl=lambda _u: False)

    r = client.post("/api/v1/admin/logout", json={"refresh_token": "r2"})
    assert r.status_code == 403
    assert "Insufficient permissions" in r.text
    assert calls == []  # service not invoked


def test_logout_forwards_correct_arguments(monkeypatch):
    seen: Dict[str, Any] = {}

    async def _logout_user(refresh_token, db, request):
        seen["token"] = refresh_token
        seen["db_is_fake"] = isinstance(db, FakeDB)
        seen["url_path"] = str(request.url)
        return {"revoked": True}

    app, client, mod, db, calls = _mk_app(monkeypatch, logout_impl=_logout_user)

    r = client.post("/api/v1/admin/logout", json={"refresh_token": "zzz"})
    assert r.status_code == 200
    assert seen["token"] == "zzz"
    assert seen["db_is_fake"] is True
    assert seen["url_path"].endswith("/api/v1/admin/logout")


def test_logout_service_error_bubbles(monkeypatch):
    async def _boom(refresh_token, db, request):
        raise HTTPException(status_code=503, detail="service down")

    app, client, mod, db, calls = _mk_app(monkeypatch, logout_impl=_boom)

    r = client.post("/api/v1/admin/logout", json={"refresh_token": "r3"})
    assert r.status_code == 503
    assert "service down" in r.text


def test_logout_idempotency_semantics_ok_on_repeat(monkeypatch):
    # Service is responsible for idempotency; route just returns what it gets.
    async def _logout_user(refresh_token, db, request):
        return {"revoked": True}

    app, client, mod, db, calls = _mk_app(monkeypatch, logout_impl=_logout_user)

    r1 = client.post("/api/v1/admin/logout", json={"refresh_token": "same"})
    r2 = client.post("/api/v1/admin/logout", json={"refresh_token": "same"})
    assert r1.status_code == 200 and r1.json() == {"revoked": True}
    assert r2.status_code == 200 and r2.json() == {"revoked": True}
