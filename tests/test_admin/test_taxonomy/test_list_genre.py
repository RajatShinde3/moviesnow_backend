# tests/test_admin/test_taxonomy/test_list_genre.py

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
    def __init__(self, rows: List[Any]): self._rows = rows
    def all(self): return list(self._rows)

class _Result:
    def __init__(self, rows: List[Any]): self._rows = rows
    def scalars(self): return _Scalars(self._rows)

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

class GenreRow:
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        name: str,
        slug: str,
        description: Optional[str] = None,
        parent_id: Optional[uuid.UUID] = None,
        is_active: bool = True,
        display_order: Optional[int] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
    ):
        self.id = id or uuid.uuid4()
        self.name = name
        self.slug = slug
        self.description = description
        self.parent_id = parent_id
        self.is_active = is_active
        self.display_order = display_order
        self.created_at = created_at or datetime(2025, 1, 1, tzinfo=timezone.utc)
        self.updated_at = updated_at


# ─────────────────────────────────────────────────────────────────────────────
# App factory (prefix-safe + SlowAPI-robust)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, rows: List[Any]):
    mod = importlib.import_module("app.api.v1.routers.admin.taxonomy")

    # Disable rate limiting
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Patch the dependency module the route imports at call-time
    adm = importlib.import_module("app.dependencies.admin")
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(adm, "ensure_admin", _ok, raising=False)
    monkeypatch.setattr(adm, "ensure_mfa", _ok, raising=False)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB(rows)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Find the route for list_genres and unwrap it robustly
    path = None
    for route in app.routes:
        endpoint = getattr(route, "endpoint", None)
        if not endpoint:
            continue
        fn = endpoint
        while hasattr(fn, "__wrapped__"):
            fn = fn.__wrapped__
        if getattr(fn, "__name__", "") == "list_genres":
            path = getattr(route, "path", None)
            # robust unwrap for SlowAPI
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

    assert path, "Could not locate list_genres route"
    client = TestClient(app)
    return app, client, mod, db, path


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_list_genres_happy_path_no_filters_and_no_store(monkeypatch):
    rows = [
        GenreRow(name="Action", slug="action", display_order=2),
        GenreRow(name="Drama", slug="drama", display_order=1),
    ]
    app, client, mod, db, path = _mk_app(monkeypatch, rows=rows)

    r = client.get(path)
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data, list) and len(data) == 2
    assert {d["slug"] for d in data} == {"action", "drama"}

    # cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    assert db.execute_calls  # DB hit

def test_list_genres_search_q_filters_results(monkeypatch):
    rows = [GenreRow(name="Thriller", slug="thriller")]
    app, client, mod, db, path = _mk_app(monkeypatch, rows=rows)

    r = client.get(f"{path}?q=thr")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1 and body[0]["slug"] == "thriller"

def test_list_genres_filter_is_active_true(monkeypatch):
    rows = [GenreRow(name="Live", slug="live", is_active=True)]
    app, client, mod, db, path = _mk_app(monkeypatch, rows=rows)

    r = client.get(f"{path}?is_active=true")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1 and body[0]["slug"] == "live"

def test_list_genres_filter_is_active_false(monkeypatch):
    rows = [GenreRow(name="Legacy", slug="legacy", is_active=False)]
    app, client, mod, db, path = _mk_app(monkeypatch, rows=rows)

    r = client.get(f"{path}?is_active=false")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1 and body[0]["slug"] == "legacy"

def test_list_genres_pagination_params_passthrough(monkeypatch):
    rows = [GenreRow(name="Only", slug="only")]
    app, client, mod, db, path = _mk_app(monkeypatch, rows=rows)

    r = client.get(f"{path}?limit=1&offset=0")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1 and body[0]["slug"] == "only"

def test_list_genres_empty_list(monkeypatch):
    app, client, mod, db, path = _mk_app(monkeypatch, rows=[])
    r = client.get(path)
    assert r.status_code == 200
    assert r.json() == []
