# tests/test_admin/test_taxonomy/test_create_genre.py

import importlib
import inspect
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.routing import request_response


class _OneResult:
    def __init__(self, row: Any | None):
        self._row = row
    def scalar_one_or_none(self):
        return self._row

class FakeDB:
    def __init__(self, *, row_for_execute: Any | None = None, raise_on_commit: bool = False):
        self.row_for_execute = row_for_execute
        self.raise_on_commit = raise_on_commit
        self.execute_calls: List[Tuple[Any, tuple, dict]] = []
        self.added: List[Any] = []
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0

    def add(self, obj: Any):
        self.added.append(obj)

    async def execute(self, query, *a, **k):
        self.execute_calls.append((query, a, k))
        return _OneResult(self.row_for_execute)

    async def flush(self):
        self.flush_calls += 1

    async def commit(self):
        self.commit_calls += 1
        if self.raise_on_commit:
            raise RuntimeError("commit boom")

    async def rollback(self):
        self.rollback_calls += 1


class FakeUser:
    def __init__(self, *, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


class FakeGenreRow:
    def __init__(self, *, slug: str):
        self.id = uuid.uuid4()
        self.slug = slug


def _mk_app(
    monkeypatch,
    *,
    db_row_for_conflict_check: Any | None = None,
    commit_should_fail: bool = False,
    idem_snapshot: Optional[dict] = None,
    fail_idem_set: bool = False,
):
    mod = importlib.import_module("app.api.v1.routers.admin.taxonomy")

    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    adm_mod = importlib.import_module("app.dependencies.admin")
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(adm_mod, "ensure_admin", _ok, raising=False)
    monkeypatch.setattr(adm_mod, "ensure_mfa", _ok, raising=False)

    async def _audit(*_a, **_k): return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Only patch Genre for happy-path tests where we won't call select(Genre).
    # For commit-error paths we must keep the real mapped class so select(Genre) works.
    if not commit_should_fail:
        class _Genre:
            def __init__(self, *, name, slug, description=None, parent_id=None, is_active=True, display_order=None):
                self.id = uuid.uuid4()
                self.name = name
                self.slug = slug
                self.description = description
                self.parent_id = parent_id
                self.is_active = bool(is_active)
                self.display_order = display_order
                self.created_at = None
                self.updated_at = None
        monkeypatch.setattr(mod, "Genre", _Genre, raising=False)

    class _Lock:
        def __init__(self, *_a, **_k): pass
        async def __aenter__(self): return None
        async def __aexit__(self, exc_type, exc, tb): return False

    class _Redis:
        def __init__(self):
            self.get_calls: List[str] = []
            self.set_calls: List[Tuple[str, Any, int]] = []
            self.snapshot = idem_snapshot
            self.fail_set = fail_idem_set
        async def idempotency_get(self, key: str):
            self.get_calls.append(key)
            return self.snapshot
        async def idempotency_set(self, key: str, val: Any, *, ttl_seconds: int):
            self.set_calls.append((key, val, ttl_seconds))
            if self.fail_set:
                raise RuntimeError("idem set boom")
            return True
        def lock(self, *a, **k):
            return _Lock()

    r = _Redis()
    monkeypatch.setattr(mod, "redis_wrapper", r, raising=False)

    app = FastAPI()
    app.include_router(mod.router)

    db = FakeDB(row_for_execute=db_row_for_conflict_check, raise_on_commit=commit_should_fail)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    path = "/api/v1/admin/genres"
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

    client = TestClient(app, raise_server_exceptions=not commit_should_fail)
    return app, client, mod, db, r, user


# ── Tests (unchanged) ────────────────────────────────────────────────────────

def test_create_genre_happy_path_no_idempotency_sets_no_store_and_returns_body(monkeypatch):
    app, client, mod, db, r, _ = _mk_app(monkeypatch)
    payload = {"name": "Action", "slug": "action", "description": "High energy", "is_active": True, "display_order": 1}
    resp = client.post("/api/v1/admin/genres", json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"] == "Action"
    assert body["slug"] == "action"
    assert body["description"] == "High energy"
    assert body["is_active"] is True
    assert body["display_order"] == 1
    assert "id" in body
    cc = (resp.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (resp.headers.get("pragma") or "").lower() == "no-cache"
    assert db.flush_calls >= 1 and db.commit_calls >= 1
    assert not r.set_calls

def test_create_genre_with_idempotency_sets_snapshot(monkeypatch):
    app, client, mod, db, r, _ = _mk_app(monkeypatch)
    resp = client.post("/api/v1/admin/genres", json={"name": "Drama", "slug": "drama"}, headers={"Idempotency-Key": "idem-1"})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["slug"] == "drama"
    assert r.set_calls and r.set_calls[-1][2] == 600
    key = r.set_calls[-1][0]
    assert "drama" in key and "idem-1" in key

def test_create_genre_idempotency_replay_skips_db(monkeypatch):
    snap = {"id": "g1", "name": "Sci-Fi", "slug": "sci-fi", "is_active": True, "display_order": None}
    app, client, mod, db, r, _ = _mk_app(monkeypatch, idem_snapshot=snap)
    resp = client.post("/api/v1/admin/genres", json={"name": "ignored", "slug": "ignored"}, headers={"Idempotency-Key": "again"})
    assert resp.status_code == 200, resp.text
    assert resp.json() == snap
    assert db.flush_calls == 0 and db.commit_calls == 0
    assert not r.set_calls

def test_create_genre_invalid_slug_400(monkeypatch):
    app, client, *_ = _mk_app(monkeypatch)
    resp = client.post("/api/v1/admin/genres", json={"name": "Bad", "slug": "NOT_valid"})
    assert resp.status_code == 400
    assert "kebab" in resp.text.lower()

def test_create_genre_conflict_409_when_slug_exists(monkeypatch):
    existing = FakeGenreRow(slug="thriller")
    app, client, mod, db, r, _ = _mk_app(
        monkeypatch,
        db_row_for_conflict_check=existing,
        commit_should_fail=True,
    )
    resp = client.post("/api/v1/admin/genres", json={"name": "Thriller", "slug": "thriller"})
    assert resp.status_code == 409
    assert "already exists" in resp.text.lower()
    assert db.rollback_calls >= 1

def test_create_genre_commit_error_without_existing_bubbles_500(monkeypatch):
    app, client, mod, db, r, _ = _mk_app(
        monkeypatch,
        db_row_for_conflict_check=None,
        commit_should_fail=True,
    )
    resp = client.post("/api/v1/admin/genres", json={"name": "X", "slug": "x"})
    assert resp.status_code == 500
