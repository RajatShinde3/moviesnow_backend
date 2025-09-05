# tests/test_admin/test_taxonomy/test_patch_genre.py

import importlib
import uuid
from typing import Any, Dict, List, Optional, Tuple
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
    """
    AsyncSession-ish stub:
      - 1st .execute() → row for SELECT ... FOR UPDATE (by id)
      - 2nd .execute() → row for slug conflict check (optional)
    """
    def __init__(self, first_row: Any | None, conflict_row: Any | None = None, commit_should_fail: bool = False):
        self.first_row = first_row
        self.conflict_row = conflict_row
        self.commit_should_fail = commit_should_fail

        self.execute_calls: List[Tuple[Any, tuple, dict]] = []
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0
        self._call_idx = 0

    async def execute(self, query, *a, **k):
        self.execute_calls.append((query, a, k))
        self._call_idx += 1
        if self._call_idx == 1:
            return _OneResult(self.first_row)
        return _OneResult(self.conflict_row)

    async def flush(self):
        self.flush_calls += 1

    async def commit(self):
        self.commit_calls += 1
        if self.commit_should_fail:
            raise RuntimeError("commit boom")

    async def rollback(self):
        self.rollback_calls += 1

class FakeGenreRow:
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        name: str = "Genre",
        slug: str = "genre",
        description: Optional[str] = None,
        parent_id: Optional[uuid.UUID] = None,
        is_active: bool = True,
        display_order: Optional[int] = 1,
        # use strings to avoid datetime JSON issues in tests
        created_at: Optional[str] = "2025-01-01T00:00:00Z",
        updated_at: Optional[str] = None,
    ):
        self.id = id or uuid.uuid4()
        self.name = name
        self.slug = slug
        self.description = description
        self.parent_id = parent_id
        self.is_active = is_active
        self.display_order = display_order
        self.created_at = created_at
        self.updated_at = updated_at


# ─────────────────────────────────────────────────────────────────────────────
# App factory (version-proof SlowAPI unwrap)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    first_row: Any | None,                # row found by id (FOR UPDATE)
    conflict_row: Any | None = None,      # row found by slug conflict check
    commit_should_fail: bool = False,
):
    mod = importlib.import_module("app.api.v1.routers.admin.taxonomy")

    # Disable rate limiting
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Security gates no-op (patch the module the route imports from)
    async def _ok(*_a, **_k): return None
    admin_mod = importlib.import_module("app.dependencies.admin")
    monkeypatch.setattr(admin_mod, "ensure_admin", _ok, raising=False)
    monkeypatch.setattr(admin_mod, "ensure_mfa", _ok, raising=False)


    # Audit is best-effort; stub to no-op
    async def _audit(*_a, **_k): return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Fake Redis lock
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

    # Build app + dependency overrides
    app = FastAPI()
    # IMPORTANT: the router in taxonomy.py already has prefix="/api/v1/admin"
    app.include_router(mod.router)  # ← no extra prefix here

    db = FakeDB(first_row=first_row, conflict_row=conflict_row, commit_should_fail=commit_should_fail)
    app.dependency_overrides[mod.get_async_db] = lambda: db
    # taxonomy endpoints depend on current_user for ensure_admin/ensure_mfa but the
    # patched ensure_admin/ensure_mfa don’t actually use it; provide a dummy.
    class _User: pass
    app.dependency_overrides[mod.get_current_user] = lambda: _User()

    # Unwrap SlowAPI for PATCH /api/v1/admin/genres/{genre_id}
    path = "/api/v1/admin/genres/{genre_id}"
    for route in app.routes:
        if getattr(route, "path", None) == path and "PATCH" in getattr(route, "methods", set()):
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

    client = TestClient(app, raise_server_exceptions=False)
    return app, client, mod, db, r


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_patch_genre_happy_path_updates_fields_and_no_store(monkeypatch):
    row = FakeGenreRow(name="Old", slug="old", description="d", is_active=True, display_order=1)
    app, client, mod, db, r = _mk_app(monkeypatch, first_row=row)

    payload = {"name": "New Name", "slug": "new-slug", "description": "new desc", "display_order": 7}
    resp = client.patch(f"/api/v1/admin/genres/{row.id}", json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # Check updates applied and reflected
    assert row.name == "New Name"
    assert row.slug == "new-slug"
    assert row.description == "new desc"
    assert row.display_order == 7
    assert data.get("name") == "New Name"
    assert data.get("slug") == "new-slug"
    assert data.get("description") == "new desc"
    assert data.get("display_order") == 7

    # cache headers
    cc = (resp.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (resp.headers.get("pragma") or "").lower() == "no-cache"

    # DB flush/commit under lock
    assert db.flush_calls >= 1 and db.commit_calls >= 1
    assert r.lock_keys and r.lock_keys[-1].endswith(str(row.id))


def test_patch_genre_400_no_changes_provided(monkeypatch):
    row = FakeGenreRow()
    app, client, mod, db, r = _mk_app(monkeypatch, first_row=row)

    resp = client.patch(f"/api/v1/admin/genres/{row.id}", json={})
    assert resp.status_code == 400
    assert "No changes provided" in resp.text
    assert db.flush_calls == 0 and db.commit_calls == 0


def test_patch_genre_400_bad_slug(monkeypatch):
    row = FakeGenreRow()
    app, client, mod, db, r = _mk_app(monkeypatch, first_row=row)

    resp = client.patch(f"/api/v1/admin/genres/{row.id}", json={"slug": "Bad_Slug"})
    assert resp.status_code == 400
    assert "kebab" in resp.text


def test_patch_genre_404_when_not_found(monkeypatch):
    app, client, mod, db, r = _mk_app(monkeypatch, first_row=None)

    gid = uuid.uuid4()
    resp = client.patch(f"/api/v1/admin/genres/{gid}", json={"name": "X"})
    assert resp.status_code == 404
    assert "Genre not found" in resp.text


def test_patch_genre_conflict_409_when_slug_exists_on_commit_fail(monkeypatch):
    row = FakeGenreRow(slug="old")
    existing = FakeGenreRow(slug="dup")  # returned by conflict check
    app, client, mod, db, r = _mk_app(
        monkeypatch,
        first_row=row,
        conflict_row=existing,
        commit_should_fail=True,
    )

    resp = client.patch(f"/api/v1/admin/genres/{row.id}", json={"slug": "dup"})
    assert resp.status_code == 409
    assert "already exists" in resp.text
    assert db.rollback_calls >= 1


def test_patch_genre_commit_error_without_conflict_bubbles_500(monkeypatch):
    row = FakeGenreRow(slug="s1")
    app, client, mod, db, r = _mk_app(
        monkeypatch,
        first_row=row,
        conflict_row=None,          # conflict check finds nothing
        commit_should_fail=True,    # commit raises
    )

    resp = client.patch(f"/api/v1/admin/genres/{row.id}", json={"name": "Z"})
    # route re-raises → 500
    assert resp.status_code == 500
    assert db.rollback_calls >= 1
