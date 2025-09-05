# tests/test_admin/test_series/test_patch_season.py

import importlib
import uuid
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class _ScalarResult:
    def __init__(self, val): self._val = val
    def scalar_one_or_none(self): return self._val

class FakeDB:
    """
    AsyncSession-ish fake.
    Queue values for .execute(...).scalar_one_or_none() calls.
    Track flush/commit calls.
    """
    def __init__(self, results: List[Any]):
        self._results = list(results)
        self.exec_queries: List[Any] = []
        self.flush_calls = 0
        self.commit_calls = 0

    async def execute(self, query, *_a, **_k):
        self.exec_queries.append(query)
        if self._results:
            return _ScalarResult(self._results.pop(0))
        return _ScalarResult(None)

    async def flush(self):
        self.flush_calls += 1

    async def commit(self):
        self.commit_calls += 1

class FakeUser:
    def __init__(self): self.id = uuid.uuid4()

class SeasonRow:
    """Minimal ORM-like Season row the route mutates and serializes."""
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        title_id: Optional[uuid.UUID] = None,
        season_number: int = 1,
        name: Optional[str] = "Old",
        slug: Optional[str] = "old",
        overview: Optional[str] = "old desc",
        release_date: Optional[date] = None,
        end_date: Optional[date] = None,
        is_published: bool = False,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
    ):
        self.id = id or uuid.uuid4()
        self.title_id = title_id or uuid.uuid4()
        self.season_number = season_number
        self.name = name
        self.slug = slug
        self.overview = overview
        self.release_date = release_date
        self.end_date = end_date
        self.is_published = is_published
        self.created_at = created_at
        self.updated_at = updated_at

class _AsyncLockCtx:
    def __init__(self, key, capture: List[str]): self.key = key; self.capture = capture
    async def __aenter__(self): self.capture.append(self.key)
    async def __aexit__(self, *_): return False


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    db_results: List[Any],
):
    mod = importlib.import_module("app.api.v1.routers.admin.series")

    # Disable SlowAPI RL in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Bypass ADMIN + MFA
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Deterministic serializer compatible with our fake SeasonRow
    def _ser(s):
        return {
            "id": str(s.id),
            "title_id": str(s.title_id),
            "season_number": s.season_number,
            "name": getattr(s, "name", None),
            "slug": getattr(s, "slug", None),
            "overview": getattr(s, "overview", None),
            "release_date": getattr(s, "release_date", None),
            "end_date": getattr(s, "end_date", None),
            "episode_count": int(getattr(s, "episode_count", 0) or 0),
            "is_published": getattr(s, "is_published", False),
            "created_at": getattr(s, "created_at", None),
            "updated_at": getattr(s, "updated_at", None),
        }
    monkeypatch.setattr(mod, "_ser_season", _ser, raising=False)

    # Capture audit call to assert updated fields list
    audit_calls: List[Dict[str, Any]] = []
    async def _audit(*_a, **k):
        audit_calls.append(k)
        return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Redis lock
    lock_keys: List[str] = []
    def _lock(key: str, timeout=10, blocking_timeout=3):
        return _AsyncLockCtx(key, lock_keys)
    monkeypatch.setattr(mod.redis_wrapper, "lock", _lock, raising=False)

    # Build app
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(db_results)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap SlowAPI decorator (only swap endpoint, don't overwrite route.app)
    path = "/api/v1/admin/seasons/{season_id}"
    for route in app.routes:
        if getattr(route, "path", None) == path and "PATCH" in getattr(route, "methods", set()):
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn
            break

    client = TestClient(app)
    return app, client, mod, db, {"audit_calls": audit_calls, "lock_keys": lock_keys}


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_patch_season_happy_path_updates_fields_trims_and_sets_no_store(monkeypatch):
    s = SeasonRow(name="Old", slug="old")
    # DB results queue:
    # 1) SELECT ... FOR UPDATE -> season row
    # 2) SELECT duplicate slug check -> None (no dup)
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[s, None])

    r = client.patch(
        f"/api/v1/admin/seasons/{s.id}",
        json={"name": "  New Name  ", "slug": "  new-slug  ", "overview": "updated"},
    )
    assert r.status_code == 200, r.text
    body = r.json()

    # Mutations applied + trimmed
    assert body["name"] == "New Name"
    assert body["slug"] == "new-slug"
    assert body["overview"] == "updated"

    # Cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # DB ops and lock
    assert db.flush_calls == 1
    assert db.commit_calls == 1
    assert st["lock_keys"] and st["lock_keys"][0].endswith(str(s.id))

    # Audit fields capture includes only mutated keys
    assert st["audit_calls"], "log_audit_event should be called"
    fields = st["audit_calls"][-1]["meta_data"]["fields"]
    assert set(fields) == {"name", "slug", "overview"}


def test_patch_season_404_when_row_missing(monkeypatch):
    # 1) SELECT ... FOR UPDATE -> None
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[None])

    r = client.patch(f"/api/v1/admin/seasons/{uuid.uuid4()}", json={"name": "X"})
    assert r.status_code == 404
    assert "Season not found" in r.text
    assert db.commit_calls == 0
    assert st["lock_keys"] and st["lock_keys"][0].startswith("lock:admin_season:patch:")


def test_patch_season_400_when_no_changes(monkeypatch):
    s = SeasonRow()
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[s])

    # Empty payload -> route detects no changes and raises 400
    r = client.patch(f"/api/v1/admin/seasons/{s.id}", json={})
    assert r.status_code == 400
    assert "No changes provided" in r.text
    assert db.commit_calls == 0


def test_patch_season_409_on_slug_duplicate(monkeypatch):
    s = SeasonRow()
    # 1) SELECT ... FOR UPDATE -> s
    # 2) SELECT duplicate slug check -> returns a row -> conflict
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[s, object()])

    r = client.patch(f"/api/v1/admin/seasons/{s.id}", json={"slug": "taken"})
    assert r.status_code == 409
    assert "Season slug already exists" in r.text
    assert db.commit_calls == 0


def test_patch_season_update_only_name_trims(monkeypatch):
    s = SeasonRow(name="  Old Name  ", slug="kept")
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[s])

    r = client.patch(f"/api/v1/admin/seasons/{s.id}", json={"name": "  New  "})
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "New"
    # slug unchanged
    assert body["slug"] == "kept"
    assert db.commit_calls == 1
