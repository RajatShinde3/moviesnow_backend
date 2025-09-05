# tests/test_admin/test_series/test_patch_episode.py

import importlib
import uuid
from typing import Any, Dict, List, Optional

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

class EpisodeRow:
    """Minimal ORM-like Episode row the route mutates and serializes."""
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        season_id: Optional[uuid.UUID] = None,
        title_id: Optional[uuid.UUID] = None,
        episode_number: int = 1,
        name: Optional[str] = "Old",
        slug: Optional[str] = "old",
        overview: Optional[str] = "old desc",
        air_date: Optional[str] = None,
        runtime_minutes: Optional[int] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
    ):
        self.id = id or uuid.uuid4()
        self.season_id = season_id or uuid.uuid4()
        self.title_id = title_id or uuid.uuid4()
        self.episode_number = episode_number
        self.name = name
        self.slug = slug
        self.overview = overview
        self.air_date = air_date
        self.runtime_minutes = runtime_minutes
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

    # Deterministic serializer compatible with our fake EpisodeRow
    def _ser(e):
        return {
            "id": str(e.id),
            "season_id": str(e.season_id),
            "title_id": str(e.title_id),
            "episode_number": e.episode_number,
            "name": getattr(e, "name", None),
            "slug": getattr(e, "slug", None),
            "overview": getattr(e, "overview", None),
            "air_date": getattr(e, "air_date", None),
            "runtime_minutes": getattr(e, "runtime_minutes", None),
            "created_at": getattr(e, "created_at", None),
            "updated_at": getattr(e, "updated_at", None),
        }
    monkeypatch.setattr(mod, "_ser_episode", _ser, raising=False)

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

    # Unwrap SlowAPI decorator (only swap endpoint)
    path = "/api/v1/admin/episodes/{episode_id}"
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

def test_patch_episode_happy_path_updates_fields_trims_and_sets_no_store(monkeypatch):
    e = EpisodeRow(name="Old", slug="old", overview="x")
    # DB results queue:
    # 1) SELECT ... FOR UPDATE -> episode row
    # 2) SELECT duplicate slug check -> None (no dup)
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[e, None])

    r = client.patch(
        f"/api/v1/admin/episodes/{e.id}",
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
    assert st["lock_keys"] and st["lock_keys"][0].endswith(str(e.id))

    # Audit fields capture includes only mutated keys
    assert st["audit_calls"], "log_audit_event should be called"
    fields = st["audit_calls"][-1]["meta_data"]["fields"]
    assert set(fields) == {"name", "slug", "overview"}


def test_patch_episode_404_when_row_missing(monkeypatch):
    # 1) SELECT ... FOR UPDATE -> None
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[None])

    r = client.patch(f"/api/v1/admin/episodes/{uuid.uuid4()}", json={"name": "X"})
    assert r.status_code == 404
    assert "Episode not found" in r.text
    assert db.commit_calls == 0
    assert st["lock_keys"] and st["lock_keys"][0].startswith("lock:admin_episode:patch:")


def test_patch_episode_400_when_no_changes(monkeypatch):
    e = EpisodeRow()
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[e])

    # Empty payload -> route detects no changes and raises 400
    r = client.patch(f"/api/v1/admin/episodes/{e.id}", json={})
    assert r.status_code == 400
    assert "No changes provided" in r.text
    assert db.commit_calls == 0


def test_patch_episode_409_on_slug_duplicate(monkeypatch):
    e = EpisodeRow()
    # 1) SELECT ... FOR UPDATE -> e
    # 2) SELECT duplicate slug check -> returns a row -> conflict
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[e, object()])

    r = client.patch(f"/api/v1/admin/episodes/{e.id}", json={"slug": "taken"})
    assert r.status_code == 409
    assert "Episode slug already exists for this season" in r.text
    assert db.commit_calls == 0


def test_patch_episode_update_only_name_trims(monkeypatch):
    e = EpisodeRow(name="  Old Name  ", slug="kept")
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[e])

    r = client.patch(f"/api/v1/admin/episodes/{e.id}", json={"name": "  New  "})
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "New"
    # slug unchanged
    assert body["slug"] == "kept"
    assert db.commit_calls == 1

    # Audit fields capture only "name"
    assert st["audit_calls"], "log_audit_event should be called"
    fields = st["audit_calls"][-1]["meta_data"]["fields"]
    assert fields == ["name"]
