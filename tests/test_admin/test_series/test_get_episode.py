# tests/test_admin/test_series/test_get_episode.py

import importlib
import uuid
from typing import Any, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes / doubles
# ─────────────────────────────────────────────────────────────────────────────

class _ScalarResult:
    def __init__(self, val): self._val = val
    def scalar_one_or_none(self): return self._val

class FakeDB:
    """AsyncSession-ish fake: route calls execute(...).scalar_one_or_none()."""
    def __init__(self, row: Any | None):
        self._row = row
        self.exec_calls = 0
    async def execute(self, _query, *_a, **_k):
        self.exec_calls += 1
        return _ScalarResult(self._row)

class FakeUser:
    def __init__(self): self.id = uuid.uuid4()

class EpisodeRow:
    """Minimal stand-in for ORM Episode with fields used by _ser_episode."""
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        season_id: Optional[uuid.UUID] = None,
        title_id: Optional[uuid.UUID] = None,
        episode_number: int = 1,
        name: Optional[str] = None,
        slug: Optional[str] = None,
        overview: Optional[str] = None,
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


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, db_row: Any | None):
    mod = importlib.import_module("app.api.v1.routers.admin.series")

    # Disable SlowAPI RL in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Bypass ADMIN + MFA
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Deterministic serializer for our fake EpisodeRow
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

    # Build app + overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(db_row)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap SlowAPI decorator (only swap endpoint; don't touch route.app)
    path = "/api/v1/admin/episodes/{episode_id}"
    for route in app.routes:
        if getattr(route, "path", None) == path and "GET" in getattr(route, "methods", set()):
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn
            break

    return app, TestClient(app), mod, db


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_get_episode_happy_path_returns_serialized_and_no_store(monkeypatch):
    e = EpisodeRow(episode_number=7, name="Lucky", slug="ep-7", runtime_minutes=50)
    app, client, mod, db = _mk_app(monkeypatch, db_row=e)

    r = client.get(f"/api/v1/admin/episodes/{e.id}")
    assert r.status_code == 200, r.text
    body = r.json()

    # Shape & values
    assert body["id"] == str(e.id)
    assert body["season_id"] == str(e.season_id)
    assert body["title_id"] == str(e.title_id)
    assert body["episode_number"] == 7
    assert body["name"] == "Lucky"
    assert body["slug"] == "ep-7"
    assert body["runtime_minutes"] == 50

    # Cache headers (seconds=0 → still no-store)
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # DB executed once
    assert db.exec_calls == 1


def test_get_episode_404_when_not_found(monkeypatch):
    missing = uuid.uuid4()
    app, client, mod, db = _mk_app(monkeypatch, db_row=None)

    r = client.get(f"/api/v1/admin/episodes/{missing}")
    assert r.status_code == 404
    assert "Episode not found" in r.text
