# tests/test_admin/test_series/test_get_season.py

import importlib
import uuid
from datetime import date
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


class SeasonRow:
    """Minimal stand-in for ORM Season with fields used by _ser_season."""
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        title_id: Optional[uuid.UUID] = None,
        season_number: int = 1,
        name: Optional[str] = None,
        slug: Optional[str] = None,
        overview: Optional[str] = None,
        release_date: Optional[date] = None,
        end_date: Optional[date] = None,
        is_published: bool = False,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
        episode_count: int = 0,
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
        self.episode_count = episode_count


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, db_row: Any | None):
    mod = importlib.import_module("app.api.v1.routers.admin.series")

    # Disable rate limiting (SlowAPI) in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Bypass ADMIN + MFA checks
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Deterministic serializer for our fake SeasonRow
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

    # Build FastAPI app + dependency overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(db_row)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap SlowAPI RL decorator (only swap the endpoint; don't touch route.app)
    path = "/api/v1/admin/seasons/{season_id}"
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

def test_get_season_happy_path_returns_serialized_and_no_store(monkeypatch):
    s = SeasonRow(season_number=2, name="Season Two", slug="s2", overview="desc", episode_count=8)
    app, client, mod, db = _mk_app(monkeypatch, db_row=s)

    r = client.get(f"/api/v1/admin/seasons/{s.id}")
    assert r.status_code == 200, r.text
    body = r.json()

    # Shape & values
    assert body["id"] == str(s.id)
    assert body["title_id"] == str(s.title_id)
    assert body["season_number"] == 2
    assert body["name"] == "Season Two"
    assert body["slug"] == "s2"
    assert body["overview"] == "desc"
    assert body["episode_count"] == 8

    # Cache headers (seconds=0 still implies no-store)
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # DB executed once
    assert db.exec_calls == 1


def test_get_season_404_when_not_found(monkeypatch):
    missing = uuid.uuid4()
    app, client, mod, db = _mk_app(monkeypatch, db_row=None)

    r = client.get(f"/api/v1/admin/seasons/{missing}")
    assert r.status_code == 404
    assert "Season not found" in r.text
