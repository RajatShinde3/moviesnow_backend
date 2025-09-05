# tests/test_admin/test_series/test_list_seasons.py

import importlib
import uuid
from datetime import date
from typing import Any, List, Optional, Tuple, Dict

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes / doubles
# ─────────────────────────────────────────────────────────────────────────────

class _AllResult:
    def __init__(self, rows: List[Tuple[Any, Any]]):
        self._rows = rows
    def all(self):
        return list(self._rows)


class FakeDB:
    """
    AsyncSession-ish fake:
    - execute(): returns one object with .all() that yields our pre-baked rows
    """
    def __init__(self, rows: List[Tuple[Any, Any]]):
        self._rows = rows
        self.exec_calls: List[Any] = []

    async def execute(self, query, *_a, **_k):
        # record the SQLAlchemy selectable passed in
        self.exec_calls.append(query)
        return _AllResult(self._rows)


class FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()


class SeasonRow:
    """Minimal object to mimic an ORM Season for serialization."""
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        title_id: Optional[uuid.UUID] = None,
        season_number: int,
        name: Optional[str] = None,
        slug: Optional[str] = None,
        overview: Optional[str] = None,
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
        # episode_count will be injected by the route via setattr


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    rows: List[Tuple[SeasonRow, Optional[int]]],
):
    mod = importlib.import_module("app.api.v1.routers.admin.series")

    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Bypass ADMIN + MFA guards
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Make serializer deterministic and tolerant of our fake SeasonRow
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

    # Build app and dependency overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(rows)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap SlowAPI decorator to avoid 429s (only swap endpoint)
    path = "/api/v1/admin/titles/{title_id}/seasons"
    for route in app.routes:
        if getattr(route, "path", None) == path and "GET" in getattr(route, "methods", set()):
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn
            break

    client = TestClient(app)
    return app, client, mod, db


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_list_seasons_happy_path_returns_serialized_counts_and_no_store(monkeypatch):
    title_id = uuid.uuid4()
    s1 = SeasonRow(title_id=title_id, season_number=1, name="One", slug="s1")
    s2 = SeasonRow(title_id=title_id, season_number=2, name="Two", slug="s2")
    # Route expects db.execute(...).all() → [(Season, count), ...]
    app, client, mod, db = _mk_app(monkeypatch, rows=[(s1, 5), (s2, 2)])

    r = client.get(f"/api/v1/admin/titles/{title_id}/seasons")
    assert r.status_code == 200, r.text
    data = r.json()

    assert isinstance(data, list) and len(data) == 2
    assert [d["season_number"] for d in data] == [1, 2]
    assert [d["episode_count"] for d in data] == [5, 2]
    assert data[0]["name"] == "One" and data[1]["name"] == "Two"

    # cache headers (seconds=0 → still no-store)
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"


def test_list_seasons_empty_list(monkeypatch):
    title_id = uuid.uuid4()
    app, client, mod, db = _mk_app(monkeypatch, rows=[])

    r = client.get(f"/api/v1/admin/titles/{title_id}/seasons")
    assert r.status_code == 200
    assert r.json() == []


def test_list_seasons_coalesces_none_count_to_zero(monkeypatch):
    title_id = uuid.uuid4()
    s = SeasonRow(title_id=title_id, season_number=3, name="Three", slug="s3")
    # Simulate NULL count; route does int(cnt or 0)
    app, client, mod, db = _mk_app(monkeypatch, rows=[(s, None)])

    r = client.get(f"/api/v1/admin/titles/{title_id}/seasons")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["episode_count"] == 0


def test_list_seasons_limit_offset_validation(monkeypatch):
    title_id = uuid.uuid4()
    s = SeasonRow(title_id=title_id, season_number=1)
    app, client, mod, db = _mk_app(monkeypatch, rows=[(s, 1)])

    # limit must be >=1 → 422
    r = client.get(f"/api/v1/admin/titles/{title_id}/seasons?limit=0")
    assert r.status_code == 422

    # offset must be >=0 → -1 should 422
    r = client.get(f"/api/v1/admin/titles/{title_id}/seasons?offset=-1")
    assert r.status_code == 422
