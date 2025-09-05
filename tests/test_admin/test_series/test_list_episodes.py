# tests/test_admin/test_series/test_list_episodes.py

import importlib
import uuid
from typing import Any, List, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes / doubles
# ─────────────────────────────────────────────────────────────────────────────

class _ScalarsSeq:
    def __init__(self, rows: List[Any]): self._rows = rows
    def all(self): return list(self._rows)

class _ExecuteResult:
    def __init__(self, rows: List[Any]): self._rows = rows
    def scalars(self): return _ScalarsSeq(self._rows)

class FakeDB:
    """AsyncSession-ish fake returning a result with .scalars().all()."""
    def __init__(self, rows: List[Any]):
        self._rows = rows
        self.exec_calls: List[Any] = []

    async def execute(self, query, *_a, **_k):
        self.exec_calls.append(query)
        return _ExecuteResult(self._rows)

class FakeUser:
    def __init__(self): self.id = uuid.uuid4()

class EpisodeRow:
    """Minimal stand-in for ORM Episode, enough for serializer."""
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

def _mk_app(monkeypatch, *, rows: List[EpisodeRow]):
    mod = importlib.import_module("app.api.v1.routers.admin.series")

    # Disable SlowAPI RL in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Bypass ADMIN + MFA
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Deterministic serializer for our fake EpisodeRow
    def _ser_episode(e):
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
    monkeypatch.setattr(mod, "_ser_episode", _ser_episode, raising=False)

    # Build app + overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(rows)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap SlowAPI decorator (only replace the endpoint; don't touch route.app)
    path = "/api/v1/admin/seasons/{season_id}/episodes"
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

def test_list_episodes_happy_path_returns_serialized_and_no_store(monkeypatch):
    season_id = uuid.uuid4()
    e1 = EpisodeRow(season_id=season_id, episode_number=1, name="Pilot", slug="ep-1", runtime_minutes=42)
    e2 = EpisodeRow(season_id=season_id, episode_number=2, name="Next", slug="ep-2", runtime_minutes=44)

    # Return rows already in ascending order (DB would enforce order_by in real life)
    app, client, mod, db = _mk_app(monkeypatch, rows=[e1, e2])

    r = client.get(f"/api/v1/admin/seasons/{season_id}/episodes")
    assert r.status_code == 200, r.text
    data = r.json()

    assert isinstance(data, list) and len(data) == 2
    assert [d["episode_number"] for d in data] == [1, 2]
    assert data[0]["name"] == "Pilot"
    assert data[1]["slug"] == "ep-2"
    assert data[0]["season_id"] == str(season_id) == data[1]["season_id"]

    # cache headers (seconds=0 → still no-store)
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"


def test_list_episodes_empty_list(monkeypatch):
    season_id = uuid.uuid4()
    app, client, mod, db = _mk_app(monkeypatch, rows=[])

    r = client.get(f"/api/v1/admin/seasons/{season_id}/episodes")
    assert r.status_code == 200
    assert r.json() == []


def test_list_episodes_limit_offset_validation(monkeypatch):
    season_id = uuid.uuid4()
    e = EpisodeRow(season_id=season_id, episode_number=1)
    app, client, mod, db = _mk_app(monkeypatch, rows=[e])

    # limit must be >= 1
    r = client.get(f"/api/v1/admin/seasons/{season_id}/episodes?limit=0")
    assert r.status_code == 422

    # offset must be >= 0
    r = client.get(f"/api/v1/admin/seasons/{season_id}/episodes?offset=-1")
    assert r.status_code == 422
