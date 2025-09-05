# tests/test_admin/test_series/test_create_episode.py

import importlib
import uuid
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes / doubles
# ─────────────────────────────────────────────────────────────────────────────

class _ScalarResult:
    def __init__(self, val): self._val = val
    def scalar_one_or_none(self): return self._val

class FakeDB:
    """
    AsyncSession-ish fake with a queue of values returned from .execute(...).
    The route only calls:
      - execute(...).scalar_one_or_none()   (season check + dup guards)
      - add(obj), flush(), commit(), refresh(obj?)
    """
    def __init__(self, results: List[Any]):
        self._results = list(results)
        self.exec_queries: List[Any] = []
        self.added: List[Any] = []
        self.flush_calls = 0
        self.commit_calls = 0
        self.refresh_calls = 0

    async def execute(self, query, *_a, **_k):
        self.exec_queries.append(query)
        if self._results:
            return _ScalarResult(self._results.pop(0))
        return _ScalarResult(None)

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        self.flush_calls += 1

    async def commit(self):
        self.commit_calls += 1
        # Give created ORM objects an id if missing so serializer has one
        for obj in self.added:
            if getattr(obj, "id", None) is None:
                setattr(obj, "id", uuid.uuid4())

    async def refresh(self, _obj):
        self.refresh_calls += 1


class FakeUser:
    def __init__(self): self.id = uuid.uuid4()


class SeasonStub:
    """Only fields the route reads from the season row."""
    def __init__(self, *, title_id: Optional[uuid.UUID] = None):
        self.id = uuid.uuid4()
        self.title_id = title_id or uuid.uuid4()


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
    redis_snap: Optional[Dict[str, Any]] = None,
    capture_set: bool = False,
    set_raises: bool = False,
):
    """
    - db_results supplies values for sequential .execute(...).scalar_one_or_none() calls:
        1) season existence check
        2) duplicate "episode_number" check
        3) duplicate "slug" check (only if slug provided)
    - redis_snap: returned by idempotency_get if present (to test replay).
    - capture_set: record idempotency_set(key, value, ttl) calls.
    - set_raises: make idempotency_set raise (error should be swallowed).
    """
    mod = importlib.import_module("app.api.v1.routers.admin.series")

    # Disable SlowAPI rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Bypass ADMIN + MFA checks
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Serializer for our test (robust to real ORM vs simple objects)
    def _ser_episode(e):
        return {
            "id": str(getattr(e, "id", uuid.uuid4())),
            "season_id": str(getattr(e, "season_id", "")),
            "title_id": str(getattr(e, "title_id", "")),
            "episode_number": getattr(e, "episode_number", None),
            "name": getattr(e, "name", None),
            "slug": getattr(e, "slug", None),
            "overview": getattr(e, "overview", None),
            "air_date": getattr(e, "air_date", None),
            "runtime_minutes": getattr(e, "runtime_minutes", None),
            "created_at": getattr(e, "created_at", None),
            "updated_at": getattr(e, "updated_at", None),
        }
    monkeypatch.setattr(mod, "_ser_episode", _ser_episode, raising=False)

    # Redis idempotency fakes
    get_calls: List[str] = []
    set_calls: List[Tuple[str, Dict[str, Any], int]] = []

    async def _id_get(key):
        get_calls.append(key)
        return redis_snap

    async def _id_set(key, val, ttl_seconds=600):
        if set_raises:
            raise RuntimeError("redis set down")
        if capture_set:
            set_calls.append((key, val, ttl_seconds))

    monkeypatch.setattr(mod.redis_wrapper, "idempotency_get", _id_get, raising=False)
    monkeypatch.setattr(mod.redis_wrapper, "idempotency_set", _id_set, raising=False)

    # Redis lock
    lock_keys: List[str] = []
    def _lock(key: str, timeout=10, blocking_timeout=3):
        return _AsyncLockCtx(key, lock_keys)
    monkeypatch.setattr(mod.redis_wrapper, "lock", _lock, raising=False)

    # Audit (async no-op but capture)
    audit_calls: List[Dict[str, Any]] = []
    async def _audit(*_a, **k):
        audit_calls.append(k)
        return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Build app and dependency overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(db_results)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap SlowAPI decorator (only replace endpoint; don't touch route.app)
    path = "/api/v1/admin/seasons/{season_id}/episodes"
    for route in app.routes:
        if getattr(route, "path", None) == path and "POST" in getattr(route, "methods", set()):
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn
            break

    client = TestClient(app)
    return app, client, mod, db, {
        "lock_keys": lock_keys,
        "id_get_calls": get_calls,
        "id_set_calls": set_calls,
        "audit_calls": audit_calls,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_create_episode_happy_path_returns_serialized_and_no_store(monkeypatch):
    season = SeasonStub()
    # Queue: season row, dup-number None, dup-slug None
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[season, None, None])

    payload = {
        "episode_number": 1,
        "name": "  Pilot  ",
        "slug": "  ep-1  ",
        "overview": "Desc",
        "runtime_minutes": 42,
        # air_date optional — you can include like: "air_date": "2025-01-01"
    }
    r = client.post(f"/api/v1/admin/seasons/{season.id}/episodes", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()

    # Basic shape + trimming
    assert body["id"]
    assert body["season_id"] == str(season.id)
    assert body["title_id"] == str(season.title_id)
    assert body["episode_number"] == 1
    assert body["name"] == "Pilot"        # trimmed
    assert body["slug"] == "ep-1"         # trimmed
    assert body["overview"] == "Desc"
    assert body["runtime_minutes"] == 42

    # Cache headers (no-store)
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # DB ops + lock used once
    assert db.flush_calls == 1
    assert db.commit_calls == 1
    assert st["lock_keys"] and st["lock_keys"][0].startswith("lock:episode:create:")

    # Audit called with episode_id + season_id
    assert st["audit_calls"], "log_audit_event should be called"
    meta = st["audit_calls"][-1]["meta_data"]
    assert meta.get("season_id") == str(season.id)
    assert "episode_id" in meta


def test_create_episode_404_when_season_missing(monkeypatch):
    # season row missing on first SELECT
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[None])

    r = client.post(f"/api/v1/admin/seasons/{uuid.uuid4()}/episodes", json={"episode_number": 1})
    assert r.status_code == 404
    assert "Season not found" in r.text
    # No commit when 404
    assert db.commit_calls == 0
    assert st["lock_keys"] == []


def test_create_episode_409_on_duplicate_number(monkeypatch):
    season = SeasonStub()
    # season row, duplicate number present
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[season, object()])

    r = client.post(f"/api/v1/admin/seasons/{season.id}/episodes", json={"episode_number": 2})
    assert r.status_code == 409
    assert "Episode number already exists" in r.text
    assert db.commit_calls == 0


def test_create_episode_409_on_duplicate_slug(monkeypatch):
    season = SeasonStub()
    # season row, dup-number None, dup-slug returns a row
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[season, None, object()])

    r = client.post(
        f"/api/v1/admin/seasons/{season.id}/episodes",
        json={"episode_number": 3, "slug": "taken"},
    )
    assert r.status_code == 409
    assert "Episode slug already exists" in r.text
    assert db.commit_calls == 0


def test_create_episode_idempotency_replay_skips_work(monkeypatch):
    season_id = uuid.uuid4()
    snap = {
        "id": str(uuid.uuid4()),
        "season_id": str(season_id),
        "title_id": str(uuid.uuid4()),
        "episode_number": 7,
        "name": "Replay",
        "slug": "replay",
        "overview": None,
        "air_date": None,
        "runtime_minutes": None,
        "created_at": None,
        "updated_at": None,
    }
    app, client, mod, db, st = _mk_app(
        monkeypatch,
        db_results=[object()],  # even if a season row would be there, replay returns early
        redis_snap=snap,
    )

    r = client.post(
        f"/api/v1/admin/seasons/{season_id}/episodes",
        json={"episode_number": 7},
        headers={"Idempotency-Key": "abc123"},
    )
    assert r.status_code == 200
    assert r.json() == snap
    # No commit or lock on replay
    assert db.commit_calls == 0
    assert st["lock_keys"] == []


def test_create_episode_sets_idempotency_snapshot_on_success(monkeypatch):
    season = SeasonStub()
    app, client, mod, db, st = _mk_app(
        monkeypatch,
        db_results=[season, None, None],
        capture_set=True,
    )

    r = client.post(
        f"/api/v1/admin/seasons/{season.id}/episodes",
        json={"episode_number": 8},
        headers={"Idempotency-Key": "idem-1"},
    )
    assert r.status_code == 200
    body = r.json()

    assert st["id_set_calls"], "idempotency_set should be called"
    k, v, ttl = st["id_set_calls"][-1]
    assert k == f"idemp:admin:episode:create:{season.id}:idem-1"
    assert ttl == 600
    assert v == body


def test_create_episode_idempotency_set_failure_is_swallowed(monkeypatch):
    season = SeasonStub()
    app, client, mod, db, st = _mk_app(
        monkeypatch,
        db_results=[season, None, None],
        capture_set=True,
        set_raises=True,
    )

    r = client.post(
        f"/api/v1/admin/seasons/{season.id}/episodes",
        json={"episode_number": 9},
        headers={"Idempotency-Key": "idem-x"},
    )
    assert r.status_code == 200  # success even if snapshot write fails
