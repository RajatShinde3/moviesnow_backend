# tests/test_admin/test_series/test_create_season.py

import importlib
import uuid
from typing import Any, Dict, List, Optional, Tuple

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes / doubles
# ─────────────────────────────────────────────────────────────────────────────

class _ScalarResult:
    def __init__(self, val):
        self._val = val
    def scalar_one_or_none(self):
        return self._val


class FakeDB:
    """
    AsyncSession-ish fake:
    - execute(): returns queued results (for SELECTs)
    - add(): capture created ORM object
    - flush(): no-op
    - commit(): marks commit and assigns an id to added rows if missing
    - refresh(): no-op
    """
    def __init__(self, results: List[Any]):
        self._results = list(results)
        self.queries: List[Any] = []
        self.added: List[Any] = []
        self.commit_calls = 0
        self.flush_calls = 0
        self.refresh_calls = 0

    async def execute(self, query, *_a, **_k):
        self.queries.append(query)
        if self._results:
            return _ScalarResult(self._results.pop(0))
        return _ScalarResult(None)

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        self.flush_calls += 1

    async def commit(self):
        self.commit_calls += 1
        # Give created rows an id if missing
        for obj in self.added:
            if getattr(obj, "id", None) is None:
                setattr(obj, "id", uuid.uuid4())

    async def refresh(self, _obj):
        self.refresh_calls += 1


class FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()


class _AsyncLockCtx:
    def __init__(self, key, capture: List[str]):
        self.key = key
        self.capture = capture
    async def __aenter__(self):
        self.capture.append(self.key)
    async def __aexit__(self, exc_type, exc, tb):
        return False


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    db_results: List[Any],
    ensure_series_title_behavior: str = "ok",  # "ok" | "404" | "400"
    redis_snap: Optional[Dict[str, Any]] = None,
    capture_set: bool = False,
    set_raises: bool = False,
):
    """
    - db_results: queue for FakeDB.execute() to feed SELECT duplicate guards.
    - ensure_series_title_behavior: controls _ensure_series_title outcome.
    - redis_snap: if provided, idempotency_get returns this snapshot (replay).
    - capture_set: capture idempotency_set calls.
    - set_raises: make idempotency_set raise (to test swallow).
    """
    mod = importlib.import_module("app.api.v1.routers.admin.series")

    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Bypass Admin + MFA
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Control _ensure_series_title behavior
    if ensure_series_title_behavior == "404":
        async def _nf(db, title_id): raise HTTPException(status_code=404, detail="Title not found")
        monkeypatch.setattr(mod, "_ensure_series_title", _nf, raising=False)
    elif ensure_series_title_behavior == "400":
        async def _bad(db, title_id): raise HTTPException(status_code=400, detail="Title is not a SERIES")
        monkeypatch.setattr(mod, "_ensure_series_title", _bad, raising=False)
    else:
        async def _pass(db, title_id): return object()
        monkeypatch.setattr(mod, "_ensure_series_title", _pass, raising=False)

    # Redis idempotency plumbing
    get_calls: List[str] = []
    set_calls: List[Tuple[str, Dict[str, Any], int]] = []
    def _mk_key(title_id, hdr):  # not used directly by test; helper to reason about keys
        return f"idemp:admin:season:create:{title_id}:{hdr}"

    async def _id_get(key):
        get_calls.append(key)
        return redis_snap

    async def _id_set(key, val, ttl_seconds=600):
        if set_raises:
            raise RuntimeError("redis down")
        if capture_set:
            set_calls.append((key, val, ttl_seconds))

    monkeypatch.setattr(mod.redis_wrapper, "idempotency_get", _id_get, raising=False)
    monkeypatch.setattr(mod.redis_wrapper, "idempotency_set", _id_set, raising=False)

    # Redis lock
    lock_keys: List[str] = []
    def _lock(key: str, timeout=10, blocking_timeout=3):
        return _AsyncLockCtx(key, lock_keys)
    monkeypatch.setattr(mod.redis_wrapper, "lock", _lock, raising=False)

    # Audit (no-op; route awaits it)
    async def _audit(*_a, **_k): return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Build app
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(db_results)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap SlowAPI decorator (only swap endpoint; don't touch route.app)
    path = "/api/v1/admin/titles/{title_id}/seasons"
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
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_create_season_happy_path_returns_serialized_and_no_store(monkeypatch):
    title_id = uuid.uuid4()
    # Duplicate guards: first None (season_number), then None (slug)
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[None, None])

    r = client.post(
        f"/api/v1/admin/titles/{title_id}/seasons",
        json={"season_number": 2, "name": "S2", "slug": "two", "overview": "desc"},
    )
    assert r.status_code == 200, r.text
    body = r.json()

    # Basic shape
    assert body["id"]
    assert body["title_id"] == str(title_id)  # set by route from constructor
    assert body["season_number"] == 2
    assert body["name"] == "S2"
    assert body["slug"] == "two"
    assert body["overview"] == "desc"

    # cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # DB and lock used
    assert db.flush_calls >= 1
    assert db.commit_calls == 1
    assert st["lock_keys"] and st["lock_keys"][0].startswith("lock:season:create:")


def test_create_season_trims_name_and_slug(monkeypatch):
    title_id = uuid.uuid4()
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[None, None])

    r = client.post(
        f"/api/v1/admin/titles/{title_id}/seasons",
        json={"season_number": 1, "name": "  Pilot  ", "slug": "  s1  "},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "Pilot"
    assert body["slug"] == "s1"


def test_create_season_409_on_duplicate_number(monkeypatch):
    title_id = uuid.uuid4()
    # First SELECT (by season_number) returns a row -> conflict
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[object()])

    r = client.post(
        f"/api/v1/admin/titles/{title_id}/seasons",
        json={"season_number": 1},
    )
    assert r.status_code == 409
    assert "Season number already exists" in r.text
    assert db.commit_calls == 0  # no write
    assert st["lock_keys"] and st["lock_keys"][0].endswith(str(title_id))


def test_create_season_409_on_duplicate_slug(monkeypatch):
    title_id = uuid.uuid4()
    # First SELECT (number) -> None; second SELECT (slug) -> dup row
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[None, object()])

    r = client.post(
        f"/api/v1/admin/titles/{title_id}/seasons",
        json={"season_number": 3, "slug": "s3"},
    )
    assert r.status_code == 409
    assert "Season slug already exists" in r.text
    assert db.commit_calls == 0


def test_create_season_idempotency_replay_skips_work(monkeypatch):
    title_id = uuid.uuid4()
    snap = {
        "id": str(uuid.uuid4()),
        "title_id": str(title_id),
        "season_number": 4,
        "name": "Replay",
        "slug": "replay",
        "overview": None,
        "release_date": None,
        "end_date": None,
        "episode_count": 0,
        "is_published": False,
        "created_at": None,
        "updated_at": None,
    }
    app, client, mod, db, st = _mk_app(
        monkeypatch,
        db_results=[],
        redis_snap=snap,
    )

    r = client.post(
        f"/api/v1/admin/titles/{title_id}/seasons",
        json={"season_number": 4},
        headers={"Idempotency-Key": "abc123"},
    )
    assert r.status_code == 200
    assert r.json() == snap
    # No commit, no lock when replayed
    assert db.commit_calls == 0
    assert st["lock_keys"] == []


def test_create_season_sets_idempotency_snapshot_on_success(monkeypatch):
    title_id = uuid.uuid4()
    app, client, mod, db, st = _mk_app(
        monkeypatch,
        db_results=[None, None],
        capture_set=True,
    )

    r = client.post(
        f"/api/v1/admin/titles/{title_id}/seasons",
        json={"season_number": 5},
        headers={"Idempotency-Key": "idem-key-1"},
    )
    assert r.status_code == 200
    body = r.json()

    # One snapshot written with 10 min TTL
    assert st["id_set_calls"], "idempotency_set should be called"
    k, v, ttl = st["id_set_calls"][-1]
    assert k == f"idemp:admin:season:create:{title_id}:idem-key-1"
    assert ttl == 600
    assert v == body


def test_create_season_idempotency_set_failure_is_swallowed(monkeypatch):
    title_id = uuid.uuid4()
    app, client, mod, db, st = _mk_app(
        monkeypatch,
        db_results=[None, None],
        capture_set=True,
        set_raises=True,
    )

    r = client.post(
        f"/api/v1/admin/titles/{title_id}/seasons",
        json={"season_number": 6},
        headers={"Idempotency-Key": "idem-key-err"},
    )
    assert r.status_code == 200  # still succeeds even if snapshot write fails


def test_create_season_title_not_found_404(monkeypatch):
    title_id = uuid.uuid4()
    app, client, mod, db, st = _mk_app(
        monkeypatch,
        db_results=[],
        ensure_series_title_behavior="404",
    )
    r = client.post(
        f"/api/v1/admin/titles/{title_id}/seasons",
        json={"season_number": 1},
    )
    assert r.status_code == 404
    assert "Title not found" in r.text


def test_create_season_title_wrong_type_400(monkeypatch):
    title_id = uuid.uuid4()
    app, client, mod, db, st = _mk_app(
        monkeypatch,
        db_results=[],
        ensure_series_title_behavior="400",
    )
    r = client.post(
        f"/api/v1/admin/titles/{title_id}/seasons",
        json={"season_number": 1},
    )
    assert r.status_code == 400
    assert "Title is not a SERIES" in r.text
