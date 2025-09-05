# tests/test_admin/test_titles/test_create_title.py

import importlib
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, Optional, Tuple, List

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class FakeDB:
    def __init__(self, *, refresh_raises: bool = False):
        self.add_calls = 0
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0
        self.refresh_calls = 0
        self.refresh_raises = refresh_raises
        self.added: List[Any] = []

    def add(self, obj: Any):
        self.add_calls += 1
        self.added.append(obj)

    async def flush(self):
        self.flush_calls += 1

    async def commit(self):
        self.commit_calls += 1

    async def rollback(self):
        self.rollback_calls += 1

    async def refresh(self, obj: Any):
        self.refresh_calls += 1
        if self.refresh_raises:
            raise RuntimeError("boom")


class FakeUser:
    def __init__(self, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


class FakeRedisIdem:
    def __init__(self, *, preset: Optional[Dict[str, Any]] = None, set_raises: bool = False):
        self.snapshots: Dict[str, Dict[str, Any]] = {}
        self.get_calls: List[str] = []
        self.set_calls: List[Tuple[str, Dict[str, Any], int]] = []
        self.set_raises = set_raises
        self.preset = preset

    async def idempotency_get(self, key: str):
        self.get_calls.append(key)
        if self.preset is not None:
            return self.preset
        return self.snapshots.get(key)

    async def idempotency_set(self, key: str, value: Dict[str, Any], ttl_seconds: int):
        self.set_calls.append((key, value, ttl_seconds))
        if self.set_raises:
            raise RuntimeError("redis set failure")
        self.snapshots[key] = value


# Minimal Title stub so we don’t pull in the ORM
class TitleStub:
    def __init__(self, *, type, name, slug, original_name=None, status=None, release_year=None, overview=None, tagline=None):  # noqa: D401, E501
        self.id = uuid.uuid4()
        self.type = type
        self.name = name
        self.slug = slug
        self.original_name = original_name
        self.status = status
        self.release_year = release_year
        self.overview = overview
        self.tagline = tagline
        self.is_published = False
        now = datetime.now(timezone.utc)
        self.created_at = now
        self.updated_at = now
        self.deleted_at = None


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    slug_exists: bool = False,
    idem_snapshot: Optional[Dict[str, Any]] = None,
    idem_set_raises: bool = False,
    audit_raises: bool = False,
    refresh_raises: bool = False,
):
    mod = importlib.import_module("app.api.v1.routers.admin.titles")

    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Patch Title model with simple stub
    monkeypatch.setattr(mod, "Title", TitleStub, raising=False)

    # Patch slug existence helper
    async def _fake_slug_exists(db, slug: str, *, exclude_id=None):
        return bool(slug_exists)
    monkeypatch.setattr(mod, "_slug_exists", _fake_slug_exists, raising=False)

    # Security stubs (module imported them as _ensure_*)
    calls = {"ensure_admin": 0, "ensure_mfa": 0}
    async def _ensure_admin(user):  # noqa: ARG001
        calls["ensure_admin"] += 1
    async def _ensure_mfa(request):  # noqa: ARG001
        calls["ensure_mfa"] += 1
    monkeypatch.setattr(mod, "_ensure_admin", _ensure_admin, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ensure_mfa, raising=False)

    # Audit logger
    audit_calls: List[Tuple[str, Dict[str, Any]]] = []
    async def _audit(db, user, action, status, request, meta_data):  # noqa: ARG001
        audit_calls.append((action, meta_data))
        if audit_raises:
            raise RuntimeError("audit down")
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Redis idempotency wrapper
    r = FakeRedisIdem(preset=idem_snapshot, set_raises=idem_set_raises)
    monkeypatch.setattr(mod, "redis_wrapper", r, raising=False)

    # Build FastAPI app & overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB(refresh_raises=refresh_raises)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, r, audit_calls, calls


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _payload(
    *,
    type_: str = "MOVIE",
    name: str = "My Film",
    slug: str = "my-film",
    original_name: Optional[str] = None,
    status_: Optional[str] = None,
    release_year: Optional[int] = None,
    overview: Optional[str] = None,
    tagline: Optional[str] = None,
) -> Dict[str, Any]:
    body = {"type": type_, "name": name, "slug": slug}
    if original_name is not None: body["original_name"] = original_name
    if status_ is not None: body["status"] = status_
    if release_year is not None: body["release_year"] = release_year
    if overview is not None: body["overview"] = overview
    if tagline is not None: body["tagline"] = tagline
    return body


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_create_title_happy_path_with_idempotency_set_and_no_store(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch)

    resp = client.post(
        "/api/v1/admin/titles",
        json=_payload(),
        headers={"Idempotency-Key": "abc123"},
    )
    assert resp.status_code == 200
    data = resp.json()
    # Minimal shape
    assert data["id"]
    assert data["name"] == "My Film"
    assert data["slug"] == "my-film"

    # DB lifecycle
    assert db.add_calls == 1
    assert db.flush_calls >= 1
    assert db.commit_calls >= 1
    assert db.rollback_calls == 0

    # Idempotency: get called, then set snapshot
    assert r.get_calls and r.get_calls[-1].endswith("abc123")
    assert r.set_calls and r.set_calls[-1][0].endswith("abc123")

    # Cache headers from set_sensitive_cache
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Audit captured
    assert audit_calls and audit_calls[-1][0] == "TITLES_CREATE"

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_create_title_idempotency_replay_uses_snapshot_and_skips_db(monkeypatch):
    snapshot = {"id": "snap-1", "name": "Snap", "slug": "snap"}
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, idem_snapshot=snapshot)

    resp = client.post(
        "/api/v1/admin/titles",
        json=_payload(),
        headers={"Idempotency-Key": "replay-key"},
    )
    assert resp.status_code == 200
    assert resp.json() == snapshot

    # No DB write when snapshot replayed
    assert db.add_calls == 0
    assert db.commit_calls == 0

    # No idempotency_set after replay
    assert r.set_calls == []

    # Security + cache still applied
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_create_title_conflict_when_slug_exists(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, slug_exists=True)

    resp = client.post("/api/v1/admin/titles", json=_payload())
    assert resp.status_code == 409
    assert resp.json() == {"detail": "Slug already exists"}

    # No DB write
    assert db.add_calls == 0
    assert db.commit_calls == 0
    # No audit, no idempotency set
    assert audit_calls == []
    assert r.set_calls == []

    # Security + cache applied (after validation, before conflict)
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_create_title_validation_422_before_security(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch)

    # Missing slug -> 422
    bad = _payload()
    del bad["slug"]

    resp = client.post("/api/v1/admin/titles", json=bad)
    assert resp.status_code == 422

    # Security not called (validation happens first)
    assert calls["ensure_admin"] == 0
    assert calls["ensure_mfa"] == 0

    # No DB, no idempotency
    assert db.add_calls == 0
    assert r.get_calls == []


def test_create_title_audit_error_is_swallowed(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, audit_raises=True)

    resp = client.post("/api/v1/admin/titles", json=_payload(), headers={"Idempotency-Key": "k"})
    assert resp.status_code == 200

    # DB committed
    assert db.commit_calls >= 1
    # Even if audit raised, request succeeded
    assert resp.json()["slug"] == "my-film"


def test_create_title_idempotency_set_error_is_swallowed(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, idem_set_raises=True)

    resp = client.post("/api/v1/admin/titles", json=_payload(), headers={"Idempotency-Key": "k2"})
    assert resp.status_code == 200

    # We attempted to set snapshot but error didn't break response
    assert r.set_calls and r.set_calls[-1][0].endswith("k2")


def test_create_title_refresh_error_is_swallowed(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, refresh_raises=True)

    resp = client.post("/api/v1/admin/titles", json=_payload())
    assert resp.status_code == 200
    assert db.refresh_calls >= 1
