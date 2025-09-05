# tests/test_admin/test_titles/test_patch_title.py

import importlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class TitleRow:
    """Lightweight mutable row that looks like a Title ORM instance at use-sites."""
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        name: str = "Old Name",
        slug: str = "old-slug",
        original_name: Optional[str] = None,
        status: Optional[str] = None,
        release_year: Optional[int] = None,
        overview: Optional[str] = None,
        tagline: Optional[str] = None,
        is_published: bool = False,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
    ):
        now = datetime.now(timezone.utc)
        self.id = id or uuid.uuid4()
        self.name = name
        self.slug = slug
        self.original_name = original_name
        self.status = status
        self.release_year = release_year
        self.overview = overview
        self.tagline = tagline
        self.is_published = is_published
        self.created_at = created_at or now
        self.updated_at = updated_at or now
        self.deleted_at = None


class FakeResult:
    def __init__(self, row: Optional[Any]):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


class FakeDB:
    """AsyncSession-shaped fake that counts flush/commit/rollback and returns a preset row."""
    def __init__(self, row: Optional[Any]):
        self._row = row
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0
        self.exec_calls: List[Any] = []

    async def execute(self, stmt):
        self.exec_calls.append(stmt)
        return FakeResult(self._row)

    async def flush(self):
        self.flush_calls += 1

    async def commit(self):
        self.commit_calls += 1

    async def rollback(self):
        self.rollback_calls += 1


class FakeUser:
    def __init__(self, user_id: Optional[uuid.UUID] = None):
        self.id = user_id or uuid.uuid4()


class FakeRedisLocks:
    """Captures lock usage; returns a simple async CM."""
    def __init__(self):
        self.lock_calls: List[Tuple[str, int, int]] = []

    def lock(self, key: str, *, timeout: int, blocking_timeout: int):
        self.lock_calls.append((key, timeout, blocking_timeout))

        class _CM:
            async def __aenter__(self_inner):  # noqa: ANN001
                return None

            async def __aexit__(self_inner, exc_type, exc, tb):  # noqa: ANN001
                return False

        return _CM()


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    row: Optional[TitleRow],
    slug_exists: bool = False,
    audit_raises: bool = False,
):
    """
    Build a FastAPI test app with router, dependency overrides, and monkeypatched collaborators.
    """
    mod = importlib.import_module("app.api.v1.routers.admin.titles")

    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Security stubs (the router imports ensure_* as _ensure_*)
    calls = {"ensure_admin": 0, "ensure_mfa": 0}

    async def _ensure_admin(user):  # noqa: ARG001
        calls["ensure_admin"] += 1

    async def _ensure_mfa(request):  # noqa: ARG001
        calls["ensure_mfa"] += 1

    monkeypatch.setattr(mod, "_ensure_admin", _ensure_admin, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ensure_mfa, raising=False)

    # _slug_exists: capture args, allow toggling conflict
    slug_calls: List[Tuple[str, Optional[uuid.UUID]]] = []

    async def _slug_exists(db, slug: str, *, exclude_id: Optional[uuid.UUID] = None):  # noqa: ARG001
        slug_calls.append((slug, exclude_id))
        return bool(slug_exists)

    monkeypatch.setattr(mod, "_slug_exists", _slug_exists, raising=False)

    # Audit logger: record or raise
    audit_calls: List[Tuple[str, Dict[str, Any]]] = []

    async def _audit(db, user, action, status, request, meta_data):  # noqa: ARG001
        audit_calls.append((action, meta_data))
        if audit_raises:
            raise RuntimeError("audit down")

    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Redis lock wrapper
    locks = FakeRedisLocks()
    monkeypatch.setattr(mod, "redis_wrapper", locks, raising=False)

    # Serialize stub: avoid datetime JSON issues in tests by ensuring strings
    def _serialize_stub(t: TitleRow):
        return {
            "id": str(t.id),
            "name": t.name,
            "slug": t.slug,
            "original_name": t.original_name,
            "status": t.status,
            "release_year": t.release_year,
            "overview": t.overview,
            "tagline": t.tagline,
            "is_published": t.is_published,
            "created_at": t.created_at.isoformat() if getattr(t, "created_at", None) else None,
            "updated_at": t.updated_at.isoformat() if getattr(t, "updated_at", None) else None,
        }

    monkeypatch.setattr(mod, "_serialize_title", _serialize_stub, raising=False)

    # Build app + overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB(row=row)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, user, calls, locks, audit_calls, slug_calls


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _payload(**kw) -> Dict[str, Any]:
    """Only include fields set by the test to mimic PATCH semantics."""
    return dict(kw)


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_patch_title_happy_path_updates_and_no_store(monkeypatch):
    row = TitleRow(name="Old", slug="old")
    app, client, mod, db, user, calls, locks, audit_calls, slug_calls = _mk_app(monkeypatch, row=row)

    body = _payload(name="New Name", tagline="Updated")
    resp = client.patch(f"/api/v1/admin/titles/{row.id}", json=body)

    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "New Name"
    assert data["tagline"] == "Updated"
    assert data["slug"] == "old"  # unchanged

    # DB lifecycle
    assert db.flush_calls >= 1
    assert db.commit_calls >= 1
    assert db.rollback_calls == 0

    # Redis lock used with key including id
    assert locks.lock_calls and str(row.id) in locks.lock_calls[-1][0]

    # Audit captured
    assert audit_calls and audit_calls[-1][0] == "TITLES_PATCH"

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1

    # Cache headers (no-store) present on success
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_patch_title_slug_conflict_409_with_no_store(monkeypatch):
    row = TitleRow()
    app, client, mod, db, user, calls, locks, audit_calls, slug_calls = _mk_app(
        monkeypatch, row=row, slug_exists=True
    )

    resp = client.patch(f"/api/v1/admin/titles/{row.id}", json=_payload(slug="taken"))
    assert resp.status_code == 409
    assert resp.json() == {"detail": "Slug already exists"}

    # No DB write/commit when conflict
    assert db.flush_calls == 0
    assert db.commit_calls == 0

    # No lock when conflict (guard triggers before lock)
    assert locks.lock_calls == []

    # Security checks still invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1

    # Id uniqueness helper called with exclude_id
    assert slug_calls and slug_calls[-1][0] == "taken" and slug_calls[-1][1] == row.id

    # Cache headers present on 409 (handler sets them)
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_patch_title_404_when_missing_sets_no_store_and_uses_lock(monkeypatch):
    # simulate not found (row=None)
    app, client, mod, db, user, calls, locks, audit_calls, slug_calls = _mk_app(monkeypatch, row=None)

    tid = uuid.uuid4()
    resp = client.patch(f"/api/v1/admin/titles/{tid}", json=_payload(name="X"))
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Title not found"}

    # Lock attempted even when not found
    assert locks.lock_calls and str(tid) in locks.lock_calls[-1][0]

    # No commit
    assert db.commit_calls == 0

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1

    # 404 should still be no-store for sensitive admin routes
    # (If this fails, add headers to the HTTPException in the route.)
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_patch_title_no_changes_400_and_no_lock(monkeypatch):
    row = TitleRow()
    app, client, mod, db, user, calls, locks, audit_calls, slug_calls = _mk_app(monkeypatch, row=row)

    # Empty body → "No changes provided"
    resp = client.patch(f"/api/v1/admin/titles/{row.id}", json={})
    assert resp.status_code == 400
    assert resp.json() == {"detail": "No changes provided"}

    # No DB write, no lock
    assert db.flush_calls == 0
    assert db.commit_calls == 0
    assert locks.lock_calls == []

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1

    # Admin endpoints should be no-store even on 400
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_patch_title_audit_error_is_swallowed(monkeypatch):
    row = TitleRow(name="Old", slug="old")
    app, client, mod, db, user, calls, locks, audit_calls, slug_calls = _mk_app(
        monkeypatch, row=row, audit_raises=True
    )

    resp = client.patch(f"/api/v1/admin/titles/{row.id}", json=_payload(name="After"))
    assert resp.status_code == 200
    assert resp.json()["name"] == "After"
    # DB still committed despite audit failure
    assert db.commit_calls >= 1
