# tests/test_admin/test_titles/test_get_title.py
import importlib
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Tuple, List

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class TitleStub:
    """Minimal stand-in for the ORM Title row used by _serialize_title()."""

    # IMPORTANT: class-level sentinel so `Title.id == ...` in the route works
    id = object()

    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        name: str = "My Film",
        slug: str = "my-film",
        type: str = "MOVIE",
        status: str = "ANNOUNCED",
        release_year: Optional[int] = None,
        overview: Optional[str] = None,
        tagline: Optional[str] = None,
        is_published: bool = False,
    ):
        now = datetime.now(timezone.utc)
        self.id = id or uuid.uuid4()
        self.name = name
        self.slug = slug
        self.type = type
        self.status = status
        self.release_year = release_year
        self.overview = overview
        self.tagline = tagline
        self.is_published = is_published
        self.created_at = now
        self.updated_at = now
        self.deleted_at = None
        # kept for parity / future-proofing
        self.popularity_score = 0.0
        self.rating_average = 0.0


class _FakeResult:
    """Emulates SQLAlchemy result for .scalar_one_or_none()."""
    def __init__(self, row):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


class FakeDB:
    def __init__(self, *, row: Optional[TitleStub]):
        self.row = row
        self.exec_calls: List[Any] = []

    async def execute(self, query):
        self.exec_calls.append(query)
        return _FakeResult(self.row)


class FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()


# ─────────────────────────────────────────────────────────────────────────────
# Tiny query shim so select(Title) etc. don't pull in real SQLA
# ─────────────────────────────────────────────────────────────────────────────

class _Q:
    def __init__(self, model):
        self.model = model
        self.where_args: Tuple[Any, ...] = tuple()

    def where(self, *conds):
        self.where_args = conds
        return self


def _fake_select(model):
    return _Q(model)


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, row: Optional[TitleStub]):
    mod = importlib.import_module("app.api.v1.routers.admin.titles")

    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Patch SQLA select to our no-op query object
    monkeypatch.setattr(mod, "select", _fake_select, raising=False)

    # Patch Title class to our stub (so Title.id exists at class level)
    monkeypatch.setattr(mod, "Title", TitleStub, raising=False)

    # Security stubs record invocations
    calls = {"ensure_admin": 0, "ensure_mfa": 0}

    async def _ensure_admin(user):  # noqa: ARG001
        calls["ensure_admin"] += 1

    async def _ensure_mfa(request):  # noqa: ARG001
        calls["ensure_mfa"] += 1

    monkeypatch.setattr(mod, "_ensure_admin", _ensure_admin, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ensure_mfa, raising=False)

    # Make set_sensitive_cache add headers used by tests
    def _no_store(resp, seconds: int = 0):  # noqa: ARG001
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"

    monkeypatch.setattr(mod, "set_sensitive_cache", _no_store, raising=False)

    # Build app and overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB(row=row)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, calls


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_get_title_happy_path_returns_record_and_no_store(monkeypatch):
    t = TitleStub(name="King", slug="king")
    app, client, mod, db, calls = _mk_app(monkeypatch, row=t)

    resp = client.get(f"/api/v1/admin/titles/{t.id}")
    assert resp.status_code == 200

    data = resp.json()
    assert data["id"] == str(t.id)
    assert data["name"] == "King"
    assert data["slug"] == "king"

    # cache headers from set_sensitive_cache
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1

    # DB was hit once
    assert len(db.exec_calls) == 1


def test_get_title_404_when_missing_still_sets_no_store(monkeypatch):
    app, client, mod, db, calls = _mk_app(monkeypatch, row=None)
    tid = uuid.uuid4()

    resp = client.get(f"/api/v1/admin/titles/{tid}")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Title not found"}

    # headers applied even on errors (we set before raising)
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1

    # DB was queried
    assert len(db.exec_calls) == 1


def test_get_title_calls_security_checks(monkeypatch):
    t = TitleStub()
    app, client, mod, db, calls = _mk_app(monkeypatch, row=t)

    resp = client.get(f"/api/v1/admin/titles/{t.id}")
    assert resp.status_code == 200

    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
