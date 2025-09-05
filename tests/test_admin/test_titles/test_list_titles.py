# tests/test_admin/test_titles/test_list_titles.py

import importlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class _RowsResult:
    def __init__(self, rows):
        self._rows = rows
    class _Scalars:
        def __init__(self, rows): self._rows = rows
        def all(self): return list(self._rows)
    def scalars(self): return self._Scalars(self._rows)

class _CountResult:
    def __init__(self, n: int): self._n = n
    def scalar_one(self): return self._n

class FakeDB:
    """
    Execute order (in route):
      1) count SELECT (best-effort)
      2) rows SELECT (with filters/order/pagination)
    """
    def __init__(self, *, rows: List[Any], total_count: Optional[int] = None, raise_on_count: bool = False):
        self.rows = rows
        self.total_count = total_count
        self.raise_on_count = raise_on_count
        self.exec_calls: List[Any] = []

    async def execute(self, stmt, *a, **k):
        self.exec_calls.append(stmt)
        # first call is the count
        if self.total_count is not None or self.raise_on_count:
            if len(self.exec_calls) == 1:
                if self.raise_on_count:
                    raise RuntimeError("count failed")
                return _CountResult(self.total_count or 0)
        # second call (or first if we didn't simulate count) returns rows
        return _RowsResult(self.rows)


class FakeUser:
    def __init__(self, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


# Minimal Title stub with the fields the serializer/route expect
class TitleStub:
    def __init__(
        self,
        *,
        type: str = "MOVIE",
        status: str = "ANNOUNCED",
        is_published: bool = False,
        name: str,
        slug: str,
        created_at: datetime,
        popularity_score: float = 0.0,
        rating_average: float = 0.0,
        release_year: Optional[int] = None,
        original_name: Optional[str] = None,
        overview: Optional[str] = None,
        tagline: Optional[str] = None,
    ):
        self.id = uuid.uuid4()
        self.type = type
        self.status = status
        self.is_published = is_published
        self.name = name
        self.slug = slug
        self.created_at = created_at
        self.updated_at = created_at
        self.deleted_at = None
        self.popularity_score = popularity_score
        self.rating_average = rating_average
        self.release_year = release_year
        self.original_name = original_name
        self.overview = overview
        self.tagline = tagline


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    rows: List[Any],
    total_count: Optional[int] = None,
    raise_on_count: bool = False,
):
    mod = importlib.import_module("app.api.v1.routers.admin.titles")

    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")


    # Track security checks (module uses _ensure_admin/_ensure_mfa directly)
    calls = {"ensure_admin": 0, "ensure_mfa": 0}
    async def _ensure_admin(user):  # noqa: ARG001
        calls["ensure_admin"] += 1
    async def _ensure_mfa(request):  # noqa: ARG001
        calls["ensure_mfa"] += 1
    monkeypatch.setattr(mod, "_ensure_admin", _ensure_admin, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ensure_mfa, raising=False)

    # Build app & overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB(rows=rows, total_count=total_count, raise_on_count=raise_on_count)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, calls


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _t(name: str, slug: str, *, created_at: datetime, **kw) -> TitleStub:
    return TitleStub(name=name, slug=slug, created_at=created_at, **kw)


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_list_titles_happy_path_default_sort_and_no_store(monkeypatch):
    now = datetime.now(timezone.utc)
    # default sort = "-created_at" (desc) → we pass pre-sorted rows to simulate DB order
    rows = [
        _t("Newest", "newest", created_at=now, release_year=2025, rating_average=7.5, popularity_score=98.0),
        _t("Middle", "middle", created_at=now - timedelta(days=1), release_year=2024, rating_average=7.0, popularity_score=50.0),
        _t("Oldest", "oldest", created_at=now - timedelta(days=2), release_year=2020, rating_average=6.0, popularity_score=30.0),
    ]
    app, client, mod, db, calls = _mk_app(monkeypatch, rows=rows, total_count=3)

    resp = client.get("/api/v1/admin/titles")

    assert resp.status_code == 200
    data = resp.json()
    assert [d["slug"] for d in data] == ["newest", "middle", "oldest"]

    # Total count header present and correct
    assert resp.headers.get("X-Total-Count") == "3"

    # Cache headers (route sets them on Response; tests expect them on final response)
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Security checks called
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_list_titles_filters_simulated_subset_and_count(monkeypatch):
    now = datetime.now(timezone.utc)
    # Simulate filtered DB results (e.g., type=MOVIE, status=RELEASED, is_published=true, q="king")
    rows = [
        _t("The King", "the-king", created_at=now - timedelta(hours=1), type="MOVIE", status="RELEASED", is_published=True, release_year=2021),
        _t("Kingmaker", "kingmaker", created_at=now - timedelta(hours=2), type="MOVIE", status="RELEASED", is_published=True, release_year=2020),
    ]
    app, client, mod, db, calls = _mk_app(monkeypatch, rows=rows, total_count=2)

    resp = client.get("/api/v1/admin/titles", params={"type": "MOVIE", "status": "RELEASED", "is_published": "true", "q": "king"})
    assert resp.status_code == 200
    data = resp.json()
    assert [d["slug"] for d in data] == ["the-king", "kingmaker"]
    assert resp.headers.get("X-Total-Count") == "2"

    # Security checks called
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_list_titles_sort_release_year_asc(monkeypatch):
    now = datetime.now(timezone.utc)
    rows = [
        _t("Older", "older", created_at=now - timedelta(days=2), release_year=2000),
        _t("Newer", "newer", created_at=now - timedelta(days=1), release_year=2010),
        _t("Newest", "newest", created_at=now, release_year=2020),
    ]
    app, client, mod, db, calls = _mk_app(monkeypatch, rows=rows, total_count=3)

    resp = client.get("/api/v1/admin/titles", params={"sort": "release_year"})
    assert resp.status_code == 200
    assert [d["slug"] for d in resp.json()] == ["older", "newer", "newest"]


def test_list_titles_sort_rating_desc(monkeypatch):
    now = datetime.now(timezone.utc)
    rows = [
        _t("A", "a", created_at=now - timedelta(days=1), rating_average=8.3),
        _t("B", "b", created_at=now - timedelta(days=2), rating_average=7.1),
        _t("C", "c", created_at=now, rating_average=6.4),
    ]
    app, client, mod, db, calls = _mk_app(monkeypatch, rows=rows, total_count=3)

    resp = client.get("/api/v1/admin/titles", params={"sort": "-rating"})
    assert resp.status_code == 200
    assert [d["slug"] for d in resp.json()] == ["a", "b", "c"]    # NOTE: We pass pre-sorted rows to simulate DB; accept either sequence
    # depending on how the test rows above were arranged.


def test_list_titles_pagination_limit_and_offset(monkeypatch):
    now = datetime.now(timezone.utc)
    # Simulate DB already applying offset=1, limit=2
    rows = [
        _t("T2", "t2", created_at=now - timedelta(minutes=2)),
        _t("T3", "t3", created_at=now - timedelta(minutes=3)),
    ]
    app, client, mod, db, calls = _mk_app(monkeypatch, rows=rows, total_count=5)

    resp = client.get("/api/v1/admin/titles", params={"limit": 2, "offset": 1})
    assert resp.status_code == 200
    assert [d["slug"] for d in resp.json()] == ["t2", "t3"]
    assert resp.headers.get("X-Total-Count") == "5"


def test_list_titles_total_count_failure_is_non_fatal(monkeypatch):
    now = datetime.now(timezone.utc)
    rows = [
        _t("A", "a", created_at=now),
        _t("B", "b", created_at=now - timedelta(minutes=1)),
    ]
    app, client, mod, db, calls = _mk_app(monkeypatch, rows=rows, total_count=None, raise_on_count=True)

    resp = client.get("/api/v1/admin/titles")
    assert resp.status_code == 200
    assert [d["slug"] for d in resp.json()] == ["a", "b"]
    # When count fails, header is omitted
    assert resp.headers.get("X-Total-Count") in (None, "")


def test_list_titles_calls_security_checks(monkeypatch):
    now = datetime.now(timezone.utc)
    rows = [_t("One", "one", created_at=now)]
    app, client, mod, db, calls = _mk_app(monkeypatch, rows=rows, total_count=1)

    resp = client.get("/api/v1/admin/titles")
    assert resp.status_code == 200
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
