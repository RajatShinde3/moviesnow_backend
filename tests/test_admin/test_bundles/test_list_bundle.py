# tests/test_admin/test_bundles/test_list_bundles.py

import importlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes / doubles
# ─────────────────────────────────────────────────────────────────────────────

class _ScalarResult:
    def __init__(self, val_or_list):
        self._val_or_list = val_or_list

    def scalar_one_or_none(self):
        # For single-row selects (e.g., Title lookup)
        if isinstance(self._val_or_list, (list, tuple)):
            return self._val_or_list[0] if self._val_or_list else None
        return self._val_or_list

    def scalars(self):
        class _Scalars:
            def __init__(self, val_or_list):
                self._val_or_list = val_or_list
            def all(self):
                if isinstance(self._val_or_list, (list, tuple)):
                    return list(self._val_or_list)
                return []
        return _Scalars(self._val_or_list)


class FakeDB:
    """AsyncSession-ish fake with queueable execute() results."""
    def __init__(self, results: List[Any]):
        self._results = list(results)
        self.queries: List[Any] = []

    async def execute(self, query, *_a, **_k):
        self.queries.append(query)
        if self._results:
            return _ScalarResult(self._results.pop(0))
        return _ScalarResult(None)


class FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()


class BundleRow:
    """Mimic ORM row fields the route projects."""
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        title_id: Optional[uuid.UUID] = None,
        season_number: Optional[int] = None,
        storage_key: str = "bundles/k.zip",
        size_bytes: Optional[int] = None,
        sha256: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        label: Optional[str] = None,
        created_by_id: Optional[uuid.UUID] = None,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
    ):
        self.id = id or uuid.uuid4()
        self.title_id = title_id or uuid.uuid4()
        self.season_number = season_number
        self.storage_key = storage_key
        self.size_bytes = size_bytes
        self.sha256 = sha256
        self.expires_at = expires_at
        self.label = label
        self.created_by_id = created_by_id
        self.created_at = created_at
        self.updated_at = updated_at


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    db_results: List[Any],
    ensure_title_404: bool = False,
):
    mod = importlib.import_module("app.api.v1.routers.admin.bundles")

    # Disable rate limiting in test env
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Fix "now" so expiry comparisons are deterministic
    fixed_now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "_now_utc", lambda: fixed_now, raising=False)

    # Bypass ADMIN + MFA checks
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Control _ensure_title behavior
    if ensure_title_404:
        async def _not_found(db, title_id):
            raise HTTPException(status_code=404, detail="Title not found")
        monkeypatch.setattr(mod, "_ensure_title", _not_found, raising=False)
    else:
        async def _ensure_title_passthru(db, title_id):
            row = (await db.execute(object())).scalar_one_or_none()
            if not row:
                raise HTTPException(status_code=404, detail="Title not found")
            return row
        monkeypatch.setattr(mod, "_ensure_title", _ensure_title_passthru, raising=False)

    # Build app + dependency overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(db_results)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap SlowAPI decorator to avoid 429s (only swap the endpoint; don't touch route.app)
    path = "/api/v1/admin/titles/{title_id}/bundles"
    for route in app.routes:
        if getattr(route, "path", None) == path and "GET" in getattr(route, "methods", set()):
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn
            break

    client = TestClient(app)
    return app, client, mod, db, {"fixed_now": fixed_now}



# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_list_bundles_hides_expired_by_default_and_sets_no_store(monkeypatch):
    title_id = uuid.uuid4()

    now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    active = BundleRow(
        title_id=title_id,
        season_number=1,
        storage_key=f"bundles/{title_id}/S01.zip",
        size_bytes=123,
        sha256="abc",
        expires_at=now + timedelta(days=1),
        label="Season 1",
        created_by_id=uuid.uuid4(),
        created_at=now - timedelta(days=2),
        updated_at=now - timedelta(days=1),
    )
    expired = BundleRow(
        title_id=title_id,
        season_number=2,
        storage_key=f"bundles/{title_id}/S02.zip",
        expires_at=now - timedelta(seconds=1),  # expired
        label="Season 2",
    )

    # DB results order: [Title row], [Bundle rows list]
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[object(), [active, expired]])

    r = client.get(f"/api/v1/admin/titles/{title_id}/bundles")
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data, list) and len(data) == 1
    item = data[0]
    assert item["storage_key"] == active.storage_key
    assert item["season_number"] == 1
    assert item["expires_at"] == active.expires_at.isoformat()
    assert item["size_bytes"] == 123
    assert item["sha256"] == "abc"
    assert item["label"] == "Season 1"
    assert item["id"] == str(active.id)
    assert item["title_id"] == str(title_id)
    assert item["created_by_id"] == str(active.created_by_id)
    assert item["created_at"] == active.created_at.isoformat()
    assert item["updated_at"] == active.updated_at.isoformat()

    # Cache headers (seconds=0 path in set_sensitive_cache)
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"


def test_list_bundles_include_expired_true_returns_all(monkeypatch):
    title_id = uuid.uuid4()
    now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    rows = [
        BundleRow(title_id=title_id, storage_key=f"bundles/{title_id}/A.zip", expires_at=now + timedelta(days=3)),
        BundleRow(title_id=title_id, storage_key=f"bundles/{title_id}/B.zip", expires_at=now - timedelta(days=1)),
        BundleRow(title_id=title_id, storage_key=f"bundles/{title_id}/C.zip", expires_at=None),  # never expires
    ]
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[object(), rows])

    r = client.get(f"/api/v1/admin/titles/{title_id}/bundles?include_expired=true")
    assert r.status_code == 200, r.text
    data = r.json()
    assert len(data) == 3
    keys = {d["storage_key"] for d in data}
    assert keys == {f"bundles/{title_id}/A.zip", f"bundles/{title_id}/B.zip", f"bundles/{title_id}/C.zip"}


def test_list_bundles_404_when_title_not_found(monkeypatch):
    title_id = uuid.uuid4()
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[], ensure_title_404=True)

    r = client.get(f"/api/v1/admin/titles/{title_id}/bundles")
    assert r.status_code == 404
    assert "Title not found" in r.text


def test_list_bundles_returns_empty_list_when_no_rows(monkeypatch):
    title_id = uuid.uuid4()
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[object(), []])

    r = client.get(f"/api/v1/admin/titles/{title_id}/bundles")
    assert r.status_code == 200
    assert r.json() == []


def test_list_bundles_all_expired_hidden_by_default(monkeypatch):
    title_id = uuid.uuid4()
    now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    rows = [
        BundleRow(title_id=title_id, expires_at=now - timedelta(seconds=1)),
        BundleRow(title_id=title_id, expires_at=now - timedelta(days=10)),
    ]
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[object(), rows])

    r = client.get(f"/api/v1/admin/titles/{title_id}/bundles")
    assert r.status_code == 200
    assert r.json() == []
