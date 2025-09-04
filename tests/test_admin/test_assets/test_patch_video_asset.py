# tests/test_admin/test_assets/test_patch_video_asset.py

import uuid
from typing import Any, Dict, List, Optional, Tuple

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

# Import the actual route module (keeps SQLAlchemy-mapped models intact)
from app.api.v1.routers.admin.assets import video as mod


# ─────────────────────────────────────────────────────────────────────────────
# Tiny async-session fake that returns canned rows for .execute()
# ─────────────────────────────────────────────────────────────────────────────

class _Scalars:
    def __init__(self, items: List[Any]): self._items = items
    def all(self): return self._items

class _Result:
    def __init__(self, items: List[Any]): self._items = items
    def scalars(self): return _Scalars(self._items)
    def scalar_one_or_none(self): return self._items[0] if self._items else None

class FakeDB:
    """Provide successive result chunks matching each .execute() call."""
    def __init__(self, chunks: List[List[Any]]):
        self._chunks = list(chunks)
        self.exec_calls: int = 0
        self.added: List[Any] = []

    async def execute(self, query, *_a, **_k):
        self.exec_calls += 1
        return _Result(self._chunks.pop(0) if self._chunks else [])

    async def flush(self): return None

    async def commit(self): return None

    def add(self, obj: Any): self.added.append(obj)


# Simple row holder mirroring fields used in the route
class AssetRow:
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        title_id: Optional[uuid.UUID] = None,
        season_id: Optional[uuid.UUID] = None,
        episode_id: Optional[uuid.UUID] = None,
        language: Optional[str] = None,
        is_primary: bool = False,
        metadata_json: Optional[dict] = None,
        sort_order: int = 0,
        cdn_url: Optional[str] = None,
    ):
        self.id = id or uuid.uuid4()
        self.title_id = title_id
        self.season_id = season_id
        self.episode_id = episode_id
        self.language = language
        self.is_primary = is_primary
        self.metadata_json = metadata_json
        self.sort_order = sort_order
        self.cdn_url = cdn_url


# ─────────────────────────────────────────────────────────────────────────────
# Fake Redis lock
# ─────────────────────────────────────────────────────────────────────────────

class _RecordedLock:
    def __init__(self, key: str, *, timeout: int, blocking_timeout: int, calls: List[Tuple[str, int, int]]):
        self.key = key
        self.timeout = timeout
        self.blocking_timeout = blocking_timeout
        self.calls = calls
    async def __aenter__(self):
        self.calls.append((self.key, self.timeout, self.blocking_timeout))
        return self
    async def __aexit__(self, exc_type, exc, tb):
        return False  # don't suppress


# ─────────────────────────────────────────────────────────────────────────────
# App factory (bypasses rate limit, overrides DB + auth deps + redis lock)
# ─────────────────────────────────────────────────────────────────────────────

async def _noop(*_a, **_k): return None
async def _raise_403(*_a, **_k): raise HTTPException(status_code=403, detail="Forbidden")
async def _raise_401(*_a, **_k): raise HTTPException(status_code=401, detail="MFA required")

class _User: id = uuid.uuid4()

def _mk_app(
    db: FakeDB,
    monkeypatch,
    *,
    ensure_admin=_noop,
    ensure_mfa=_noop,
    lock_calls: Optional[List[Tuple[str, int, int]]] = None,
) -> Tuple[FastAPI, TestClient, List[Tuple[str, int, int]]]:
    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Patch lazy-imported admin/MFA checks
    monkeypatch.setattr("app.dependencies.admin.ensure_admin", ensure_admin, raising=False)
    monkeypatch.setattr("app.dependencies.admin.ensure_mfa", ensure_mfa, raising=False)

    # Patch Redis lock
    if lock_calls is None:
        lock_calls = []
    def _fake_lock(key, *, timeout, blocking_timeout):
        return _RecordedLock(key, timeout=timeout, blocking_timeout=blocking_timeout, calls=lock_calls)
    monkeypatch.setattr(mod.redis_wrapper, "lock", _fake_lock, raising=False)

    app = FastAPI()
    app.include_router(mod.router)  # router already has /api/v1/admin prefix

    # Dependency overrides
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: _User()

    return app, TestClient(app), lock_calls


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_patch_video_happy_updates_label_sort_cdn(monkeypatch):
    asset_id = uuid.uuid4()
    # SELECT ... FOR UPDATE -> existing row, UPDATE -> [], final SELECT -> updated row
    existing = AssetRow(id=asset_id, title_id=uuid.uuid4(), language="en", is_primary=False, metadata_json={})
    updated  = AssetRow(id=asset_id, title_id=existing.title_id, language="en", is_primary=False,
                        metadata_json={"label": "Theatrical"}, sort_order=5, cdn_url="https://cdn/x.mp4")
    db = FakeDB([[existing], [], [updated]])
    app, client, lock_calls = _mk_app(db, monkeypatch)

    r = client.patch(
        f"/api/v1/admin/video/{asset_id}",
        json={"label": "Theatrical", "sort_order": 5, "cdn_url": "https://cdn/x.mp4"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body == {
        "id": str(asset_id),
        "language": "en",
        "is_primary": False,
        "label": "Theatrical",
        "sort_order": 5,
        "cdn_url": "https://cdn/x.mp4",
    }
    # strict no-store headers
    assert r.headers.get("Cache-Control", "").startswith("no-store")
    assert r.headers.get("Pragma") == "no-cache"
    # lock used with expected key/params
    assert lock_calls and lock_calls[0][0] == f"lock:admin:video:{asset_id}"


def test_patch_video_404_when_asset_missing(monkeypatch):
    asset_id = uuid.uuid4()
    db = FakeDB([[]])  # first SELECT returns no rows -> 404
    app, client, lock_calls = _mk_app(db, monkeypatch)

    r = client.patch(f"/api/v1/admin/video/{asset_id}", json={})
    assert r.status_code == 404
    assert "Video asset not found" in r.text
    assert lock_calls and lock_calls[0][0] == f"lock:admin:video:{asset_id}"


def test_patch_video_language_validation_400(monkeypatch):
    asset_id = uuid.uuid4()
    existing = AssetRow(id=asset_id, title_id=uuid.uuid4(), language="en")
    db = FakeDB([[existing]])  # error occurs before any UPDATE/commit
    app, client, _ = _mk_app(db, monkeypatch)

    r = client.patch(f"/api/v1/admin/video/{asset_id}", json={"language": "en_US"})  # invalid BCP-47
    assert r.status_code == 400
    assert "Invalid language" in r.text or "language" in r.text


def test_patch_video_set_primary_true_unsets_others(monkeypatch):
    asset_id = uuid.uuid4()
    t_id = uuid.uuid4()
    existing = AssetRow(id=asset_id, title_id=t_id, language="en", is_primary=False)
    updated  = AssetRow(id=asset_id, title_id=t_id, language="en", is_primary=True)
    # order: SELECT (row for update) -> UPDATE (unset others) -> UPDATE (this row) -> final SELECT (updated)
    db = FakeDB([[existing], [], [], [updated]])
    app, client, _ = _mk_app(db, monkeypatch)

    r = client.patch(f"/api/v1/admin/video/{asset_id}", json={"is_primary": True})
    assert r.status_code == 200
    body = r.json()
    assert body["is_primary"] is True
    # At least 4 .execute() calls: select-for-update, unset-others update, update-self, final select
    assert db.exec_calls >= 4


def test_patch_video_set_primary_false(monkeypatch):
    asset_id = uuid.uuid4()
    existing = AssetRow(id=asset_id, language="en", is_primary=True)
    updated  = AssetRow(id=asset_id, language="en", is_primary=False)
    db = FakeDB([[existing], [], [updated]])  # no "unset others" when setting False
    app, client, _ = _mk_app(db, monkeypatch)

    r = client.patch(f"/api/v1/admin/video/{asset_id}", json={"is_primary": False})
    assert r.status_code == 200
    assert r.json()["is_primary"] is False


def test_patch_video_label_removed_when_empty(monkeypatch):
    asset_id = uuid.uuid4()
    existing = AssetRow(id=asset_id, language="en", metadata_json={"label": "Old"})
    updated  = AssetRow(id=asset_id, language="en", metadata_json={})
    db = FakeDB([[existing], [], [updated]])
    app, client, _ = _mk_app(db, monkeypatch)

    r = client.patch(f"/api/v1/admin/video/{asset_id}", json={"label": ""})
    assert r.status_code == 200
    assert r.json()["label"] is None


def test_patch_video_cdn_empty_string_maps_to_none(monkeypatch):
    asset_id = uuid.uuid4()
    existing = AssetRow(id=asset_id, cdn_url="https://cdn/old.mp4")
    updated  = AssetRow(id=asset_id, cdn_url=None)
    db = FakeDB([[existing], [], [updated]])
    app, client, _ = _mk_app(db, monkeypatch)

    r = client.patch(f"/api/v1/admin/video/{asset_id}", json={"cdn_url": ""})
    assert r.status_code == 200
    assert r.json()["cdn_url"] is None


def test_patch_video_audit_log_failure_is_swallowed(monkeypatch):
    asset_id = uuid.uuid4()
    existing = AssetRow(id=asset_id, language="en")
    updated  = AssetRow(id=asset_id, language="fr")
    db = FakeDB([[existing], [], [updated]])

    async def _boom(*_a, **_k): raise RuntimeError("audit down")
    app, client, _ = _mk_app(db, monkeypatch)
    monkeypatch.setattr(mod, "log_audit_event", _boom, raising=False)

    r = client.patch(f"/api/v1/admin/video/{asset_id}", json={"language": "fr"})
    assert r.status_code == 200  # still succeeds


def test_patch_video_requires_admin(monkeypatch):
    asset_id = uuid.uuid4()
    db = FakeDB([[AssetRow(id=asset_id)]])  # won't reach due to 403
    app, client, _ = _mk_app(db, monkeypatch, ensure_admin=_raise_403, ensure_mfa=_noop)

    r = client.patch(f"/api/v1/admin/video/{asset_id}", json={})
    assert r.status_code == 403
    assert r.json()["detail"] == "Forbidden"


def test_patch_video_requires_mfa(monkeypatch):
    asset_id = uuid.uuid4()
    db = FakeDB([[AssetRow(id=asset_id)]])  # won't reach due to 401
    app, client, _ = _mk_app(db, monkeypatch, ensure_admin=_noop, ensure_mfa=_raise_401)

    r = client.patch(f"/api/v1/admin/video/{asset_id}", json={})
    assert r.status_code == 401
    assert r.json()["detail"] == "MFA required"
