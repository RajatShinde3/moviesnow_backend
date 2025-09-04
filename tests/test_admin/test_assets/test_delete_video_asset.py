# tests/test_admin/test_assets/test_delete_video_asset.py

import uuid
from typing import Any, List, Optional, Tuple

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
        self.last_queries: List[Any] = []

    async def execute(self, query, params=None, *_a, **_k):
        self.exec_calls += 1
        self.last_queries.append(query)
        return _Result(self._chunks.pop(0) if self._chunks else [])

    async def flush(self): return None
    async def commit(self): return None


# Minimal row holder with the fields used by the route
class AssetRow:
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        storage_key: Optional[str] = None,
    ):
        self.id = id or uuid.uuid4()
        self.storage_key = storage_key


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

def test_delete_video_happy_path_deletes_row_and_calls_s3(monkeypatch):
    asset_id = uuid.uuid4()
    key = f"video/title/{uuid.uuid4()}/main_{uuid.uuid4().hex}.mp4"
    existing = AssetRow(id=asset_id, storage_key=key)

    # Call order: SELECT -> UPDATE placeholder -> DELETE raw -> (commit) -> S3 delete
    db = FakeDB([[existing], [], []])

    # Capture S3 delete call by overriding _ensure_s3
    called: List[str] = []
    class _S3:
        def delete(self, k): called.append(k)

    app, client, lock_calls = _mk_app(db, monkeypatch)
    monkeypatch.setattr(mod, "_ensure_s3", lambda: _S3(), raising=False)

    r = client.delete(f"/api/v1/admin/video/{asset_id}")
    assert r.status_code == 200, r.text
    assert r.json() == {"message": "Deleted"}

    # Strict no-store headers
    assert r.headers.get("Cache-Control", "").startswith("no-store")
    assert r.headers.get("Pragma") == "no-cache"

    # Lock usage
    assert lock_calls and lock_calls[0][0] == f"lock:admin:video:delete:{asset_id}"

    # S3 was called with the captured storage_key
    assert called == [key]

    # We executed at least 3 DB ops: SELECT + UPDATE + DELETE
    assert db.exec_calls >= 3


def test_delete_video_404_when_missing(monkeypatch):
    asset_id = uuid.uuid4()
    db = FakeDB([[]])  # SELECT returns no rows -> 404

    app, client, lock_calls = _mk_app(db, monkeypatch)
    r = client.delete(f"/api/v1/admin/video/{asset_id}")

    assert r.status_code == 404
    assert "Video asset not found" in r.text
    # No lock acquired because we bail before deletion step
    assert lock_calls == []


def test_delete_video_s3_errors_are_ignored(monkeypatch):
    asset_id = uuid.uuid4()
    existing = AssetRow(id=asset_id, storage_key="s3://bucket/video.mp4")
    db = FakeDB([[existing], [], []])

    # _ensure_s3 raises — route should still return 200 because it's in try/except
    def _boom(): raise RuntimeError("s3 down")
    app, client, _ = _mk_app(db, monkeypatch)
    monkeypatch.setattr(mod, "_ensure_s3", _boom, raising=False)

    r = client.delete(f"/api/v1/admin/video/{asset_id}")
    assert r.status_code == 200
    assert r.json() == {"message": "Deleted"}


def test_delete_video_does_not_call_s3_when_no_storage_key(monkeypatch):
    asset_id = uuid.uuid4()
    existing = AssetRow(id=asset_id, storage_key=None)
    db = FakeDB([[existing], [], []])

    # If S3 is invoked, fail the test
    def _should_not_be_called(): raise AssertionError("_ensure_s3 should not be called when no key")
    app, client, _ = _mk_app(db, monkeypatch)
    monkeypatch.setattr(mod, "_ensure_s3", _should_not_be_called, raising=False)

    r = client.delete(f"/api/v1/admin/video/{asset_id}")
    assert r.status_code == 200
    assert r.json() == {"message": "Deleted"}


def test_delete_video_audit_log_failure_is_swallowed(monkeypatch):
    asset_id = uuid.uuid4()
    existing = AssetRow(id=asset_id, storage_key="s3://bucket/video.mp4")
    db = FakeDB([[existing], [], []])

    async def _boom(*_a, **_k): raise RuntimeError("audit down")
    app, client, _ = _mk_app(db, monkeypatch)
    monkeypatch.setattr(mod, "log_audit_event", _boom, raising=False)

    r = client.delete(f"/api/v1/admin/video/{asset_id}")
    assert r.status_code == 200  # still OK


def test_delete_video_requires_admin(monkeypatch):
    asset_id = uuid.uuid4()
    db = FakeDB([[AssetRow(id=asset_id, storage_key="x")]])  # won't reach due to 403
    app, client, _ = _mk_app(db, monkeypatch, ensure_admin=_raise_403, ensure_mfa=_noop)

    r = client.delete(f"/api/v1/admin/video/{asset_id}")
    assert r.status_code == 403
    assert r.json()["detail"] == "Forbidden"


def test_delete_video_requires_mfa(monkeypatch):
    asset_id = uuid.uuid4()
    db = FakeDB([[AssetRow(id=asset_id, storage_key="x")]])  # won't reach due to 401
    app, client, _ = _mk_app(db, monkeypatch, ensure_admin=_noop, ensure_mfa=_raise_401)

    r = client.delete(f"/api/v1/admin/video/{asset_id}")
    assert r.status_code == 401
    assert r.json()["detail"] == "MFA required"
