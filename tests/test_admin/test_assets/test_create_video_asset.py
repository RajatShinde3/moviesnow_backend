# tests/test_admin/test_assets/test_create_video_asset.py

import uuid
from typing import Any, Dict, List, Optional, Tuple, Callable

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

# Import the actual route module (it contains the mapped ORM models)
from app.api.v1.routers.admin.assets import video as mod


# ─────────────────────────────────────────────────────────────────────────────
# Minimal DB fakes
# ─────────────────────────────────────────────────────────────────────────────

class _Scalars:
    def __init__(self, items: List[Any]): self._items = items
    def all(self): return self._items

class _Result:
    def __init__(self, items: List[Any]): self._items = items
    def scalars(self): return _Scalars(self._items)
    def scalar_one_or_none(self): return self._items[0] if self._items else None

class FakeDB:
    """
    Tiny async session stub. Provide a list of 'chunks' matching successive
    .execute() calls. Each chunk is a list of rows for that query.
    """
    def __init__(self, chunks: List[List[Any]]):
        self._chunks = list(chunks)
        self.added: List[Any] = []
        self.exec_calls: int = 0

    async def execute(self, _query, *_a, **_k):
        self.exec_calls += 1
        items = self._chunks.pop(0) if self._chunks else []
        return _Result(items)

    async def flush(self):
        # Emulate DB primary key assignment so response has asset_id
        for obj in self.added:
            if getattr(obj, "id", None) is None:
                setattr(obj, "id", uuid.uuid4())
        return None

    async def commit(self): return None

    def add(self, obj: Any): self.added.append(obj)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers / Fakes
# ─────────────────────────────────────────────────────────────────────────────

async def _noop(*_a, **_k): return None
async def _raise_403(*_a, **_k): raise HTTPException(status_code=403, detail="Forbidden")
async def _raise_401(*_a, **_k): raise HTTPException(status_code=401, detail="MFA required")

class _User: id = uuid.uuid4()

class FakeS3:
    def __init__(self, on_put: Optional[Callable]=None): self.on_put = on_put
    def presigned_put(self, key, *, content_type, public):
        if self.on_put: self.on_put(key, content_type, public)
        return f"https://s3.test/{key}?sig=abc"

class FakeRedis:
    def __init__(self): self.store = {}
    async def idempotency_get(self, key): return self.store.get(key)
    async def idempotency_set(self, key, body, ttl_seconds=600): self.store[key] = body


def _mk_app(
    db: FakeDB,
    monkeypatch,
    *,
    ensure_admin=_noop,
    ensure_mfa=_noop,
    s3: Optional[FakeS3]=None,
    redis: Optional[FakeRedis]=None
) -> Tuple[FastAPI, TestClient, FakeRedis]:

    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Patch AuthZ/MFA (lazy-imported inside handler)
    monkeypatch.setattr("app.dependencies.admin.ensure_admin", ensure_admin, raising=False)
    monkeypatch.setattr("app.dependencies.admin.ensure_mfa", ensure_mfa, raising=False)

    # Patch Redis idempotency wrapper
    if redis is None:
        redis = FakeRedis()
    monkeypatch.setattr(mod.redis_wrapper, "idempotency_get", redis.idempotency_get, raising=False)
    monkeypatch.setattr(mod.redis_wrapper, "idempotency_set", redis.idempotency_set, raising=False)

    # Patch S3 client only if an explicit fake is provided.
    # (This allows tests to monkeypatch mod.S3Client themselves.)
    if s3 is not None:
        monkeypatch.setattr(mod, "S3Client", lambda: s3, raising=False)

    app = FastAPI()
    app.include_router(mod.router)  # router already has /api/v1/admin prefix

    # Dependency overrides
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: _User()

    return app, TestClient(app), redis


# ─────────────────────────────────────────────────────────────────────────────
# Happy path
# ─────────────────────────────────────────────────────────────────────────────

def test_create_video_happy_path_returns_presigned_url_and_no_store_headers(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[object()]])  # Title exists
    s3 = FakeS3()
    app, client, _ = _mk_app(db, monkeypatch, s3=s3)

    payload = {"content_type": "video/mp4", "language": "en", "is_primary": False, "label": "Theatrical"}
    r = client.post(f"/api/v1/admin/titles/{title_id}/video", json=payload)

    assert r.status_code == 200, r.text
    data = r.json()
    assert set(data.keys()) == {"upload_url", "storage_key", "asset_id"}
    assert data["upload_url"].startswith("https://s3.test/")
    assert f"/title/{title_id}/" in data["storage_key"]

    # strict no-store headers
    assert r.headers.get("Cache-Control", "").startswith("no-store")
    assert r.headers.get("Pragma") == "no-cache"


# ─────────────────────────────────────────────────────────────────────────────
# Input validation
# ─────────────────────────────────────────────────────────────────────────────

def test_create_video_404_title_not_found(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[]])  # Title lookup returns None
    app, client, _ = _mk_app(db, monkeypatch)

    r = client.post(f"/api/v1/admin/titles/{title_id}/video", json={"content_type": "video/mp4"})
    assert r.status_code == 404
    assert "Title not found" in r.text

def test_create_video_415_unsupported_mime(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[object()]])
    app, client, _ = _mk_app(db, monkeypatch)

    r = client.post(f"/api/v1/admin/titles/{title_id}/video", json={"content_type": "video/avi"})
    assert r.status_code == 415
    assert "Unsupported video content-type" in r.text

def test_create_video_400_invalid_language(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[object()]])
    app, client, _ = _mk_app(db, monkeypatch)

    r = client.post(
        f"/api/v1/admin/titles/{title_id}/video",
        json={"content_type": "video/mp4", "language": "en_US"},  # underscore is invalid BCP-47
    )
    assert r.status_code == 400
    assert "Invalid language tag" in r.text


# ─────────────────────────────────────────────────────────────────────────────
# Idempotency
# ─────────────────────────────────────────────────────────────────────────────

def test_create_video_idempotency_replays_snapshot_and_skips_work(monkeypatch):
    title_id = uuid.uuid4()
    snap = {"upload_url": "https://cached/url", "storage_key": "cached/key", "asset_id": "cached-id"}

    class _Redis(FakeRedis):
        async def idempotency_get(self, key): return snap  # always hit cache

    db = FakeDB([[object()]])

    # Make S3 constructor blow up if called (shouldn't be, due to replay)
    class _BoomS3:
        def __init__(self): raise AssertionError("S3 should not be constructed on idempotent replay")

    monkeypatch.setattr(mod, "S3Client", _BoomS3, raising=False)

    app, client, _ = _mk_app(db, monkeypatch, redis=_Redis())  # note: no s3=... so our patch stands

    r = client.post(
        f"/api/v1/admin/titles/{title_id}/video",
        json={"content_type": "video/mp4"},
        headers={"Idempotency-Key": "same-key"},
    )
    assert r.status_code == 200
    assert r.json() == snap  # exact replay

def test_create_video_sets_idempotency_snapshot_on_success(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[object()]])
    redis = FakeRedis()
    calls: List[Tuple[str, Dict[str, Any], int]] = []

    async def _set(k, v, ttl_seconds=600):
        calls.append((k, v, ttl_seconds))
        await redis.idempotency_set(k, v, ttl_seconds=ttl_seconds)

    # Build the app first (this sets idempotency_get/idempotency_set),
    # then re-patch idempotency_set so it doesn't get overwritten.
    app, client, _ = _mk_app(db, monkeypatch, s3=FakeS3(), redis=redis)
    monkeypatch.setattr(mod.redis_wrapper, "idempotency_set", _set, raising=False)

    r = client.post(
        f"/api/v1/admin/titles/{title_id}/video",
        json={"content_type": "video/mp4"},
        headers={"Idempotency-Key": "abc123"},
    )
    assert r.status_code == 200
    k, body, ttl = calls[-1]
    assert k == f"idemp:admin:video:create:{title_id}:abc123"
    assert ttl == 600
    assert body["asset_id"]


def test_create_video_ignores_redis_set_error(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[object()]])

    async def _boom(*_a, **_k): raise RuntimeError("redis down")

    monkeypatch.setattr(mod.redis_wrapper, "idempotency_set", _boom, raising=False)

    app, client, _ = _mk_app(db, monkeypatch, s3=FakeS3())
    r = client.post(
        f"/api/v1/admin/titles/{title_id}/video",
        json={"content_type": "video/mp4"},
        headers={"Idempotency-Key": "abc123"},
    )
    assert r.status_code == 200  # still succeeds


# ─────────────────────────────────────────────────────────────────────────────
# S3 & storage key behavior
# ─────────────────────────────────────────────────────────────────────────────

def test_storage_key_extension_matches_mp4(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[object()]])
    app, client, _ = _mk_app(db, monkeypatch, s3=FakeS3())
    r = client.post(f"/api/v1/admin/titles/{title_id}/video", json={"content_type": "video/mp4"})
    assert r.status_code == 200
    assert r.json()["storage_key"].endswith(".mp4")

def test_storage_key_extension_matches_mpeg(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[object()]])
    app, client, _ = _mk_app(db, monkeypatch, s3=FakeS3())
    r = client.post(f"/api/v1/admin/titles/{title_id}/video", json={"content_type": "video/mpeg"})
    assert r.status_code == 200
    assert r.json()["storage_key"].endswith(".mpg")

def test_s3_client_error_maps_to_503(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[object()]])

    class _FailS3:
        def __init__(self): raise mod.S3StorageError("outage")

    monkeypatch.setattr(mod, "S3Client", _FailS3, raising=False)
    app, client, _ = _mk_app(db, monkeypatch)  # no s3 override

    r = client.post(f"/api/v1/admin/titles/{title_id}/video", json={"content_type": "video/mp4"})
    assert r.status_code == 503
    assert "outage" in r.text


# ─────────────────────────────────────────────────────────────────────────────
# Primary semantics & DB side-effects
# ─────────────────────────────────────────────────────────────────────────────

def test_is_primary_unsets_others_for_same_title_and_language(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[object()], []])  # 2nd execute for the UPDATE
    app, client, _ = _mk_app(db, monkeypatch, s3=FakeS3())

    r = client.post(
        f"/api/v1/admin/titles/{title_id}/video",
        json={"content_type": "video/mp4", "language": "en", "is_primary": True},
    )
    assert r.status_code == 200
    # Title SELECT + UPDATE to unset other primaries
    assert db.exec_calls >= 2

def test_label_is_persisted_in_metadata(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[object()]])
    app, client, _ = _mk_app(db, monkeypatch, s3=FakeS3())

    label = "Director's Cut"
    r = client.post(
        f"/api/v1/admin/titles/{title_id}/video",
        json={"content_type": "video/mp4", "label": label},
    )
    assert r.status_code == 200
    created = db.added[0]
    assert getattr(created, "metadata_json", None) and created.metadata_json.get("label") == label


# ─────────────────────────────────────────────────────────────────────────────
# Audit logging is best-effort
# ─────────────────────────────────────────────────────────────────────────────

def test_audit_log_failure_is_swallowed(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[object()]])

    async def _boom(*_a, **_k): raise RuntimeError("audit down")

    monkeypatch.setattr(mod, "log_audit_event", _boom, raising=False)
    app, client, _ = _mk_app(db, monkeypatch, s3=FakeS3())

    r = client.post(f"/api/v1/admin/titles/{title_id}/video", json={"content_type": "video/mp4"})
    assert r.status_code == 200  # still OK


# ─────────────────────────────────────────────────────────────────────────────
# AuthZ + MFA
# ─────────────────────────────────────────────────────────────────────────────

def test_admin_required(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[object()]])
    app, client, _ = _mk_app(db, monkeypatch, ensure_admin=_raise_403, ensure_mfa=_noop, s3=FakeS3())
    r = client.post(f"/api/v1/admin/titles/{title_id}/video", json={"content_type": "video/mp4"})
    assert r.status_code == 403
    assert r.json()["detail"] == "Forbidden"

def test_mfa_required(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[object()]])
    app, client, _ = _mk_app(db, monkeypatch, ensure_admin=_noop, ensure_mfa=_raise_401, s3=FakeS3())
    r = client.post(f"/api/v1/admin/titles/{title_id}/video", json={"content_type": "video/mp4"})
    assert r.status_code == 401
    assert r.json()["detail"] == "MFA required"
