# tests/test_admin/test_assets/test_asset_checksum_only.py
import hashlib
from typing import Optional

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import uuid4

from app.db.models.media_asset import MediaAsset

BASE = "/api/v1/admin"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
async def _mk_asset(
    db,
    *,
    storage_key: Optional[str] = "media/a.mp4",
    bytes_size: Optional[int] = None,
    checksum_sha256: Optional[str] = None,
) -> MediaAsset:
    m = MediaAsset(
        id=str(uuid4()),
        title_id=None,
        storage_key=storage_key,
        bytes_size=bytes_size,
        mime_type=None,
        checksum_sha256=checksum_sha256,
    )
    db.add(m)
    await db.commit()
    await db.refresh(m)
    return m


class _NoopLock:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeS3:
    """Minimal fake with .client.head_object / .client.get_object semantics."""

    def __init__(self, *, head_len: int | None = None, data: bytes | None = None, get_boom: Exception | None = None):
        self.bucket = "test-bucket"
        self._head_len = head_len
        self._data = data if data is not None else b""
        self._get_boom = get_boom

        class _Client:
            def __init__(self, outer):
                self._outer = outer

            def head_object(self, Bucket: str, Key: str):
                assert Bucket == "test-bucket"
                assert Key
                return {"ContentLength": int(outer._head_len or 0)}

            def get_object(self, Bucket: str, Key: str):
                assert Bucket == "test-bucket"
                assert Key
                if outer._get_boom:
                    raise outer._get_boom

                class _Body:
                    def read(self_non):
                        return outer._data

                return {"Body": _Body()}

        outer = self
        self.client = _Client(self)

# -----------------------------
# Shared stubs
# -----------------------------
async def _noop(*args, **kwargs):
    return None

@pytest.fixture(autouse=True)
def _patch_admin_auth(monkeypatch):
    """
    Make `ensure_admin` and `ensure_mfa` no-ops so we don't need real auth/MFA in tests.
    (The route imports them at call time from app.dependencies.admin.)
    """
    import app.dependencies.admin as admin_mod

    monkeypatch.setattr(admin_mod, "ensure_admin", _noop, raising=True)
    monkeypatch.setattr(admin_mod, "ensure_mfa", _noop, raising=True)


@pytest.fixture(autouse=True)
async def _override_current_user(app):
    """Provide a valid UUID-bearing admin user for dependency-based auth."""
    import uuid as _uuid
    from app.core.security import get_current_user

    async def _test_user_dep():
        class _U:
            id = _uuid.uuid4()
            is_superuser = True
        return _U()

    app.dependency_overrides[get_current_user] = _test_user_dep
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_current_user, None)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_checksum_with_provided_hex_updates_db(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session, storage_key="media/x.mp4", bytes_size=123)
    asset_id = str(m.id)

    # No Redis lock side-effects
    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod.redis_wrapper, "lock", lambda *_a, **_k: _NoopLock(), raising=True)

    good_sha = hashlib.sha256(b"anything").hexdigest()
    r = await async_client.post(f"{BASE}/assets/{asset_id}/checksum", json={"sha256": good_sha})
    assert r.status_code == 200, r.text
    assert r.json() == {"sha256": good_sha, "status": "UPDATED"}
    # persisted
    fresh = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one()
    assert fresh.checksum_sha256 == good_sha


@pytest.mark.anyio
async def test_checksum_invalid_hex(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session)
    asset_id = str(m.id)
    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod.redis_wrapper, "lock", lambda *_a, **_k: _NoopLock(), raising=True)

    r = await async_client.post(f"{BASE}/assets/{asset_id}/checksum", json={"sha256": "not-a-hash"})
    assert r.status_code == 400
    assert r.json()["detail"] == "Invalid sha256 hex"


@pytest.mark.anyio
async def test_checksum_requires_sha_for_large_asset_size_from_db(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session, bytes_size=2_000_000)  # will exceed patched threshold
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    # Make the "small-compute" threshold tiny so DB size is considered "large"
    monkeypatch.setattr(mod, "SMALL_COMPUTE_MAX_BYTES", 1024, raising=False)
    monkeypatch.setattr(mod.redis_wrapper, "lock", lambda *_a, **_k: _NoopLock(), raising=True)
    monkeypatch.setattr(mod, "_ensure_s3", lambda: _FakeS3(), raising=True)

    r = await async_client.post(f"{BASE}/assets/{asset_id}/checksum", json={})  # sha absent
    assert r.status_code == 400
    assert "Provide sha256" in r.json()["detail"]


@pytest.mark.anyio
async def test_checksum_server_computes_when_small_using_db_size(async_client: AsyncClient, db_session, monkeypatch):
    data = b"hello world"
    expected = hashlib.sha256(data).hexdigest()
    m = await _mk_asset(db_session, bytes_size=100)  # small → compute allowed
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    fake = _FakeS3(data=data)
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)
    monkeypatch.setattr(mod.redis_wrapper, "lock", lambda *_a, **_k: _NoopLock(), raising=True)

    r = await async_client.post(f"{BASE}/assets/{asset_id}/checksum", json={})
    assert r.status_code == 200, r.text
    assert r.json() == {"sha256": expected, "status": "UPDATED"}

    fresh = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one()
    assert fresh.checksum_sha256 == expected


@pytest.mark.anyio
async def test_checksum_server_computes_when_small_using_head_if_db_missing(async_client: AsyncClient, db_session, monkeypatch):
    data = b"abcde"
    expected = hashlib.sha256(data).hexdigest()
    m = await _mk_asset(db_session, bytes_size=None)  # force HEAD path
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    # HEAD reports small size; then get_object provides body
    fake = _FakeS3(head_len=5, data=data)
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)
    monkeypatch.setattr(mod.redis_wrapper, "lock", lambda *_a, **_k: _NoopLock(), raising=True)

    r = await async_client.post(f"{BASE}/assets/{asset_id}/checksum", json={})
    assert r.status_code == 200, r.text
    assert r.json() == {"sha256": expected, "status": "UPDATED"}

    fresh = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one()
    assert fresh.checksum_sha256 == expected


@pytest.mark.anyio
async def test_checksum_compute_failure_returns_503(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session, bytes_size=100)
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    fake = _FakeS3(get_boom=RuntimeError("get failed"))
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)
    monkeypatch.setattr(mod.redis_wrapper, "lock", lambda *_a, **_k: _NoopLock(), raising=True)

    r = await async_client.post(f"{BASE}/assets/{asset_id}/checksum", json={})
    assert r.status_code == 503
    assert r.json()["detail"].startswith("Checksum compute failed:")


@pytest.mark.anyio
async def test_checksum_existing_not_overwritten_without_force(async_client: AsyncClient, db_session, monkeypatch):
    existing = "a" * 64
    m = await _mk_asset(db_session, checksum_sha256=existing, bytes_size=100)
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod.redis_wrapper, "lock", lambda *_a, **_k: _NoopLock(), raising=True)
    # Provide a different valid sha, but expect UNCHANGED
    new_sha = "b" * 64

    r = await async_client.post(f"{BASE}/assets/{asset_id}/checksum", json={"sha256": new_sha})
    assert r.status_code == 200
    assert r.json() == {"sha256": existing, "status": "UNCHANGED"}

    fresh = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one()
    assert fresh.checksum_sha256 == existing


@pytest.mark.anyio
async def test_checksum_force_overwrites_existing(async_client: AsyncClient, db_session, monkeypatch):
    existing = "a" * 64
    m = await _mk_asset(db_session, checksum_sha256=existing, bytes_size=100)
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod.redis_wrapper, "lock", lambda *_a, **_k: _NoopLock(), raising=True)

    new_sha = "b" * 64
    r = await async_client.post(f"{BASE}/assets/{asset_id}/checksum", json={"sha256": new_sha, "force": True})
    assert r.status_code == 200
    assert r.json() == {"sha256": new_sha, "status": "UPDATED"}

    fresh = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one()
    assert fresh.checksum_sha256 == new_sha


@pytest.mark.anyio
async def test_checksum_audit_log_failure_is_ignored(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session, bytes_size=10)
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod.redis_wrapper, "lock", lambda *_a, **_k: _NoopLock(), raising=True)
    monkeypatch.setattr(mod, "_ensure_s3", lambda: _FakeS3(data=b"x"), raising=True)

    async def _boom_log(*args, **kwargs):
        raise RuntimeError("audit down")

    monkeypatch.setattr(mod, "log_audit_event", _boom_log, raising=True)

    r = await async_client.post(f"{BASE}/assets/{asset_id}/checksum", json={})
    assert r.status_code == 200
    assert "sha256" in r.json()


@pytest.mark.anyio
async def test_checksum_asset_not_found(async_client: AsyncClient):
    r = await async_client.post(f"{BASE}/assets/{uuid4()}/checksum", json={"sha256": "a" * 64})
    assert r.status_code == 404
    assert r.json()["detail"] == "Asset not found"


@pytest.mark.anyio
async def test_checksum_missing_storage_key(async_client: AsyncClient, db_session):
    m = await _mk_asset(db_session, storage_key=None)
    asset_id = str(m.id)

    r = await async_client.post(f"{BASE}/assets/{asset_id}/checksum", json={"sha256": "a" * 64})
    assert r.status_code == 400
    assert r.json()["detail"] == "Asset missing storage_key"


@pytest.mark.anyio
async def test_checksum_db_commit_failure_bubbles(async_client: AsyncClient, db_session, monkeypatch):
    # Create asset first, then make commit fail only for the route's commit
    m = await _mk_asset(db_session, bytes_size=10)
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod.redis_wrapper, "lock", lambda *_a, **_k: _NoopLock(), raising=True)
    monkeypatch.setattr(mod, "_ensure_s3", lambda: _FakeS3(data=b"x"), raising=True)

    async def _boom_commit(self):
        raise RuntimeError("commit failed")

    monkeypatch.setattr(AsyncSession, "commit", _boom_commit, raising=True)

    r = await async_client.post(f"{BASE}/assets/{asset_id}/checksum", json={})
    # FastAPI will turn this into a 500 response
    assert r.status_code == 500
