# tests/test_admin/test_assets/test_asset_head_only.py
import pytest
from uuid import uuid1, uuid4

from sqlalchemy import select
from httpx import AsyncClient

from app.db.models.media_asset import MediaAsset


BASE = "/api/v1/admin"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
async def _mk_asset(db, *, storage_key: str | None = "media/a.mp4"):
    m = MediaAsset(
        id=str(uuid4()),
        title_id=None,
        storage_key=storage_key,
        bytes_size=None,
        mime_type=None,
        checksum_sha256=None,
    )
    db.add(m)
    await db.commit()
    await db.refresh(m)
    return m


class _FakeS3:
    def __init__(self, head_payload=None, boom: Exception | None = None):
        self.bucket = "test-bucket"
        self._boom = boom
        self._payload = head_payload or {
            "ContentLength": 1234,
            "ContentType": "video/mp4",
            "ETag": '"abc123etag"',
        }

        class _Client:
            def __init__(self, outer):
                self._outer = outer

            def head_object(self, Bucket: str, Key: str):
                assert Bucket == "test-bucket"
                assert isinstance(Key, str) and Key
                if outer._boom:
                    raise outer._boom
                return dict(outer._payload)

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
async def test_assets_head_success_updates_db(async_client: AsyncClient, db_session, monkeypatch):
    # Arrange
    m = await _mk_asset(db_session, storage_key="media/video-1.mp4")
    asset_id = str(m.id)  # capture before any other commits

    # S3 returns head info
    from app.api.v1.routers.admin.assets import meta as mod
    fake = _FakeS3(
        head_payload={"ContentLength": 999, "ContentType": "video/mp4", "ETag": '"XYZ"'}
    )
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)

    # Act
    r = await async_client.get(f"{BASE}/assets/{asset_id}/head")

    # Assert
    assert r.status_code == 200, r.text
    data = r.json()
    assert data == {
        "size_bytes": 999,
        "content_type": "video/mp4",
        "etag": "XYZ",
        "storage_key": "media/video-1.mp4",
    }

    # DB cache was updated
    fresh = (
        await db_session.execute(
            select(MediaAsset).where(MediaAsset.id == asset_id)
        )
    ).scalar_one()
    assert fresh.bytes_size == 999
    assert fresh.mime_type == "video/mp4"

    # Cache headers present (no-store)
    assert r.headers.get("Cache-Control") == "no-store"
    assert r.headers.get("Pragma") == "no-cache"


@pytest.mark.anyio
async def test_assets_head_asset_not_found(async_client: AsyncClient):
    r = await async_client.get(f"{BASE}/assets/{uuid4()}/head")
    assert r.status_code == 404
    assert r.json()["detail"] == "Asset not found"


@pytest.mark.anyio
async def test_assets_head_missing_storage_key(async_client: AsyncClient, db_session):
    m = await _mk_asset(db_session, storage_key=None)
    asset_id = str(m.id)

    r = await async_client.get(f"{BASE}/assets/{asset_id}/head")
    assert r.status_code == 400
    assert r.json()["detail"] == "Asset missing storage_key"


@pytest.mark.anyio
async def test_assets_head_s3_error_returns_503(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session, storage_key="media/broken.mp4")
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    fake = _FakeS3(boom=RuntimeError("boom"))
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)

    r = await async_client.get(f"{BASE}/assets/{asset_id}/head")
    assert r.status_code == 503
    assert "HEAD failed:" in r.json()["detail"]


@pytest.mark.anyio
async def test_assets_head_db_commit_failure_is_non_fatal(async_client: AsyncClient, db_session, monkeypatch):
    # Arrange
    m = await _mk_asset(db_session, storage_key="media/no-commit.mp4")
    asset_id = str(m.id)  # capture before we monkeypatch commit

    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: _FakeS3(), raising=True)

    # Patch only the commit used by the route's session, not this test's creation step
    async def _boom_commit(self):
        raise RuntimeError("commit failed")

    from sqlalchemy.ext.asyncio import AsyncSession
    monkeypatch.setattr(AsyncSession, "commit", _boom_commit, raising=True)

    # Act
    r = await async_client.get(f"{BASE}/assets/{asset_id}/head")

    # Assert: still succeeds with live S3 data
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["size_bytes"] == 1234
    assert data["content_type"] == "video/mp4"
    assert data["etag"] == "abc123etag"

    # And DB likely did NOT persist (best-effort cache)
    fresh = (
        await db_session.execute(
            select(MediaAsset).where(MediaAsset.id == asset_id)
        )
    ).scalar_one()
    assert fresh.bytes_size in (None, 0)
    assert fresh.mime_type in (None, "")


@pytest.mark.anyio
async def test_assets_head_audit_log_failure_is_ignored(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session, storage_key="media/audit-ok.mp4")
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: _FakeS3(), raising=True)

    async def _boom_log(*args, **kwargs):
        raise RuntimeError("audit down")

    monkeypatch.setattr(mod, "log_audit_event", _boom_log, raising=True)

    r = await async_client.get(f"{BASE}/assets/{asset_id}/head")
    assert r.status_code == 200
    assert "size_bytes" in r.json()


@pytest.mark.anyio
async def test_assets_head_uses_exact_bucket_and_key(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session, storage_key="exact/path/file.mov")
    asset_id = str(m.id)

    calls = {"seen": []}

    class _CheckS3(_FakeS3):
        def __init__(self):
            super().__init__(head_payload={"ContentLength": 1, "ContentType": "video/quicktime", "ETag": '"E"'})
            # wrap the client's head_object to record inputs
            orig = self.client.head_object

            def wrapped(Bucket, Key):
                calls["seen"].append((Bucket, Key))
                return orig(Bucket=Bucket, Key=Key)

            self.client.head_object = wrapped

    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: _CheckS3(), raising=True)

    r = await async_client.get(f"{BASE}/assets/{asset_id}/head")
    assert r.status_code == 200
    assert calls["seen"] == [("test-bucket", "exact/path/file.mov")]
