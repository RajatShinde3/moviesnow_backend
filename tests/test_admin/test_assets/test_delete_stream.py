# tests/test_admin/test_streams/test_delete_stream.py
import uuid
import pytest
from sqlalchemy import select

from app.db.models.title import Title
from app.db.models.media_asset import MediaAsset
from app.db.models.stream_variant import StreamVariant
from app.schemas.enums import TitleType, MediaAssetKind

BASE_TITLES = "/api/v1/admin/titles"
BASE_STREAMS = "/api/v1/admin/streams"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _mk_title(db_session) -> Title:
    t = Title(
        id=uuid.uuid4(),
        type=TitleType.MOVIE,
        name=f"Title {uuid.uuid4().hex[:6]}",
        slug=f"t-{uuid.uuid4().hex[:6]}",
        is_published=True,
        release_year=2024,
    )
    db_session.add(t)
    await db_session.flush()
    await db_session.commit()
    return t


async def _mk_asset(db_session, *, title_id, kind=MediaAssetKind.VIDEO, language=None) -> MediaAsset:
    a = MediaAsset(
        id=uuid.uuid4(),
        title_id=title_id,
        kind=kind,
        language=language,
        storage_key=f"assets/{title_id}/{uuid.uuid4().hex}.bin",
    )
    db_session.add(a)
    await db_session.flush()
    await db_session.commit()
    return a


# ─────────────────────────────────────────────────────────────────────────────
# Admin/MFA & audit: bypass / mute for tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _mock_admin_mfa(monkeypatch):
    import app.dependencies.admin as admin_deps
    async def _noop(*args, **kwargs):  # nosec - test stub
        return None
    monkeypatch.setattr(admin_deps, "ensure_admin", _noop)
    monkeypatch.setattr(admin_deps, "ensure_mfa", _noop)


@pytest.fixture(autouse=True)
async def _override_current_user(app):
    from app.core.security import get_current_user
    async def _test_user_dep():
        class _U:
            id = uuid.uuid4()
            is_superuser = True
        return _U()
    app.dependency_overrides[get_current_user] = _test_user_dep
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture(autouse=True)
def _mute_audit(monkeypatch):
    import app.services.audit_log_service as audit
    async def _noop(*args, **kwargs):  # nosec - test stub
        return None
    monkeypatch.setattr(audit, "log_audit_event", _noop)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Tests                                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.mark.anyio
async def test_delete_stream_success_then_row_absent(async_client, db_session):
    t = await _mk_title(db_session)

    # Create a stream via POST (ensures row is consistent with route behavior)
    r_create = await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={"type": "hls", "quality": "480p", "url_path": "hls/480.m3u8", "bandwidth_bps": 900_000},
    )
    assert r_create.status_code == 200, r_create.text
    sid = r_create.json()["id"]

    # Delete it
    r_del = await async_client.delete(f"{BASE_STREAMS}/{sid}")
    assert r_del.status_code == 200, r_del.text
    assert r_del.headers.get("Cache-Control") == "no-store"
    assert "Stream deleted" in r_del.text

    # Verify the row is gone
    row = (
        await db_session.execute(select(StreamVariant).where(StreamVariant.id == uuid.UUID(sid)))
    ).scalar_one_or_none()
    assert row is None


@pytest.mark.anyio
async def test_delete_stream_second_attempt_404(async_client, db_session):
    t = await _mk_title(db_session)
    r_create = await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={"type": "mp4", "quality": "1080p", "url_path": "files/1080.mp4", "bandwidth_bps": 8_000_000},
    )
    assert r_create.status_code == 200, r_create.text
    sid = r_create.json()["id"]

    # First delete OK
    r1 = await async_client.delete(f"{BASE_STREAMS}/{sid}")
    assert r1.status_code == 200, r1.text

    # Second delete → 404
    r2 = await async_client.delete(f"{BASE_STREAMS}/{sid}")
    assert r2.status_code == 404
    assert "Stream not found" in r2.text


@pytest.mark.anyio
async def test_delete_stream_404_when_missing(async_client):
    missing = uuid.uuid4()
    r = await async_client.delete(f"{BASE_STREAMS}/{missing}")
    assert r.status_code == 404
    assert "Stream not found" in r.text


@pytest.mark.anyio
async def test_delete_one_does_not_affect_others(async_client, db_session):
    t = await _mk_title(db_session)

    # Create two variants
    r1 = await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={"type": "hls", "quality": "720p", "url_path": "hls/720.m3u8", "bandwidth_bps": 2_000_000},
    )
    r2 = await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={"type": "hls", "quality": "1080p", "url_path": "hls/1080.m3u8", "bandwidth_bps": 5_000_000},
    )
    assert r1.status_code == 200 and r2.status_code == 200
    sid_to_delete = r1.json()["id"]
    sid_keep = r2.json()["id"]

    # Delete first
    r_del = await async_client.delete(f"{BASE_STREAMS}/{sid_to_delete}")
    assert r_del.status_code == 200, r_del.text

    # First gone
    gone = (
        await db_session.execute(select(StreamVariant).where(StreamVariant.id == uuid.UUID(sid_to_delete)))
    ).scalar_one_or_none()
    assert gone is None

    # Second still present
    keep = (
        await db_session.execute(select(StreamVariant).where(StreamVariant.id == uuid.UUID(sid_keep)))
    ).scalar_one_or_none()
    assert keep is not None
