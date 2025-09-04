# tests/test_admin/test_streams/test_patch_stream.py
import uuid
import pytest
from sqlalchemy import select

from app.db.models.title import Title
from app.db.models.media_asset import MediaAsset
from app.db.models.stream_variant import StreamVariant
from app.schemas.enums import (
    TitleType,
    MediaAssetKind,
    StreamProtocol,
    Container,
    StreamTier,
)

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


async def _mk_stream_row(
    db_session,
    *,
    asset: MediaAsset,
    protocol: StreamProtocol = StreamProtocol.HLS,
    container: Container = Container.FMP4,
    url_path: str = "hls/custom.m3u8",
    is_streamable: bool = False,
    is_downloadable: bool = False,
    stream_tier: StreamTier | None = None,
    audio_language: str | None = None,
    label: str | None = None,
) -> StreamVariant:
    v = StreamVariant(
        media_asset_id=asset.id,
        url_path=url_path,
        protocol=protocol,
        container=container,
        bandwidth_bps=1_000_000,
        avg_bandwidth_bps=None,
        width=None,
        height=None,
        is_streamable=is_streamable,
        is_downloadable=is_downloadable,
        stream_tier=stream_tier,
        is_default=False,
        audio_language=audio_language,
        label=label,
    )
    db_session.add(v)
    await db_session.flush()
    await db_session.commit()
    return v


# ─────────────────────────────────────────────────────────────────────────────
# Admin/MFA & audit log: bypass / mute for tests
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
async def test_patch_updates_flags_label_language_success(async_client, db_session):
    t = await _mk_title(db_session)

    # Create HLS variant via POST
    payload = {
        "type": "hls",
        "quality": "720p",
        "url_path": "hls/720.m3u8",
        "bandwidth_bps": 2_000_000,
        "label": "orig",
        "audio_language": "en",
    }
    r_create = await async_client.post(f"{BASE_TITLES}/{t.id}/streams", json=payload)
    assert r_create.status_code == 200, r_create.text
    stream = r_create.json()

    # Patch several fields
    patch = {
        "is_streamable": False,
        "is_downloadable": True,
        "is_default": True,
        "label": "Alt 720p",
        "audio_language": "en-US",
    }
    r = await async_client.patch(f"{BASE_STREAMS}/{stream['id']}", json=patch)
    assert r.status_code == 200, r.text
    assert r.headers.get("Cache-Control") == "no-store"

    data = r.json()
    assert data["is_streamable"] is False
    assert data["is_downloadable"] is True
    assert data["is_default"] is True
    assert data["label"] == "Alt 720p"
    assert data["audio_language"].lower() == "en-us"


@pytest.mark.anyio
async def test_patch_only_hls_can_be_streamable_true(async_client, db_session):
    t = await _mk_title(db_session)

    # Create MP4 variant
    r_create = await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={
            "type": "mp4",
            "quality": "1080p",
            "url_path": "files/1080.mp4",
            "bandwidth_bps": 8_000_000,
        },
    )
    assert r_create.status_code == 200, r_create.text
    stream = r_create.json()

    # Attempt to set streamable=True
    r = await async_client.patch(f"{BASE_STREAMS}/{stream['id']}", json={"is_streamable": True})
    assert r.status_code == 400
    assert "Only HLS variants can be streamable" in r.text


@pytest.mark.anyio
async def test_patch_streamable_true_requires_tier_when_absent(async_client, db_session):
    t = await _mk_title(db_session)
    asset = await _mk_asset(db_session, title_id=t.id)

    # Manually create HLS with NO tier on row
    v = await _mk_stream_row(
        db_session,
        asset=asset,
        protocol=StreamProtocol.HLS,
        container=Container.FMP4,
        url_path="hls/custom.m3u8",
        is_streamable=False,
        is_downloadable=False,
        stream_tier=None,  # critical: absent
    )

    # Make it streamable without providing tier → 400
    r = await async_client.patch(f"{BASE_STREAMS}/{v.id}", json={"is_streamable": True})
    assert r.status_code == 400
    assert "stream_tier required" in r.text


@pytest.mark.anyio
async def test_patch_invalid_language(async_client, db_session):
    t = await _mk_title(db_session)
    r_create = await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={"type": "hls", "quality": "480p", "url_path": "hls/480.m3u8", "bandwidth_bps": 900_000},
    )
    stream = r_create.json()

    r = await async_client.patch(f"{BASE_STREAMS}/{stream['id']}", json={"audio_language": "en_US"})
    assert r.status_code == 400
    assert "Invalid language tag" in r.text


@pytest.mark.anyio
async def test_patch_no_changes_provided(async_client, db_session):
    t = await _mk_title(db_session)
    r_create = await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={"type": "hls", "quality": "480p", "url_path": "hls/480.m3u8", "bandwidth_bps": 900_000},
    )
    stream = r_create.json()

    r = await async_client.patch(f"{BASE_STREAMS}/{stream['id']}", json={})
    assert r.status_code == 400
    assert "No changes provided" in r.text


@pytest.mark.anyio
async def test_patch_updates_tier_only(async_client, db_session):
    t = await _mk_title(db_session)
    r_create = await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={"type": "hls", "quality": "720p", "url_path": "hls/720.m3u8", "bandwidth_bps": 2_000_000},
    )
    assert r_create.status_code == 200, r_create.text
    sid = r_create.json()["id"]

    # Update tier to P1080
    r = await async_client.patch(f"{BASE_STREAMS}/{sid}", json={"stream_tier": "P1080"})
    assert r.status_code == 200, r.text
    assert "P1080" in str(r.json()["stream_tier"])

    # Verify persisted
    row = (
        await db_session.execute(select(StreamVariant).where(StreamVariant.id == uuid.UUID(sid)))
    ).scalar_one()
    assert str(row.stream_tier).endswith("P1080")


@pytest.mark.anyio
async def test_patch_404_when_stream_not_found(async_client):
    missing = uuid.uuid4()
    r = await async_client.patch(f"{BASE_STREAMS}/{missing}", json={"is_default": True})
    assert r.status_code == 404
    assert "Stream not found" in r.text
