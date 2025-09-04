# tests/test_admin/test_assets/test_list_streams.py
import uuid
import pytest
import anyio
from sqlalchemy import select

from app.db.models.title import Title
from app.db.models.media_asset import MediaAsset
from app.db.models.stream_variant import StreamVariant
from app.schemas.enums import TitleType, MediaAssetKind

BASE_TITLES = "/api/v1/admin/titles"


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


# ─────────────────────────────────────────────────────────────────────────────
# Admin/MFA & audit log: bypass / mute for tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _mock_admin_mfa(monkeypatch):
    import app.dependencies.admin as admin_deps

    async def _noop(*args, **kwargs):
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

    async def _noop(*args, **kwargs):
        return None

    monkeypatch.setattr(audit, "log_audit_event", _noop)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Tests                                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.mark.anyio
async def test_list_filters_by_protocol(async_client, db_session):
    t = await _mk_title(db_session)

    await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={"type": "hls", "quality": "720p", "url_path": "hls.m3u8", "bandwidth_bps": 2_500_000},
    )
    r_mp4 = await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={"type": "mp4", "quality": "1080p", "url_path": "movie_1080.mp4", "bandwidth_bps": 8_000_000},
    )
    mp4_id = r_mp4.json()["id"]

    r = await async_client.get(f"{BASE_TITLES}/{t.id}/streams", params={"protocol": "MP4"})
    assert r.status_code == 200, r.text
    items = r.json()
    assert all("MP4" in str(i["protocol"]) for i in items)
    assert mp4_id in {i["id"] for i in items}


@pytest.mark.anyio
async def test_list_filters_by_tier(async_client, db_session):
    t = await _mk_title(db_session)

    r_480 = await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={"type": "hls", "quality": "480p", "url_path": "hls/480p.m3u8", "bandwidth_bps": 900_000},
    )
    r_720 = await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={"type": "hls", "quality": "720p", "url_path": "hls/720p.m3u8", "bandwidth_bps": 2_000_000},
    )
    v720_id = r_720.json()["id"]

    r = await async_client.get(f"{BASE_TITLES}/{t.id}/streams", params={"tier": "P720"})
    assert r.status_code == 200, r.text
    items = r.json()
    assert len(items) >= 1
    assert all("P720" in str(i["stream_tier"]) for i in items)
    assert v720_id in {i["id"] for i in items}

    r = await async_client.get(f"{BASE_TITLES}/{t.id}/streams", params={"tier": "P480"})
    assert r.status_code == 200
    assert r_480.json()["id"] in {i["id"] for i in r.json()}
    assert v720_id not in {i["id"] for i in r.json()}


@pytest.mark.anyio
async def test_list_filters_by_language_normalized(async_client, db_session):
    t = await _mk_title(db_session)

    await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={"type": "hls", "quality": "480p", "url_path": "hls/en_480p.m3u8", "bandwidth_bps": 900_000, "audio_language": "en"},
    )
    r_enus = await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={"type": "hls", "quality": "720p", "url_path": "hls/enus_720p.m3u8", "bandwidth_bps": 2_000_000, "audio_language": "en-US"},
    )
    enus_id = r_enus.json()["id"]

    r = await async_client.get(f"{BASE_TITLES}/{t.id}/streams", params={"language": "en-us"})
    assert r.status_code == 200, r.text
    items = r.json()
    ids = {i["id"] for i in items}
    assert enus_id in ids
    assert all(i["audio_language"].lower() == "en-us" for i in items)


@pytest.mark.anyio
async def test_list_filters_streamable_and_downloadable(async_client, db_session):
    t = await _mk_title(db_session)

    r_hls = await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={"type": "hls", "quality": "720p", "url_path": "hls/720.m3u8", "bandwidth_bps": 2_000_000},
    )
    r_mp4 = await async_client.post(
        f"{BASE_TITLES}/{t.id}/streams",
        json={"type": "mp4", "quality": "1080p", "url_path": "files/1080.mp4", "bandwidth_bps": 8_000_000},
    )

    r = await async_client.get(f"{BASE_TITLES}/{t.id}/streams", params={"streamable": True})
    assert r.status_code == 200
    items = r.json()
    assert all(i["is_streamable"] is True for i in items)
    assert r_hls.json()["id"] in {i["id"] for i in items}
    assert r_mp4.json()["id"] not in {i["id"] for i in items}

    r = await async_client.get(f"{BASE_TITLES}/{t.id}/streams", params={"downloadable": True})
    assert r.status_code == 200
    items = r.json()
    assert all(i["is_downloadable"] is True for i in items)
    assert r_mp4.json()["id"] in {i["id"] for i in items}
    assert r_hls.json()["id"] not in {i["id"] for i in items}


@pytest.mark.anyio
async def test_list_pagination_limit_offset(async_client, db_session):
    t = await _mk_title(db_session)

    ids = []
    for q, path in [("480p", "hls/a.m3u8"), ("720p", "hls/b.m3u8"), ("1080p", "hls/c.m3u8")]:
        r = await async_client.post(
            f"{BASE_TITLES}/{t.id}/streams",
            json={"type": "hls", "quality": q, "url_path": path, "bandwidth_bps": 1_000_000},
        )
        assert r.status_code == 200
        ids.append(r.json()["id"])

    r = await async_client.get(f"{BASE_TITLES}/{t.id}/streams", params={"limit": 2, "offset": 0})
    assert r.status_code == 200
    page1 = [i["id"] for i in r.json()]
    assert len(page1) == 2

    r = await async_client.get(f"{BASE_TITLES}/{t.id}/streams", params={"limit": 2, "offset": 2})
    assert r.status_code == 200
    page2 = [i["id"] for i in r.json()]
    assert len(page2) >= 1
    assert not set(page1) & set(page2)


@pytest.mark.anyio
async def test_list_400_on_invalid_language_query(async_client, db_session):
    t = await _mk_title(db_session)

    r = await async_client.get(f"{BASE_TITLES}/{t.id}/streams", params={"language": "en_US"})
    assert r.status_code == 400
    assert "Invalid language tag" in r.text


@pytest.mark.anyio
async def test_list_404_when_title_not_found(async_client):
    missing = uuid.uuid4()
    r = await async_client.get(f"{BASE_TITLES}/{missing}/streams")
    assert r.status_code == 404
