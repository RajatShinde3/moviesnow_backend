# tests/test_admin/test_streams/test_create_stream.py
import uuid
import pytest
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
# Admin/MFA & audit log: bypass / mute for tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _mock_admin_mfa(monkeypatch):
    # Make admin + MFA checks no-ops
    import app.dependencies.admin as admin_deps

    async def _noop(*args, **kwargs):
        return None

    monkeypatch.setattr(admin_deps, "ensure_admin", _noop)
    monkeypatch.setattr(admin_deps, "ensure_mfa", _noop)


@pytest.fixture(autouse=True)
async def _override_current_user(app):
    # Provide a valid superuser for dependency injection
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
    # Prevent audit logs from touching DB (FK on users)
    import app.services.audit_log_service as audit

    async def _noop(*args, **kwargs):
        return None

    monkeypatch.setattr(audit, "log_audit_event", _noop)


@pytest.fixture
def _fake_idempotency(monkeypatch):
    """
    Minimal in-memory idempotency snapshot store.
    Patches whichever redis_wrapper your route actually imports.
    """
    store: dict[str, dict] = {}

    async def _iget(key):  # type: ignore[override]
        return store.get(key)

    async def _iset(key, value, ttl_seconds=600):  # type: ignore[override]
        store[key] = value

    # Try both common locations; only patch those that import successfully.
    try:
        import app.core.redis_client as rc
        monkeypatch.setattr(rc.redis_wrapper, "idempotency_get", _iget, raising=True)
        monkeypatch.setattr(rc.redis_wrapper, "idempotency_set", _iset, raising=True)
    except Exception:
        pass

    try:
        import app.core.redis_client as rw
        monkeypatch.setattr(rw.redis_wrapper, "idempotency_get", _iget, raising=True)
        monkeypatch.setattr(rw.redis_wrapper, "idempotency_set", _iset, raising=True)
    except Exception:
        pass

    return store


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Tests                                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.mark.anyio
async def test_create_hls_creates_streamable_variant_and_holder_asset(async_client, db_session):
    t = await _mk_title(db_session)

    payload = {
        "type": "hls",
        "quality": "720p",
        "url_path": "hls/master.m3u8",
        "bandwidth_bps": 3_000_000,
        "avg_bandwidth_bps": 2_500_000,
        "audio_language": "en",
        "label": "Main EN 720p",
        "is_default": True,
    }
    r = await async_client.post(f"{BASE_TITLES}/{t.id}/streams", json=payload)
    assert r.status_code == 200, r.text

    data = r.json()
    # cache headers applied by _json()
    assert r.headers.get("Cache-Control") == "no-store"

    # Basic shape & flags
    assert data["url_path"] == payload["url_path"]
    assert "HLS" in str(data["protocol"])
    assert "FMP4" in str(data["container"])
    assert data["height"] == 720
    assert data["is_streamable"] is True
    assert data["is_downloadable"] is False
    assert "P720" in str(data["stream_tier"])
    assert data["is_default"] is True
    assert data["audio_language"] == "en"
    assert data["label"] == "Main EN 720p"

    # Holder asset should have been created and linked
    asset_id = uuid.UUID(data["media_asset_id"])
    asset = (
        await db_session.execute(
            select(MediaAsset).where(MediaAsset.id == asset_id)
        )
    ).scalar_one()
    assert asset.title_id == t.id
    assert asset.kind == MediaAssetKind.VIDEO


@pytest.mark.anyio
async def test_create_mp4_creates_downloadable_variant(async_client, db_session):
    t = await _mk_title(db_session)

    payload = {
        "type": "mp4",
        "quality": "1080p",
        "url_path": "files/movie_1080.mp4",
        "bandwidth_bps": 8_000_000,
        "avg_bandwidth_bps": 7_000_000,
        "audio_language": "en-US",
        "label": "FullHD MP4",
        "is_default": False,
    }
    r = await async_client.post(f"{BASE_TITLES}/{t.id}/streams", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()

    assert "MP4" in str(data["protocol"])          # StreamProtocol.MP4
    assert "MP4" in str(data["container"])         # Container.MP4
    assert data["height"] == 1080
    assert data["is_streamable"] is False
    assert data["is_downloadable"] is True
    assert data["stream_tier"] is None             # MP4 not streamable → no tier


@pytest.mark.anyio
async def test_create_binds_to_existing_asset_when_provided(async_client, db_session):
    t = await _mk_title(db_session)
    asset = await _mk_asset(db_session, title_id=t.id, language="en")

    payload = {
        "type": "hls",
        "quality": "480p",
        "url_path": "hls/480p.m3u8",
        "bandwidth_bps": 1_000_000,
        "avg_bandwidth_bps": 900_000,
        "audio_language": "en",
        "asset_id": str(asset.id),
    }
    r = await async_client.post(f"{BASE_TITLES}/{t.id}/streams", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["media_asset_id"] == str(asset.id)


@pytest.mark.anyio
async def test_create_400_when_asset_belongs_to_other_title(async_client, db_session):
    t1 = await _mk_title(db_session)
    t2 = await _mk_title(db_session)
    foreign = await _mk_asset(db_session, title_id=t2.id)

    payload = {
        "type": "hls",
        "quality": "480p",
        "url_path": "hls/480p.m3u8",
        "bandwidth_bps": 900_000,
        "asset_id": str(foreign.id),
    }
    r = await async_client.post(f"{BASE_TITLES}/{t1.id}/streams", json=payload)
    assert r.status_code == 400
    assert "asset_id not found for this title" in r.text


@pytest.mark.anyio
async def test_create_422_on_invalid_quality(async_client, db_session):
    """
    If your Pydantic schema restricts quality via Literal(...)
    (e.g., '480p'|'720p'|'1080p'), invalid values should be a 422.
    """
    t = await _mk_title(db_session)
    payload = {
        "type": "hls",
        "quality": "144p",                 # invalid per schema
        "url_path": "hls/144p.m3u8",
        "bandwidth_bps": 200_000,
    }
    r = await async_client.post(f"{BASE_TITLES}/{t.id}/streams", json=payload)
    assert r.status_code == 422
    # Basic sanity: the validation error should mention the 'quality' field
    assert "quality" in r.text


@pytest.mark.anyio
async def test_create_400_on_invalid_language_tag(async_client, db_session):
    """
    Language tag passes schema as a string but fails domain validation
    in _validate_language → 400.
    """
    t = await _mk_title(db_session)
    payload = {
        "type": "hls",
        "quality": "480p",
        "url_path": "hls/480p.m3u8",
        "bandwidth_bps": 900_000,
        "audio_language": "en_US",  # underscore → invalid per BCP 47-ish regex
    }
    r = await async_client.post(f"{BASE_TITLES}/{t.id}/streams", json=payload)
    assert r.status_code == 400
    assert "Invalid language tag" in r.text


@pytest.mark.anyio
async def test_create_idempotency_replays_snapshot(async_client, db_session, _fake_idempotency):
    t = await _mk_title(db_session)

    payload = {
        "type": "hls",
        "quality": "720p",
        "url_path": "hls/master.m3u8",
        "bandwidth_bps": 3_000_000,
    }
    headers = {"Idempotency-Key": "same-key"}

    r1 = await async_client.post(f"{BASE_TITLES}/{t.id}/streams", json=payload, headers=headers)
    r2 = await async_client.post(f"{BASE_TITLES}/{t.id}/streams", json=payload, headers=headers)

    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json() == r2.json()  # exact replay

    # Ensure only one variant row created
    rows = (
        await db_session.execute(
            select(StreamVariant)
            .join(MediaAsset, StreamVariant.media_asset_id == MediaAsset.id)
            .where(MediaAsset.title_id == t.id)
        )
    ).scalars().all()
    assert len(rows) == 1
