# tests/test_admin/test_subtitles/test_create_subtitle.py
import uuid
import pytest
from sqlalchemy import select

from app.db.models.title import Title
from app.db.models.media_asset import MediaAsset
from app.db.models.subtitle import Subtitle
from app.schemas.enums import TitleType, MediaAssetKind, SubtitleFormat

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
# Autofixed fixtures: admin/MFA bypass, audit mute, idempotency, S3 stub
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _mock_admin_mfa(monkeypatch):
    import app.dependencies.admin as admin_deps
    async def _noop(*args, **kwargs): return None
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
    async def _noop(*args, **kwargs): return None
    monkeypatch.setattr(audit, "log_audit_event", _noop)


@pytest.fixture(autouse=True)
def _fake_idempotency(monkeypatch):
    store = {}

    async def _iget(key):  # type: ignore[override]
        return store.get(key)

    async def _iset(key, value, ttl_seconds=600):  # type: ignore[override]
        store[key] = value

    import app.core.redis_client as rc
    monkeypatch.setattr(rc.redis_wrapper, "idempotency_get", _iget)
    monkeypatch.setattr(rc.redis_wrapper, "idempotency_set", _iset)
    return store


@pytest.fixture(autouse=True)
def _s3_stub(monkeypatch):
    """Replace S3Client used by the route with a simple stub."""
    calls = {"presigned_put": []}

    class _S3Stub:
        def __init__(self, *a, **k): ...
        def presigned_put(self, key, content_type, public=False):
            calls["presigned_put"].append({"key": key, "content_type": content_type, "public": public})
            return f"https://s3.mock/{key}"
        def delete(self, key):
            calls.setdefault("delete", []).append(key)

    # Patch the exact symbol imported in the router module
    import app.api.v1.routers.admin.assets.subtitles as mod
    monkeypatch.setattr(mod, "S3Client", _S3Stub)

    return calls


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Tests                                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.mark.anyio
async def test_create_vtt_success_returns_presigned_and_rows(async_client, db_session, _s3_stub):
    t = await _mk_title(db_session)
    payload = {
        "language": "en",
        "format": "VTT",
        "content_type": "text/VTT",
        "label": "English",
        "is_default": True,
        "is_forced": False,
        "is_sdh": False,
    }

    r = await async_client.post(f"{BASE_TITLES}/{t.id}/subtitles", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()

    # Response contract
    for k in ("asset_id", "subtitle_id", "upload_url", "storage_key"):
        assert k in data

    # Cache headers hardened
    assert r.headers.get("Cache-Control") == "no-store"

    # Storage key shape and S3 call
    key = data["storage_key"]
    assert key.startswith(f"subs/title/{t.id}/en/")
    assert key.endswith(".VTT")
    assert data["upload_url"].endswith(key)
    assert _s3_stub["presigned_put"] and _s3_stub["presigned_put"][-1]["key"] == key

    # Rows persisted
    asset = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == uuid.UUID(data["asset_id"])))).scalar_one()
    sub = (await db_session.execute(select(Subtitle).where(Subtitle.id == uuid.UUID(data["subtitle_id"])))).scalar_one()
    assert asset.title_id == t.id
    assert asset.kind == MediaAssetKind.SUBTITLE
    assert asset.mime_type == "text/VTT"
    assert sub.title_id == t.id
    assert sub.language == "en"
    assert sub.format == SubtitleFormat.VTT
    assert sub.label == "English"
    assert sub.is_default is True
    assert sub.is_forced is False
    assert sub.is_sdh is False
    assert asset.storage_key == key


@pytest.mark.anyio
async def test_create_SRT_success(async_client, db_session, _s3_stub):
    t = await _mk_title(db_session)
    payload = {
        "language": "en-US",
        "format": "SRT",
        "content_type": "application/x-subrip",
        "label": "English (US)",
        "is_default": False,
    }

    r = await async_client.post(f"{BASE_TITLES}/{t.id}/subtitles", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()

    key = data["storage_key"]
    assert key.startswith(f"subs/title/{t.id}/en-US/")
    assert key.endswith(".SRT")
    assert _s3_stub["presigned_put"][-1]["content_type"] == "application/x-subrip"

    sub = (await db_session.execute(select(Subtitle).where(Subtitle.id == uuid.UUID(data["subtitle_id"])))).scalar_one()
    assert sub.format == SubtitleFormat.SRT
    assert sub.is_default is False


@pytest.mark.anyio
async def test_create_415_unsupported_content_type(async_client, db_session):
    t = await _mk_title(db_session)
    payload = {
        "language": "en",
        "format": "VTT",
        "content_type": "text/plain",
    }
    r = await async_client.post(f"{BASE_TITLES}/{t.id}/subtitles", json=payload)
    assert r.status_code == 415
    assert "Unsupported subtitle" in r.text


@pytest.mark.anyio
async def test_create_400_mismatch_ct_and_format(async_client, db_session):
    t = await _mk_title(db_session)

    # VTT format but SRT mime
    r1 = await async_client.post(
        f"{BASE_TITLES}/{t.id}/subtitles",
        json={"language": "en", "format": "VTT", "content_type": "application/x-subrip"},
    )
    assert r1.status_code == 400
    assert "content_type must be text/VTT" in r1.text

    # SRT format but VTT mime
    r2 = await async_client.post(
        f"{BASE_TITLES}/{t.id}/subtitles",
        json={"language": "en", "format": "SRT", "content_type": "text/VTT"},
    )
    assert r2.status_code == 400
    assert "content_type must be application/x-subrip" in r2.text


@pytest.mark.anyio
async def test_create_400_invalid_language_tag(async_client, db_session):
    t = await _mk_title(db_session)
    payload = {"language": "en_US", "format": "VTT", "content_type": "text/VTT"}  # underscore invalid
    r = await async_client.post(f"{BASE_TITLES}/{t.id}/subtitles", json=payload)
    assert r.status_code == 400
    assert "Invalid language tag" in r.text


@pytest.mark.anyio
async def test_create_idempotency_replays_snapshot(async_client, db_session):
    t = await _mk_title(db_session)

    payload = {"language": "en", "format": "VTT", "content_type": "text/VTT", "label": "EN"}
    headers = {"Idempotency-Key": "idem-key"}

    r1 = await async_client.post(f"{BASE_TITLES}/{t.id}/subtitles", json=payload, headers=headers)
    r2 = await async_client.post(f"{BASE_TITLES}/{t.id}/subtitles", json=payload, headers=headers)

    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json() == r2.json()

    # Only one subtitle row for this title
    rows = (await db_session.execute(select(Subtitle).where(Subtitle.title_id == t.id))).scalars().all()
    assert len(rows) == 1


@pytest.mark.anyio
async def test_is_default_demotes_previous_default_same_language(async_client, db_session):
    t = await _mk_title(db_session)

    # First default
    r1 = await async_client.post(
        f"{BASE_TITLES}/{t.id}/subtitles",
        json={"language": "en", "format": "VTT", "content_type": "text/VTT", "label": "A", "is_default": True},
    )
    assert r1.status_code == 200
    sub1_id = uuid.UUID(r1.json()["subtitle_id"])

    # Second default in same language → first should be demoted
    r2 = await async_client.post(
        f"{BASE_TITLES}/{t.id}/subtitles",
        json={"language": "en", "format": "VTT", "content_type": "text/VTT", "label": "B", "is_default": True},
    )
    assert r2.status_code == 200
    sub2_id = uuid.UUID(r2.json()["subtitle_id"])

    s1 = (await db_session.execute(select(Subtitle).where(Subtitle.id == sub1_id))).scalar_one()
    s2 = (await db_session.execute(select(Subtitle).where(Subtitle.id == sub2_id))).scalar_one()
    assert s1.is_default is False
    assert s2.is_default is True


@pytest.mark.anyio
async def test_404_when_title_not_found(async_client):
    bad_id = uuid.uuid4()
    payload = {"language": "en", "format": "VTT", "content_type": "text/VTT"}
    r = await async_client.post(f"{BASE_TITLES}/{bad_id}/subtitles", json=payload)
    assert r.status_code == 404
    assert "Title not found" in r.text


@pytest.mark.anyio
async def test_storage_key_format_includes_title_lang_and_id(async_client, db_session):
    t = await _mk_title(db_session)
    r = await async_client.post(
        f"{BASE_TITLES}/{t.id}/subtitles",
        json={"language": "pt-BR", "format": "VTT", "content_type": "text/VTT"},
    )
    assert r.status_code == 200
    key = r.json()["storage_key"]
    # shape: subs/title/{title_id}/pt-BR/{subtitle_id}.VTT
    parts = key.split("/")
    assert parts[0] == "subs" and parts[1] == "title"
    assert parts[2] == str(t.id)
    assert parts[3] == "pt-BR"
    assert parts[4].endswith(".VTT")


@pytest.mark.anyio
async def test_s3_construction_failure_returns_503(async_client, db_session, monkeypatch):
    t = await _mk_title(db_session)

    # Make S3Client() raise S3StorageError at construction time
    import app.api.v1.routers.admin.assets.subtitles as mod
    class _Boom(Exception): ...
    def _raise(*a, **k):  # S3StorageError is handled and surfaced as 503
        raise mod.S3StorageError("S3 unavailable")
    monkeypatch.setattr(mod, "S3Client", _raise)

    r = await async_client.post(
        f"{BASE_TITLES}/{t.id}/subtitles",
        json={"language": "en", "format": "VTT", "content_type": "text/VTT"},
    )
    assert r.status_code == 503
    assert "S3 unavailable" in r.text
