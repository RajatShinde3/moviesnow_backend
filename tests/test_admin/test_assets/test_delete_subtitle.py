# tests/test_admin/test_subtitles/test_delete_subtitle.py
import uuid
import pytest
from sqlalchemy import select

from app.db.models.title import Title
from app.db.models.media_asset import MediaAsset
from app.db.models.subtitle import Subtitle
from app.schemas.enums import TitleType, MediaAssetKind, SubtitleFormat


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


async def _mk_subtitle(
    db_session,
    *,
    title_id,
    language="en",
    fmt=SubtitleFormat.VTT,
    label=None,
    storage_key=None,
) -> Subtitle:
    if storage_key is None:
        ext = "vtt" if fmt == SubtitleFormat.VTT else "srt"
        storage_key = f"subs/title/{title_id}/{language}/{uuid.uuid4().hex}.{ext}"

    a = MediaAsset(
        id=uuid.uuid4(),
        title_id=title_id,
        kind=MediaAssetKind.SUBTITLE,
        language=language,
        mime_type="text/vtt" if fmt == SubtitleFormat.VTT else "application/x-subrip",
        storage_key=storage_key,
    )
    db_session.add(a)
    await db_session.flush()

    s = Subtitle(
        id=uuid.uuid4(),
        title_id=title_id,
        asset_id=a.id,
        language=language,
        format=fmt,
        label=label,
        is_default=False,
        is_forced=False,
        is_sdh=False,
        active=True,
    )
    db_session.add(s)
    await db_session.flush()
    await db_session.commit()
    return s


# ─────────────────────────────────────────────────────────────────────────────
# Global fixtures: admin/MFA bypass, audit mute
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


# ─────────────────────────────────────────────────────────────────────────────
# S3 stub
# ─────────────────────────────────────────────────────────────────────────────

class _S3Stub:
    def __init__(self, should_raise=False, calls=None):
        self.should_raise = should_raise
        self.calls = calls if calls is not None else []

    def delete(self, key: str):
        self.calls.append(key)
        if self.should_raise:
            raise RuntimeError("boom")


@pytest.fixture
def s3_stub(monkeypatch):
    calls = []
    stub = _S3Stub(should_raise=False, calls=calls)

    # Patch the function as imported/used in the router module
    import app.api.v1.routers.admin.assets.subtitles as mod
    def _ensure_s3_stub():
        return stub
    monkeypatch.setattr(mod, "_ensure_s3", _ensure_s3_stub)
    return stub


@pytest.fixture
def s3_stub_raises(monkeypatch):
    stub = _S3Stub(should_raise=True, calls=[])

    import app.api.v1.routers.admin.assets.subtitles as mod
    def _ensure_s3_stub():
        return stub
    monkeypatch.setattr(mod, "_ensure_s3", _ensure_s3_stub)
    return stub


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Tests                                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.mark.anyio
async def test_delete_subtitle_200_then_404(async_client, db_session, s3_stub):
    t = await _mk_title(db_session)
    s = await _mk_subtitle(db_session, title_id=t.id, language="en")

    # First delete → 200 + rows gone
    r1 = await async_client.delete(f"/api/v1/admin/subtitles/{s.id}")
    assert r1.status_code == 200, r1.text
    assert r1.json().get("message") == "Subtitle deleted"
    # cache hardened
    assert r1.headers.get("Cache-Control") == "no-store"

    s_row = (await db_session.execute(select(Subtitle).where(Subtitle.id == s.id))).scalar_one_or_none()
    assert s_row is None
    a_row = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == s.asset_id))).scalar_one_or_none()
    assert a_row is None

    # Second delete → 404
    r2 = await async_client.delete(f"/api/v1/admin/subtitles/{s.id}")
    assert r2.status_code == 404
    assert "Subtitle not found" in r2.text


@pytest.mark.anyio
async def test_delete_subtitle_purges_storage_when_key_present(async_client, db_session, s3_stub):
    t = await _mk_title(db_session)
    s = await _mk_subtitle(db_session, title_id=t.id, language="es")

    # Capture the key before deletion for assertion
    key = (await db_session.execute(select(MediaAsset.storage_key).where(MediaAsset.id == s.asset_id))).scalar_one()

    r = await async_client.delete(f"/api/v1/admin/subtitles/{s.id}")
    assert r.status_code == 200, r.text

    # Best-effort purge called with the asset key
    assert s3_stub.calls == [key]


@pytest.mark.anyio
async def test_delete_subtitle_swallows_storage_errors(async_client, db_session, s3_stub_raises):
    t = await _mk_title(db_session)
    s = await _mk_subtitle(db_session, title_id=t.id, language="fr")

    r = await async_client.delete(f"/api/v1/admin/subtitles/{s.id}")
    # Despite S3 error, endpoint still returns 200 and DB rows are gone
    assert r.status_code == 200, r.text

    s_row = (await db_session.execute(select(Subtitle).where(Subtitle.id == s.id))).scalar_one_or_none()
    a_row = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == s.asset_id))).scalar_one_or_none()
    assert s_row is None and a_row is None
    assert s3_stub_raises.calls and isinstance(s3_stub_raises.calls[0], str)


@pytest.mark.anyio
async def test_delete_subtitle_404_when_missing(async_client):
    r = await async_client.delete(f"/api/v1/admin/subtitles/{uuid.uuid4()}")
    assert r.status_code == 404
    assert "Subtitle not found" in r.text


@pytest.mark.anyio
async def test_delete_subtitle_no_storage_purge_when_no_key(async_client, db_session, s3_stub):
    t = await _mk_title(db_session)
    # Create with a None storage_key
    s = await _mk_subtitle(db_session, title_id=t.id, language="de", storage_key=None)

    # Manually null the key on the asset to simulate missing key
    await db_session.execute(
        select(MediaAsset).where(MediaAsset.id == s.asset_id)
    )
    asset = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == s.asset_id))).scalar_one()
    asset.storage_key = None
    await db_session.flush()
    await db_session.commit()

    r = await async_client.delete(f"/api/v1/admin/subtitles/{s.id}")
    assert r.status_code == 200, r.text
    # No delete call when key is missing
    assert s3_stub.calls == []
