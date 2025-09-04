# tests/test_admin/test_subtitles/test_patch_subtitle.py
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
    is_default=False,
    is_forced=False,
    is_sdh=False,
    active=True,
) -> Subtitle:
    a = MediaAsset(
        id=uuid.uuid4(),
        title_id=title_id,
        kind=MediaAssetKind.SUBTITLE,
        language=language,
        mime_type="text/vtt" if fmt == SubtitleFormat.VTT else "application/x-subrip",
        storage_key=f"subs/title/{title_id}/{language}/{uuid.uuid4().hex}.{ 'vtt' if fmt == SubtitleFormat.VTT else 'srt'}",
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
        is_default=is_default,
        is_forced=is_forced,
        is_sdh=is_sdh,
        active=active,
    )
    db_session.add(s)
    await db_session.flush()
    await db_session.commit()
    return s


# ─────────────────────────────────────────────────────────────────────────────
# Autofixed fixtures: admin/MFA bypass & audit mute
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


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Tests                                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.mark.anyio
async def test_patch_updates_label_and_language(async_client, db_session):
    t = await _mk_title(db_session)
    s = await _mk_subtitle(db_session, title_id=t.id, language="en", label="Old")

    payload = {"language": "en-GB", "label": "New Label"}
    r = await async_client.patch(f"/api/v1/admin/subtitles/{s.id}", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["language"] == "en-GB"
    assert data["label"] == "New Label"

    # verify DB
    s_db = (await db_session.execute(select(Subtitle).where(Subtitle.id == s.id))).scalar_one()
    assert s_db.language == "en-GB"
    assert s_db.label == "New Label"


@pytest.mark.anyio
async def test_patch_default_demotes_others_same_language(async_client, db_session):
    t = await _mk_title(db_session)
    s1 = await _mk_subtitle(db_session, title_id=t.id, language="en", is_default=True)
    s2 = await _mk_subtitle(db_session, title_id=t.id, language="en", is_default=False)

    # Make s2 the default → s1 must be demoted
    r = await async_client.patch(f"/api/v1/admin/subtitles/{s2.id}", json={"is_default": True})
    assert r.status_code == 200, r.text

    s1_db = (await db_session.execute(select(Subtitle).where(Subtitle.id == s1.id))).scalar_one()
    s2_db = (await db_session.execute(select(Subtitle).where(Subtitle.id == s2.id))).scalar_one()
    assert s2_db.is_default is True
    assert s1_db.is_default is False


@pytest.mark.anyio
async def test_patch_default_after_language_change_demotes_in_new_scope(async_client, db_session):
    t = await _mk_title(db_session)
    s_en = await _mk_subtitle(db_session, title_id=t.id, language="en", is_default=False)
    s_es_default = await _mk_subtitle(db_session, title_id=t.id, language="es", is_default=True)

    # Change s_en to language "es" and set as default → should demote s_es_default
    r = await async_client.patch(
        f"/api/v1/admin/subtitles/{s_en.id}",
        json={"language": "es", "is_default": True},
    )
    assert r.status_code == 200, r.text

    es_old = (await db_session.execute(select(Subtitle).where(Subtitle.id == s_es_default.id))).scalar_one()
    es_new = (await db_session.execute(select(Subtitle).where(Subtitle.id == s_en.id))).scalar_one()
    assert es_new.language == "es" and es_new.is_default is True
    assert es_old.is_default is False


@pytest.mark.anyio
async def test_patch_flags_toggle_and_active(async_client, db_session):
    t = await _mk_title(db_session)
    s = await _mk_subtitle(db_session, title_id=t.id, language="en", is_forced=False, is_sdh=False, active=True)

    r = await async_client.patch(
        f"/api/v1/admin/subtitles/{s.id}",
        json={"is_forced": True, "is_sdh": True, "active": False, "is_default": True},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["is_forced"] is True
    assert data["is_sdh"] is True
    assert data["active"] is False
    assert data["is_default"] is True

    s_db = (await db_session.execute(select(Subtitle).where(Subtitle.id == s.id))).scalar_one()
    assert s_db.is_forced is True
    assert s_db.is_sdh is True
    assert s_db.active is False
    assert s_db.is_default is True


@pytest.mark.anyio
async def test_patch_label_clear_on_empty_string(async_client, db_session):
    t = await _mk_title(db_session)
    s = await _mk_subtitle(db_session, title_id=t.id, language="en", label="Keep?")

    r = await async_client.patch(f"/api/v1/admin/subtitles/{s.id}", json={"label": ""})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["label"] is None

    s_db = (await db_session.execute(select(Subtitle).where(Subtitle.id == s.id))).scalar_one()
    assert s_db.label is None


@pytest.mark.anyio
async def test_patch_400_no_changes(async_client, db_session):
    t = await _mk_title(db_session)
    s = await _mk_subtitle(db_session, title_id=t.id)

    r = await async_client.patch(f"/api/v1/admin/subtitles/{s.id}", json={})
    assert r.status_code == 400
    assert "No changes provided" in r.text


@pytest.mark.anyio
async def test_patch_404_not_found(async_client):
    r = await async_client.patch(f"/api/v1/admin/subtitles/{uuid.uuid4()}", json={"label": "X"})
    assert r.status_code == 404
    assert "Subtitle not found" in r.text


@pytest.mark.anyio
async def test_patch_400_invalid_language_tag(async_client, db_session):
    t = await _mk_title(db_session)
    s = await _mk_subtitle(db_session, title_id=t.id, language="en")

    r = await async_client.patch(f"/api/v1/admin/subtitles/{s.id}", json={"language": "en_US"})  # underscore invalid
    assert r.status_code == 400
    assert "Invalid language tag" in r.text
