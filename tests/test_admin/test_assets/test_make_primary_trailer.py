# tests/test_admin/test_assets/test_make_primary_trailer.py

import uuid
import pytest
from sqlalchemy import select

from app.schemas.enums import TitleType, MediaAssetKind
from app.db.models.title import Title
from app.db.models.media_asset import MediaAsset

BASE_ADMIN = "/api/v1/admin"


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

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


async def _mk_trailer(
    db_session,
    *,
    title_id,
    language=None,
    is_primary=False,
    content_type="video/mp4",
    label=None,
) -> MediaAsset:
    meta = {"label": label} if label else None
    m = MediaAsset(
        id=uuid.uuid4(),
        title_id=title_id,
        kind=MediaAssetKind.TRAILER,
        language=language,
        mime_type=content_type,
        is_primary=is_primary,
        metadata_json=meta,
        storage_key=f"video/title/{title_id}/trailers/{(language or 'und')}/{uuid.uuid4()}.mp4",
    )
    db_session.add(m)
    await db_session.flush()
    await db_session.commit()
    return m


# ────────────────────────────────────────────────────────────────────────────
# Test scaffolding (auth / MFA / audit)
# ────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _mock_admin_mfa(monkeypatch):
    import app.dependencies.admin as admin_deps
    async def _noop(*args, **kwargs): return None
    monkeypatch.setattr(admin_deps, "ensure_admin", _noop)
    monkeypatch.setattr(admin_deps, "ensure_mfa", _noop)


@pytest.fixture(autouse=True)
async def _override_current_user(app):
    from app.core.security import get_current_user
    import uuid as _uuid
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


@pytest.fixture(autouse=True)
def _suppress_audit_logs(monkeypatch):
    import app.services.audit_log_service as audit_mod
    async def _noop(*args, **kwargs): return None
    monkeypatch.setattr(audit_mod, "log_audit_event", _noop)


# ────────────────────────────────────────────────────────────────────────────
# Tests
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_make_primary_success_demotes_same_language_scope(async_client, db_session):
    t = await _mk_title(db_session)
    en_primary = await _mk_trailer(db_session, title_id=t.id, language="en", is_primary=True)
    en_other = await _mk_trailer(db_session, title_id=t.id, language="en", is_primary=False)

    r = await async_client.post(f"{BASE_ADMIN}/titles/{t.id}/trailers/{en_other.id}/make-primary")
    assert r.status_code == 200, r.text
    assert r.json()["message"] == "Primary set"

    rows = (await db_session.execute(
        select(MediaAsset).where(MediaAsset.id.in_([en_primary.id, en_other.id]))
    )).scalars().all()
    by_id = {str(x.id): x for x in rows}
    assert by_id[str(en_other.id)].is_primary is True
    assert by_id[str(en_primary.id)].is_primary is False


@pytest.mark.anyio
async def test_make_primary_keeps_other_language_primary(async_client, db_session):
    t = await _mk_title(db_session)
    en_primary = await _mk_trailer(db_session, title_id=t.id, language="en", is_primary=True)
    en_other = await _mk_trailer(db_session, title_id=t.id, language="en", is_primary=False)
    fr_primary = await _mk_trailer(db_session, title_id=t.id, language="fr", is_primary=True)

    # Promote the non-primary English trailer
    r = await async_client.post(f"{BASE_ADMIN}/titles/{t.id}/trailers/{en_other.id}/make-primary")
    assert r.status_code == 200, r.text

    rows = (await db_session.execute(
        select(MediaAsset).where(MediaAsset.id.in_([en_primary.id, en_other.id, fr_primary.id]))
    )).scalars().all()
    by_id = {str(x.id): x for x in rows}

    # English: new one is primary, old one demoted
    assert by_id[str(en_other.id)].is_primary is True
    assert by_id[str(en_primary.id)].is_primary is False
    # French: untouched
    assert by_id[str(fr_primary.id)].is_primary is True


@pytest.mark.anyio
async def test_make_primary_with_null_language_demotes_all_languages_same_title(async_client, db_session):
    """If target trailer has NULL language, endpoint demotes all trailers for the title."""
    t = await _mk_title(db_session)
    en_primary = await _mk_trailer(db_session, title_id=t.id, language="en", is_primary=True)
    fr_primary = await _mk_trailer(db_session, title_id=t.id, language="fr", is_primary=True)
    null_lang = await _mk_trailer(db_session, title_id=t.id, language=None, is_primary=False)

    r = await async_client.post(f"{BASE_ADMIN}/titles/{t.id}/trailers/{null_lang.id}/make-primary")
    assert r.status_code == 200, r.text

    rows = (await db_session.execute(
        select(MediaAsset).where(MediaAsset.title_id == t.id, MediaAsset.kind == MediaAssetKind.TRAILER)
    )).scalars().all()
    by_id = {str(x.id): x for x in rows}
    assert by_id[str(null_lang.id)].is_primary is True
    # Both language groups were demoted because target language is NULL
    assert by_id[str(en_primary.id)].is_primary is False
    assert by_id[str(fr_primary.id)].is_primary is False


@pytest.mark.anyio
async def test_make_primary_404_when_trailer_not_for_title(async_client, db_session):
    t1 = await _mk_title(db_session)
    t2 = await _mk_title(db_session)
    foreign = await _mk_trailer(db_session, title_id=t2.id, language="en", is_primary=True)

    r = await async_client.post(f"{BASE_ADMIN}/titles/{t1.id}/trailers/{foreign.id}/make-primary")
    assert r.status_code == 404
    assert "not found" in r.text.lower()
