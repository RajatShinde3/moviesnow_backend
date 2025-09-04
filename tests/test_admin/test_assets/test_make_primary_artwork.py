# tests/test_admin/test_assets/test_make_primary_artwork.py

import uuid
import pytest
from sqlalchemy import select

from app.schemas.enums import ArtworkKind, TitleType
from app.db.models.title import Title
from app.db.models.artwork import Artwork

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


async def _mk_art(
    db_session,
    *,
    title_id,
    kind=ArtworkKind.POSTER,
    language="en",
    is_primary=False,
    sort_order=0,
    region=None,
) -> Artwork:
    art = Artwork(
        id=uuid.uuid4(),
        title_id=title_id,
        kind=kind,
        language=language,
        region=region,
        content_type="image/jpeg",
        storage_key=f"art/{title_id}/{kind.name.lower()}/{language or 'none'}/{uuid.uuid4()}.jpg",
        is_primary=is_primary,
        sort_order=sort_order,
    )
    db_session.add(art)
    await db_session.flush()
    await db_session.commit()
    return art


# ─────────────────────────────────────────────────────────────────────────────
# Auth/MFA no-ops + mute audit in tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _mock_admin_mfa(monkeypatch):
    import app.dependencies.admin as admin_deps
    async def _noop(*args, **kwargs): return None
    monkeypatch.setattr(admin_deps, "ensure_admin", _noop)
    monkeypatch.setattr(admin_deps, "ensure_mfa", _noop)


@pytest.fixture(autouse=True)
def _mute_audit(monkeypatch):
    import app.services.audit_log_service as audit
    async def _noaudit(*args, **kwargs): return None
    monkeypatch.setattr(audit, "log_audit_event", _noaudit)


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


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Tests (use tid = t.id ! )                                               ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.mark.anyio
async def test_make_primary_success_demotes_same_scope(async_client, db_session):
    t = await _mk_title(db_session)
    tid = t.id  # capture to avoid MissingGreenlet
    a1 = await _mk_art(db_session, title_id=tid, is_primary=False, language="en")
    a2 = await _mk_art(db_session, title_id=tid, is_primary=True,  language="en")
    a3 = await _mk_art(db_session, title_id=tid, is_primary=False, language="en")

    r = await async_client.post(f"{BASE_TITLES}/{tid}/artwork/{a1.id}/make-primary")
    assert r.status_code == 200, r.text
    assert r.json()["message"] == "Primary set"

    rows = (await db_session.execute(select(Artwork).where(Artwork.title_id == tid))).scalars().all()
    by_id = {str(x.id): x for x in rows}
    assert by_id[str(a1.id)].is_primary is True
    assert by_id[str(a2.id)].is_primary is False
    assert by_id[str(a3.id)].is_primary is False


@pytest.mark.anyio
async def test_make_primary_keeps_other_language_primary(async_client, db_session):
    t = await _mk_title(db_session)
    tid = t.id
    en1 = await _mk_art(db_session, title_id=tid, language="en", is_primary=False)
    en2 = await _mk_art(db_session, title_id=tid, language="en", is_primary=True)
    fr1 = await _mk_art(db_session, title_id=tid, language="fr", is_primary=True)

    r = await async_client.post(f"{BASE_TITLES}/{tid}/artwork/{en1.id}/make-primary")
    assert r.status_code == 200, r.text

    rows = (await db_session.execute(select(Artwork).where(Artwork.title_id == tid))).scalars().all()
    by_id = {str(x.id): x for x in rows}
    assert by_id[str(en1.id)].is_primary is True
    assert by_id[str(en2.id)].is_primary is False
    assert by_id[str(fr1.id)].is_primary is True  # untouched (different language)


@pytest.mark.anyio
async def test_make_primary_keeps_other_kind_primary(async_client, db_session):
    t = await _mk_title(db_session)
    tid = t.id
    poster = await _mk_art(db_session, title_id=tid, kind=ArtworkKind.POSTER, language="en", is_primary=False)
    poster_other = await _mk_art(db_session, title_id=tid, kind=ArtworkKind.POSTER, language="en", is_primary=True)
    backdrop = await _mk_art(db_session, title_id=tid, kind=ArtworkKind.BACKDROP, language="en", is_primary=True)

    r = await async_client.post(f"{BASE_TITLES}/{tid}/artwork/{poster.id}/make-primary")
    assert r.status_code == 200, r.text

    rows = (await db_session.execute(select(Artwork).where(Artwork.title_id == tid))).scalars().all()
    by_id = {str(x.id): x for x in rows}
    assert by_id[str(poster.id)].is_primary is True
    assert by_id[str(poster_other.id)].is_primary is False
    assert by_id[str(backdrop.id)].is_primary is True  # untouched (different kind)


@pytest.mark.anyio
async def test_make_primary_404_when_artwork_not_for_title(async_client, db_session):
    t1 = await _mk_title(db_session); tid1 = t1.id
    t2 = await _mk_title(db_session); tid2 = t2.id
    foreign = await _mk_art(db_session, title_id=tid2, is_primary=False)

    r = await async_client.post(f"{BASE_TITLES}/{tid1}/artwork/{foreign.id}/make-primary")
    assert r.status_code == 404
    assert "Artwork not found for this title" in r.text


@pytest.mark.anyio
async def test_make_primary_404_when_artwork_missing(async_client, db_session):
    t = await _mk_title(db_session)
    tid = t.id
    missing_id = uuid.uuid4()

    r = await async_client.post(f"{BASE_TITLES}/{tid}/artwork/{missing_id}/make-primary")
    assert r.status_code == 404
    assert "Artwork not found" in r.text


@pytest.mark.anyio
async def test_make_primary_with_null_language_demotes_all_languages_same_kind(async_client, db_session):
    """If chosen artwork.language is NULL, route omits language filter → demotes all languages for that kind."""
    t = await _mk_title(db_session)
    tid = t.id
    none_lang = await _mk_art(db_session, title_id=tid, language=None, is_primary=False)
    en = await _mk_art(db_session, title_id=tid, language="en", is_primary=True)
    fr = await _mk_art(db_session, title_id=tid, language="fr", is_primary=True)

    r = await async_client.post(f"{BASE_TITLES}/{tid}/artwork/{none_lang.id}/make-primary")
    assert r.status_code == 200, r.text

    rows = (await db_session.execute(select(Artwork).where(Artwork.title_id == tid))).scalars().all()
    by_id = {str(x.id): x for x in rows}
    assert by_id[str(none_lang.id)].is_primary is True
    assert by_id[str(en.id)].is_primary is False
    assert by_id[str(fr.id)].is_primary is False
