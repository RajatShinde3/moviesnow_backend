import uuid
import pytest
from datetime import datetime, timezone

from sqlalchemy import select, update

from app.schemas.enums import ArtworkKind, TitleType
from app.db.models.title import Title
from app.db.models.artwork import Artwork

BASE = "/api/v1/admin/artwork"  # adjust if your router isn't under /admin


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
        kind=kind,                  # Enum (maps to PG enum artwork_kind)
        language=language,
        region=region,
        content_type="image/jpeg",
        storage_key=f"art/{title_id}/{kind.name.lower()}/{language}/{uuid.uuid4()}.jpg",
        is_primary=is_primary,
        sort_order=sort_order,
    )
    db_session.add(art)
    await db_session.flush()
    await db_session.commit()
    return art


# ─────────────────────────────────────────────────────────────────────────────
# Admin/MFA gates: make them no-ops for tests (keeps focus on business logic)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _mock_admin_mfa(monkeypatch):
    import app.dependencies.admin as admin_deps
    async def _noop(*args, **kwargs): return None
    monkeypatch.setattr(admin_deps, "ensure_admin", _noop)
    monkeypatch.setattr(admin_deps, "ensure_mfa", _noop)


# Ensure auth dependency resolves in tests without real tokens
@pytest.fixture(autouse=True)
async def _override_current_user(app):
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


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Tests                                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.mark.anyio
async def test_patch_updates_basic_fields(async_client, db_session):
    t = await _mk_title(db_session)
    art = await _mk_art(db_session, title_id=t.id, is_primary=False, sort_order=0, language="en")

    payload = {
        "language": "fr",
        "region": "CA",
        "dominant_color": "#112233",
        "focus_x": 0.33,
        "focus_y": 0.66,
        "sort_order": 7,
        "cdn_url": "https://cdn.example.com/x.jpg",
    }
    r = await async_client.patch(f"{BASE}/{art.id}", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["id"] == str(art.id)
    assert data["language"] == "fr"
    assert data["sort_order"] == 7
    assert data["is_primary"] is False

    row = (await db_session.execute(select(Artwork).where(Artwork.id == art.id))).scalar_one()
    assert row.language == "fr"
    assert row.region == "CA"
    assert row.dominant_color == "#112233"
    assert float(row.focus_x) == pytest.approx(0.33, rel=1e-6)
    assert float(row.focus_y) == pytest.approx(0.66, rel=1e-6)
    assert row.sort_order == 7
    assert row.cdn_url == "https://cdn.example.com/x.jpg"


@pytest.mark.anyio
async def test_patch_primary_promotion_demotes_siblings_same_scope_and_lang(async_client, db_session):
    t = await _mk_title(db_session)
    a = await _mk_art(db_session, title_id=t.id, language="en", is_primary=False, sort_order=1)  # A
    b = await _mk_art(db_session, title_id=t.id, language="en", is_primary=True,  sort_order=2)  # B (current primary)
    c = await _mk_art(db_session, title_id=t.id, language="en", is_primary=False, sort_order=3)  # C (to promote)

    r = await async_client.patch(f"{BASE}/{c.id}", json={"is_primary": True})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["is_primary"] is True

    rows = (await db_session.execute(select(Artwork).where(Artwork.title_id == t.id))).scalars().all()
    by_id = {str(x.id): x for x in rows}
    assert by_id[str(a.id)].is_primary is False
    assert by_id[str(b.id)].is_primary is False
    assert by_id[str(c.id)].is_primary is True


@pytest.mark.anyio
async def test_patch_primary_promotion_respects_updated_language_group(async_client, db_session):
    """
    When changing language in the same PATCH and promoting primary,
    demotion applies to siblings in the *new* language group.
    """
    t = await _mk_title(db_session)
    # en group
    en_primary = await _mk_art(db_session, title_id=t.id, language="en", is_primary=True)
    en_other   = await _mk_art(db_session, title_id=t.id, language="en", is_primary=False)
    # fr group
    fr_primary = await _mk_art(db_session, title_id=t.id, language="fr", is_primary=True)
    target     = await _mk_art(db_session, title_id=t.id, language="en", is_primary=False)

    # Move `target` to fr and promote to primary → should demote fr_primary only
    r = await async_client.patch(f"{BASE}/{target.id}", json={"language": "fr", "is_primary": True})
    assert r.status_code == 200, r.text

    rows = (await db_session.execute(select(Artwork).where(Artwork.title_id == t.id))).scalars().all()
    by_id = {str(x.id): x for x in rows}
    # 'en' group unchanged
    assert by_id[str(en_primary.id)].is_primary is True
    assert by_id[str(en_other.id)].is_primary is False
    # 'fr' group: target becomes primary, old fr_primary demoted
    assert by_id[str(target.id)].is_primary is True
    assert by_id[str(fr_primary.id)].is_primary is False


@pytest.mark.anyio
async def test_patch_can_demote_primary_without_affecting_others(async_client, db_session):
    t = await _mk_title(db_session)
    a = await _mk_art(db_session, title_id=t.id, language="en", is_primary=True)
    b = await _mk_art(db_session, title_id=t.id, language="en", is_primary=False)

    r = await async_client.patch(f"{BASE}/{a.id}", json={"is_primary": False})
    assert r.status_code == 200, r.text

    rows = (await db_session.execute(select(Artwork).where(Artwork.title_id == t.id))).scalars().all()
    by_id = {str(x.id): x for x in rows}
    assert by_id[str(a.id)].is_primary is False
    assert by_id[str(b.id)].is_primary is False  # unchanged


@pytest.mark.anyio
async def test_patch_cdn_url_can_be_cleared(async_client, db_session):
    t = await _mk_title(db_session)
    art = await _mk_art(db_session, title_id=t.id, language="en")
    # Set cdn_url first
    await db_session.execute(update(Artwork).where(Artwork.id == art.id).values(cdn_url="https://cdn/foo.jpg"))
    await db_session.commit()

    # Clear by sending empty string (route maps "" → None)
    r = await async_client.patch(f"{BASE}/{art.id}", json={"cdn_url": ""})
    assert r.status_code == 200, r.text

    row = (await db_session.execute(select(Artwork).where(Artwork.id == art.id))).scalar_one()
    assert row.cdn_url is None


@pytest.mark.anyio
async def test_patch_404_when_not_found(async_client):
    missing = uuid.uuid4()
    r = await async_client.patch(f"{BASE}/{missing}", json={"language": "en"})
    assert r.status_code == 404


@pytest.mark.anyio
async def test_patch_language_validation(async_client, db_session):
    t = await _mk_title(db_session)
    art = await _mk_art(db_session, title_id=t.id, language="en")
    # Invalid language should trigger 422 from _validate_language
    r = await async_client.patch(f"{BASE}/{art.id}", json={"language": "zzzzzzzzzzzzzzzzzzz"})
    assert r.status_code in (400, 422), r.text
