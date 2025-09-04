# tests/test_admin/test_assets/test_patch_trailer.py

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
    content_type="video/mp4",
    is_primary=False,
    label=None,
) -> MediaAsset:
    meta = {"label": label} if label else None
    asset = MediaAsset(
        id=uuid.uuid4(),
        title_id=title_id,
        kind=MediaAssetKind.TRAILER,
        language=language,
        mime_type=content_type,
        is_primary=is_primary,
        metadata_json=meta,
        storage_key=f"video/title/{title_id}/trailers/{(language or 'und')}/{uuid.uuid4()}.mp4",
    )
    db_session.add(asset)
    await db_session.flush()
    await db_session.commit()
    return asset


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
async def test_patch_trailer_update_language(async_client, db_session):
    t = await _mk_title(db_session)
    m = await _mk_trailer(db_session, title_id=t.id, language="en")
    r = await async_client.patch(
        f"{BASE_ADMIN}/trailers/{m.id}",
        json={"language": "fr"},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["id"] == str(m.id)
    assert data["language"] == "fr"

    # Verify persisted
    row = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == m.id))).scalar_one()
    assert row.language == "fr"


@pytest.mark.anyio
async def test_patch_trailer_invalid_language_400(async_client, db_session):
    t = await _mk_title(db_session)
    m = await _mk_trailer(db_session, title_id=t.id, language="en")
    r = await async_client.patch(f"{BASE_ADMIN}/trailers/{m.id}", json={"language": "english"})
    assert r.status_code == 400
    assert "Invalid language" in r.text


@pytest.mark.anyio
async def test_patch_trailer_make_primary_demotes_siblings_same_scope(async_client, db_session):
    t = await _mk_title(db_session)
    a = await _mk_trailer(db_session, title_id=t.id, language="en", is_primary=True)
    b = await _mk_trailer(db_session, title_id=t.id, language="en", is_primary=False)

    # Make b primary; a should be demoted
    r = await async_client.patch(f"{BASE_ADMIN}/trailers/{b.id}", json={"is_primary": True})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["is_primary"] is True

    rows = (await db_session.execute(
        select(MediaAsset).where(MediaAsset.id.in_([a.id, b.id]))
    )).scalars().all()
    by_id = {str(x.id): x for x in rows}
    assert by_id[str(a.id)].is_primary is False
    assert by_id[str(b.id)].is_primary is True


@pytest.mark.anyio
async def test_patch_trailer_primary_change_scoped_to_new_language_when_language_changes(async_client, db_session):
    t = await _mk_title(db_session)
    # en group
    en1 = await _mk_trailer(db_session, title_id=t.id, language="en", is_primary=True)
    en2 = await _mk_trailer(db_session, title_id=t.id, language="en", is_primary=False)
    # fr group
    fr1 = await _mk_trailer(db_session, title_id=t.id, language="fr", is_primary=True)

    # Move en2 to fr and make it primary → should demote fr1 but not touch en1
    r = await async_client.patch(
        f"{BASE_ADMIN}/trailers/{en2.id}",
        json={"language": "fr", "is_primary": True},
    )
    assert r.status_code == 200, r.text

    rows = (await db_session.execute(
        select(MediaAsset).where(MediaAsset.id.in_([en1.id, en2.id, fr1.id]))
    )).scalars().all()
    by_id = {str(x.id): x for x in rows}

    # en group unchanged
    assert by_id[str(en1.id)].is_primary is True
    # fr group: en2 (now fr) is primary; fr1 demoted
    assert by_id[str(en2.id)].language == "fr"
    assert by_id[str(en2.id)].is_primary is True
    assert by_id[str(fr1.id)].is_primary is False


@pytest.mark.anyio
async def test_patch_trailer_unset_primary_does_not_affect_others(async_client, db_session):
    t = await _mk_title(db_session)
    a = await _mk_trailer(db_session, title_id=t.id, language="en", is_primary=True)
    b = await _mk_trailer(db_session, title_id=t.id, language="en", is_primary=False)

    r = await async_client.patch(f"{BASE_ADMIN}/trailers/{a.id}", json={"is_primary": False})
    assert r.status_code == 200
    rows = (await db_session.execute(
        select(MediaAsset).where(MediaAsset.id.in_([a.id, b.id]))
    )).scalars().all()
    by_id = {str(x.id): x for x in rows}
    assert by_id[str(a.id)].is_primary is False
    # b stays non-primary
    assert by_id[str(b.id)].is_primary is False


@pytest.mark.anyio
async def test_patch_trailer_set_and_clear_label(async_client, db_session):
    t = await _mk_title(db_session)
    m = await _mk_trailer(db_session, title_id=t.id, language="en", is_primary=False)

    # Set label
    r1 = await async_client.patch(f"{BASE_ADMIN}/trailers/{m.id}", json={"label": "Official Trailer"})
    assert r1.status_code == 200, r1.text
    assert r1.json()["label"] == "Official Trailer"

    # Clear label with empty string
    r2 = await async_client.patch(f"{BASE_ADMIN}/trailers/{m.id}", json={"label": ""})
    assert r2.status_code == 200
    assert r2.json()["label"] is None

    # Persisted check
    row = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == m.id))).scalar_one()
    assert (row.metadata_json or {}).get("label") is None


@pytest.mark.anyio
async def test_patch_trailer_not_found(async_client):
    missing = uuid.uuid4()
    r = await async_client.patch(f"{BASE_ADMIN}/trailers/{missing}", json={"is_primary": True})
    assert r.status_code == 404
    assert "Trailer not found" in r.text
