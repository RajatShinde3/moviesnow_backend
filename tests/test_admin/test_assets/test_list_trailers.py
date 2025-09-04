# tests/test_admin/test_assets/test_list_trailers.py

import uuid
import pytest
from sqlalchemy import select

from app.schemas.enums import TitleType, MediaAssetKind
from app.db.models.title import Title
from app.db.models.media_asset import MediaAsset

BASE_TITLES = "/api/v1/admin/titles"


# ────────────────────────────────────────────────────────────────────────────
# Common helpers
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
        mime_type=content_type,  # some schemas use mime_type; route also falls back to content_type
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
    # Skip real admin/MFA for focused behavior tests
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
    # Defensive: if list path ever adds audit, keep tests isolated.
    import app.services.audit_log_service as audit_mod
    async def _noop(*args, **kwargs): return None
    monkeypatch.setattr(audit_mod, "log_audit_event", _noop)


# ────────────────────────────────────────────────────────────────────────────
# Tests
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_list_trailers_returns_empty_when_none(async_client, db_session):
    t = await _mk_title(db_session)
    r = await async_client.get(f"{BASE_TITLES}/{t.id}/trailers")
    assert r.status_code == 200, r.text
    assert r.json() == []


@pytest.mark.anyio
async def test_list_trailers_newest_first(async_client, db_session):
    t = await _mk_title(db_session)
    # Create in sequence; created_at desc should return last created first
    a1 = await _mk_trailer(db_session, title_id=t.id, language="en", label="T1")
    a2 = await _mk_trailer(db_session, title_id=t.id, language="en", label="T2")
    a3 = await _mk_trailer(db_session, title_id=t.id, language="en", label="T3")
    r = await async_client.get(f"{BASE_TITLES}/{t.id}/trailers")
    assert r.status_code == 200
    ids = [row["id"] for row in r.json()]
    # newest first => a3, a2, a1
    assert ids == [str(a3.id), str(a2.id), str(a1.id)]


@pytest.mark.anyio
async def test_list_trailers_filter_by_language_case_insensitive(async_client, db_session):
    t = await _mk_title(db_session)
    a_en = await _mk_trailer(db_session, title_id=t.id, language="en-US")
    await _mk_trailer(db_session, title_id=t.id, language="fr")
    r = await async_client.get(f"{BASE_TITLES}/{t.id}/trailers", params={"language": "en-us"})
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["id"] == str(a_en.id)
    assert data[0]["language"] == "en-US"


@pytest.mark.anyio
async def test_list_trailers_only_primary_true(async_client, db_session):
    t = await _mk_title(db_session)
    # Mix of primary/non-primary across languages
    a1 = await _mk_trailer(db_session, title_id=t.id, language="en", is_primary=True)
    await _mk_trailer(db_session, title_id=t.id, language="en", is_primary=False)
    a3 = await _mk_trailer(db_session, title_id=t.id, language="fr", is_primary=True)

    # Only primary across all languages
    r = await async_client.get(f"{BASE_TITLES}/{t.id}/trailers", params={"only_primary": True})
    assert r.status_code == 200
    got_ids = {row["id"] for row in r.json()}
    assert got_ids == {str(a1.id), str(a3.id)}

    # Only primary for a specific language
    r2 = await async_client.get(
        f"{BASE_TITLES}/{t.id}/trailers",
        params={"only_primary": True, "language": "fr"},
    )
    assert r2.status_code == 200
    data2 = r2.json()
    assert len(data2) == 1 and data2[0]["id"] == str(a3.id)


@pytest.mark.anyio
async def test_list_trailers_pagination_limit_offset(async_client, db_session):
    t = await _mk_title(db_session)
    a1 = await _mk_trailer(db_session, title_id=t.id, language="en")
    a2 = await _mk_trailer(db_session, title_id=t.id, language="en")
    a3 = await _mk_trailer(db_session, title_id=t.id, language="en")

    # Newest first is [a3, a2, a1]
    r1 = await async_client.get(f"{BASE_TITLES}/{t.id}/trailers", params={"limit": 2, "offset": 0})
    assert r1.status_code == 200
    ids1 = [row["id"] for row in r1.json()]
    assert ids1 == [str(a3.id), str(a2.id)]

    r2 = await async_client.get(f"{BASE_TITLES}/{t.id}/trailers", params={"limit": 2, "offset": 2})
    assert r2.status_code == 200
    ids2 = [row["id"] for row in r2.json()]
    assert ids2 == [str(a1.id)]


@pytest.mark.anyio
async def test_list_trailers_invalid_language_400(async_client, db_session):
    t = await _mk_title(db_session)
    # Bad BCP-47 → route calls _validate_language and raises 400
    r = await async_client.get(f"{BASE_TITLES}/{t.id}/trailers", params={"language": "english"})
    assert r.status_code == 400
    assert "Invalid language" in r.text


@pytest.mark.anyio
async def test_list_trailers_title_not_found(async_client):
    missing = uuid.uuid4()
    r = await async_client.get(f"{BASE_TITLES}/{missing}/trailers")
    assert r.status_code == 404
    assert "Title not found" in r.text


@pytest.mark.anyio
async def test_list_trailers_response_shape_includes_label_and_content_type(async_client, db_session):
    t = await _mk_title(db_session)
    a = await _mk_trailer(
        db_session,
        title_id=t.id,
        language="en-GB",
        content_type="video/webm",
        label="Official Trailer",
        is_primary=True,
    )
    r = await async_client.get(f"{BASE_TITLES}/{t.id}/trailers")
    assert r.status_code == 200
    row = r.json()[0]
    assert row["id"] == str(a.id)
    assert row["title_id"] == str(t.id)
    assert row["language"] == "en-GB"
    assert row["content_type"] == "video/webm"
    assert row["is_primary"] is True
    assert row["label"] == "Official Trailer"
