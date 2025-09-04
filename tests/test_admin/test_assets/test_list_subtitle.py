# tests/test_admin/test_subtitles/test_list_subtitles.py
import uuid
import pytest
from datetime import datetime, timedelta, timezone
from sqlalchemy import select, update

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


async def _mk_subtitle(
    db_session,
    *,
    title_id,
    language="en",
    fmt=SubtitleFormat.VTT,
    active=True,
    label=None,
):
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
        is_default=False,
        is_forced=False,
        is_sdh=False,
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
async def test_list_returns_newest_first_and_shape(async_client, db_session):
    t = await _mk_title(db_session)

    # create three subs, then stamp created_at to control ordering
    s1 = await _mk_subtitle(db_session, title_id=t.id, language="en", fmt=SubtitleFormat.VTT, label="A")
    s2 = await _mk_subtitle(db_session, title_id=t.id, language="en-US", fmt=SubtitleFormat.SRT, label="B")
    s3 = await _mk_subtitle(db_session, title_id=t.id, language="es", fmt=SubtitleFormat.VTT, label="C")

    base = datetime.now(timezone.utc)
    # oldest → newest
    await db_session.execute(update(Subtitle).where(Subtitle.id == s1.id).values(created_at=base - timedelta(minutes=2)))
    await db_session.execute(update(Subtitle).where(Subtitle.id == s2.id).values(created_at=base - timedelta(minutes=1)))
    await db_session.execute(update(Subtitle).where(Subtitle.id == s3.id).values(created_at=base))
    await db_session.commit()

    r = await async_client.get(f"{BASE_TITLES}/{t.id}/subtitles")
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data, list) and len(data) == 3

    # newest first → s3, then s2, then s1
    ids = [uuid.UUID(d["id"]) for d in data]
    assert ids == [s3.id, s2.id, s1.id]

    # shape
    row = data[0]
    for k in ("id", "asset_id", "title_id", "language", "format", "label",
              "is_default", "is_forced", "is_sdh", "active"):
        assert k in row
    assert row["active"] is True


@pytest.mark.anyio
async def test_list_filter_by_language_case_insensitive(async_client, db_session):
    t = await _mk_title(db_session)
    s_enus = await _mk_subtitle(db_session, title_id=t.id, language="en-US", fmt=SubtitleFormat.VTT)
    await _mk_subtitle(db_session, title_id=t.id, language="es", fmt=SubtitleFormat.SRT)

    # Query with mixed case; route lower-cases and validates BCP-47
    r = await async_client.get(f"{BASE_TITLES}/{t.id}/subtitles", params={"language": "EN-us"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert len(data) == 1
    assert uuid.UUID(data[0]["id"]) == s_enus.id
    assert data[0]["language"] == "en-US"


@pytest.mark.anyio
async def test_list_active_only(async_client, db_session):
    t = await _mk_title(db_session)
    s_active = await _mk_subtitle(db_session, title_id=t.id, language="en", active=True)
    await _mk_subtitle(db_session, title_id=t.id, language="en-GB", active=False)

    r = await async_client.get(f"{BASE_TITLES}/{t.id}/subtitles", params={"active_only": True})
    assert r.status_code == 200, r.text
    data = r.json()
    assert len(data) == 1
    assert uuid.UUID(data[0]["id"]) == s_active.id
    assert data[0]["active"] is True


@pytest.mark.anyio
async def test_list_pagination_limit_offset(async_client, db_session):
    t = await _mk_title(db_session)
    s1 = await _mk_subtitle(db_session, title_id=t.id, language="en")
    s2 = await _mk_subtitle(db_session, title_id=t.id, language="en-US")
    s3 = await _mk_subtitle(db_session, title_id=t.id, language="es")

    base = datetime.now(timezone.utc)
    await db_session.execute(update(Subtitle).where(Subtitle.id == s1.id).values(created_at=base - timedelta(minutes=2)))
    await db_session.execute(update(Subtitle).where(Subtitle.id == s2.id).values(created_at=base - timedelta(minutes=1)))
    await db_session.execute(update(Subtitle).where(Subtitle.id == s3.id).values(created_at=base))
    await db_session.commit()

    # Newest order: s3, s2, s1 → offset=1, limit=1 should return s2
    r = await async_client.get(f"{BASE_TITLES}/{t.id}/subtitles", params={"limit": 1, "offset": 1})
    assert r.status_code == 200, r.text
    data = r.json()
    assert len(data) == 1
    assert uuid.UUID(data[0]["id"]) == s2.id


@pytest.mark.anyio
async def test_list_404_when_title_not_found(async_client):
    bad_id = uuid.uuid4()
    r = await async_client.get(f"{BASE_TITLES}/{bad_id}/subtitles")
    assert r.status_code == 404
    assert "Title not found" in r.text


@pytest.mark.anyio
async def test_list_400_on_invalid_language_tag(async_client, db_session):
    t = await _mk_title(db_session)
    r = await async_client.get(f"{BASE_TITLES}/{t.id}/subtitles", params={"language": "en_US"})  # underscore invalid
    assert r.status_code == 400
    assert "Invalid language tag" in r.text
