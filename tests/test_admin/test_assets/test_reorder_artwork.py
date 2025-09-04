# tests/test_admin/test_assets/test_reorder_artwork.py

import uuid
import pytest
from sqlalchemy import select

from app.schemas.enums import ArtworkKind, TitleType
from app.db.models.title import Title
from app.db.models.artwork import Artwork

BASE_TITLES = "/api/v1/admin/titles"

# ─────────────────────────────────────────────────────────────────────────────
# New: mute audit writer (avoids FK violations and noisy logs)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _mute_audit(monkeypatch):
    import app.services.audit_log_service as audit
    async def _noop(*args, **kwargs):
        return None
    monkeypatch.setattr(audit, "log_audit_event", _noop)

# ─────────────────────────────────────────────────────────────────────────────
# Keep your admin/MFA overrides as you had them
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
    import uuid as _uuid
    async def _test_user_dep():
        class _U:
            id = _uuid.uuid4()      # not persisted; OK because auditing is muted
            is_superuser = True
        return _U()
    app.dependency_overrides[get_current_user] = _test_user_dep
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_current_user, None)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers: return lightweight objects with only the IDs (avoid expired loads)
# ─────────────────────────────────────────────────────────────────────────────
from types import SimpleNamespace

async def _mk_title(db_session) -> SimpleNamespace:
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
    tid = t.id                # freeze before commit to avoid expired attribute load
    await db_session.commit() # committed so the API's own session can see it
    return SimpleNamespace(id=tid)

async def _mk_art(
    db_session,
    *,
    title_id,
    kind=ArtworkKind.POSTER,
    language="en",
    is_primary=False,
    sort_order=0,
    region=None,
) -> SimpleNamespace:
    art = Artwork(
        id=uuid.uuid4(),
        title_id=title_id,
        kind=kind,
        language=language,
        region=region,
        content_type="image/jpeg",
        storage_key=f"art/{title_id}/{str(kind).split('.')[-1].lower()}/{language}/{uuid.uuid4()}.jpg",
        is_primary=is_primary,
        sort_order=sort_order,
    )
    db_session.add(art)
    await db_session.flush()
    aid = art.id              # freeze before commit
    await db_session.commit()
    return SimpleNamespace(id=aid)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Tests                                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════╝

@pytest.mark.anyio
async def test_reorder_success_updates_all_specified(async_client, db_session):
    t = await _mk_title(db_session)
    a1 = await _mk_art(db_session, title_id=t.id, sort_order=10)
    a2 = await _mk_art(db_session, title_id=t.id, sort_order=20)
    a3 = await _mk_art(db_session, title_id=t.id, sort_order=30)

    order = [str(a3.id), str(a2.id), str(a1.id)]  # front→back
    r = await async_client.post(f"{BASE_TITLES}/{t.id}/artwork/reorder", json={"order": order})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["message"] == "Reordered"
    assert data["count"] == len(order)

    rows = (await db_session.execute(select(Artwork).where(Artwork.title_id == t.id))).scalars().all()
    by_id = {str(x.id): x for x in rows}
    assert by_id[str(a3.id)].sort_order == 0
    assert by_id[str(a2.id)].sort_order == 1
    assert by_id[str(a1.id)].sort_order == 2

@pytest.mark.anyio
async def test_reorder_partial_list_only_touches_those_ids(async_client, db_session):
    t = await _mk_title(db_session)
    a1 = await _mk_art(db_session, title_id=t.id, sort_order=0)
    a2 = await _mk_art(db_session, title_id=t.id, sort_order=1)
    a3 = await _mk_art(db_session, title_id=t.id, sort_order=2)
    a4 = await _mk_art(db_session, title_id=t.id, sort_order=3)

    order = [str(a4.id), str(a2.id)]
    r = await async_client.post(f"{BASE_TITLES}/{t.id}/artwork/reorder", json={"order": order})
    assert r.status_code == 200, r.text

    rows = (await db_session.execute(select(Artwork).where(Artwork.title_id == t.id))).scalars().all()
    by_id = {str(x.id): x for x in rows}
    assert by_id[str(a4.id)].sort_order == 0
    assert by_id[str(a2.id)].sort_order == 1
    # Unmentioned ones unchanged
    assert by_id[str(a1.id)].sort_order == 0
    assert by_id[str(a3.id)].sort_order == 2

@pytest.mark.anyio
async def test_reorder_errors_on_empty_list(async_client, db_session):
    t = await _mk_title(db_session)
    r = await async_client.post(f"{BASE_TITLES}/{t.id}/artwork/reorder", json={"order": []})
    assert r.status_code == 400, r.text
    assert "Provide at least one artwork id" in r.text

@pytest.mark.anyio
async def test_reorder_errors_when_id_not_for_title(async_client, db_session):
    t1 = await _mk_title(db_session)
    t2 = await _mk_title(db_session)
    a1 = await _mk_art(db_session, title_id=t1.id, sort_order=0)
    foreign = await _mk_art(db_session, title_id=t2.id, sort_order=0)

    r = await async_client.post(
        f"{BASE_TITLES}/{t1.id}/artwork/reorder",
        json={"order": [str(a1.id), str(foreign.id)]},
    )
    assert r.status_code == 400, r.text
    assert str(foreign.id) in r.text

@pytest.mark.anyio
async def test_reorder_with_duplicate_ids_last_position_applies(async_client, db_session):
    t = await _mk_title(db_session)
    a1 = await _mk_art(db_session, title_id=t.id, sort_order=0)
    a2 = await _mk_art(db_session, title_id=t.id, sort_order=1)

    order = [str(a1.id), str(a2.id), str(a1.id)]
    r = await async_client.post(f"{BASE_TITLES}/{t.id}/artwork/reorder", json={"order": order})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["count"] == 3

    rows = (await db_session.execute(select(Artwork).where(Artwork.title_id == t.id))).scalars().all()
    by_id = {str(x.id): x for x in rows}
    assert by_id[str(a1.id)].sort_order == 2  # last write wins
    assert by_id[str(a2.id)].sort_order == 1

@pytest.mark.anyio
async def test_reorder_all_foreign_ids_is_400(async_client, db_session):
    t1 = await _mk_title(db_session)
    t2 = await _mk_title(db_session)
    f1 = await _mk_art(db_session, title_id=t2.id)
    f2 = await _mk_art(db_session, title_id=t2.id)

    r = await async_client.post(
        f"{BASE_TITLES}/{t1.id}/artwork/reorder",
        json={"order": [str(f1.id), str(f2.id)]},
    )
    assert r.status_code == 400, r.text
    assert str(f1.id) in r.text and str(f2.id) in r.text
