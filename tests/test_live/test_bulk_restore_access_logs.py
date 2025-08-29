# tests/test_live/test_bulk_restore_access_logs.py

import builtins
import pytest
from httpx import AsyncClient
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.db.models.organization import Organization
from app.db.models.live_sessions import LiveSession
from app.db.models.session_access_log import SessionAccessLog

BASE = "/api/v1/course/live/security"


# ---------- helpers ----------

def _utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0)

async def _ensure_org_exists(db: AsyncSession, org_id: UUID):
    """Insert minimal Organization row satisfying NOT NULLs."""
    now = _utcnow()
    org = Organization(
        id=org_id,
        name=f"org-{str(org_id)[:8]}",
        slug=f"org-{str(org_id)[:8]}",
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    db.add(org)
    await db.commit()
    await db.refresh(org)
    return org

def _find_creator_attr():
    for a in ("instructor_id", "created_by", "owner_user_id", "creator_user_id"):
        if hasattr(LiveSession, a):
            return a
    return None

async def _mk_session(
    db: AsyncSession,
    *,
    org_id: UUID,
    title: str = "Session",
    start: datetime | None = None,
    end: datetime | None = None,
    is_deleted: bool = False,
    creator_id: UUID | None = None,
):
    """Create a LiveSession with optional creator field if present."""
    now = _utcnow()
    st = start or now
    et = end or (st + timedelta(hours=1))
    data = dict(title=title, organization_id=org_id)

    # start/end variants the model might use
    for attr in ("start_time", "scheduled_at", "starts_at", "start_at"):
        if hasattr(LiveSession, attr):
            data[attr] = st
            break
    for attr in ("end_time", "ends_at"):
        if hasattr(LiveSession, attr):
            data[attr] = et
            break

    if hasattr(LiveSession, "is_deleted"):
        data["is_deleted"] = is_deleted

    # set creator attribute if available
    if creator_id is not None:
        cattr = _find_creator_attr()
        if cattr:
            data[cattr] = creator_id

    row = LiveSession(**data)
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row

async def _add_log(
    db: AsyncSession,
    *,
    org_id: UUID,
    session_id: UUID,
    user_id: UUID | None = None,
    is_deleted: bool | None = None,
    deleted_at: datetime | None = None,
):
    row = SessionAccessLog(
        id=uuid4(),
        org_id=org_id,
        session_id=session_id,
        user_id=user_id,
        ip_address="127.0.0.1",
        user_agent="pytest",
        token_jti=str(uuid4()),
        result="ALLOWED",
        success=True,
        reason="ok",
        accessed_at=_utcnow(),
    )
    if hasattr(SessionAccessLog, "is_deleted") and is_deleted is not None:
        setattr(row, "is_deleted", is_deleted)
    if hasattr(SessionAccessLog, "deleted_at") and deleted_at is not None:
        setattr(row, "deleted_at", deleted_at)

    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row

async def _get_log(db: AsyncSession, log_id: UUID) -> SessionAccessLog | None:
    rs = await db.execute(select(SessionAccessLog).where(SessionAccessLog.id == log_id))
    return rs.scalar_one_or_none()


# ---------- tests ----------

@pytest.mark.anyio
async def test_bulk_restore__200_admin_restores_all_in_org_strict_true(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id)

    # two soft-deleted logs in caller org
    l1 = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=True, deleted_at=_utcnow() - timedelta(days=1))
    l2 = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=True, deleted_at=_utcnow() - timedelta(days=2))

    r = await async_client.post(
        f"{BASE}/access-log/bulk-restore",
        headers=headers,
        params={"strict": True},
        json=[str(l1.id), str(l2.id)],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["restored_count"] == 2
    assert set(body["restored_ids"]) == {str(l1.id), str(l2.id)}

    # verify DB state
    l1_db = await _get_log(db_session, l1.id)
    l2_db = await _get_log(db_session, l2.id)
    if hasattr(SessionAccessLog, "is_deleted"):
        assert l1_db.is_deleted is False
        assert l2_db.is_deleted is False


@pytest.mark.anyio
async def test_bulk_restore__400_empty_ids(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    # empty JSON array is the correct body shape for List[UUID]
    r = await async_client.post(f"{BASE}/access-log/bulk-restore", headers=headers, json=[])
    assert r.status_code == 400
    assert "log_ids" in r.text.lower()


@pytest.mark.anyio
async def test_bulk_restore__400_strict_true_with_missing_not_deleted_unauthorized(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # member (non-admin) to exercise unauthorized path
    member, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    # session created by member (allowed)
    sess_ok = await _mk_session(db_session, org_id=org.id, creator_id=member.id)
    log_ok = await _add_log(db_session, org_id=org.id, session_id=sess_ok.id, is_deleted=True, deleted_at=_utcnow())

    # session created by someone else (unauthorized)
    sess_other = await _mk_session(db_session, org_id=org.id, creator_id=None)
    log_unauth = await _add_log(db_session, org_id=org.id, session_id=sess_other.id, is_deleted=True, deleted_at=_utcnow())

    # not soft-deleted
    log_active = await _add_log(db_session, org_id=org.id, session_id=sess_ok.id, is_deleted=False, deleted_at=None)

    # missing (random UUID)
    missing = uuid4()

    r = await async_client.post(
        f"{BASE}/access-log/bulk-restore",
        headers=headers,
        params={"strict": True},
        json=[str(log_ok.id), str(log_unauth.id), str(log_active.id), str(missing)],
    )
    assert r.status_code == 400, r.text
    detail = r.json().get("detail")
    # strict mode responds with a dict
    assert isinstance(detail, dict)
    assert str(missing) in detail.get("missing_ids", [])
    assert str(log_active.id) in detail.get("not_soft_deleted", [])
    assert str(log_unauth.id) in detail.get("unauthorized_ids", [])

    # none should have been restored due to strict failure
    if hasattr(SessionAccessLog, "is_deleted"):
        assert (await _get_log(db_session, log_ok.id)).is_deleted is True


@pytest.mark.anyio
async def test_bulk_restore__200_strict_false_partial_restore(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # non-admin; can only restore own-session logs
    member, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    # own session
    sess_mine = await _mk_session(db_session, org_id=org.id, creator_id=member.id)
    mine1 = await _add_log(db_session, org_id=org.id, session_id=sess_mine.id, is_deleted=True, deleted_at=_utcnow())

    # other's session, soft-deleted
    sess_other = await _mk_session(db_session, org_id=org.id, creator_id=None)
    other1 = await _add_log(db_session, org_id=org.id, session_id=sess_other.id, is_deleted=True, deleted_at=_utcnow())

    # active (not deleted)
    active1 = await _add_log(db_session, org_id=org.id, session_id=sess_mine.id, is_deleted=False)

    # missing
    missing = uuid4()

    r = await async_client.post(
        f"{BASE}/access-log/bulk-restore",
        headers=headers,
        params={"strict": False},
        json=[str(mine1.id), str(other1.id), str(active1.id), str(missing)],
    )
    assert r.status_code == 200, r.text
    body = r.json()
    # only mine1 should restore
    assert body["restored_count"] == 1
    assert set(body["restored_ids"]) == {str(mine1.id)}
    assert str(other1.id) in set(body["skipped_unauthorized"])
    assert str(active1.id) in set(body["skipped_not_deleted"])
    assert str(missing) in set(body["missing_ids"])

    if hasattr(SessionAccessLog, "is_deleted"):
        assert (await _get_log(db_session, mine1.id)).is_deleted is False
        assert (await _get_log(db_session, other1.id)).is_deleted is True
        assert (await _get_log(db_session, active1.id)).is_deleted is False


@pytest.mark.anyio
async def test_bulk_restore__200_non_admin_only_own_sessions(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # If no creator attribute exists on LiveSession, skip this test.
    if _find_creator_attr() is None:
        pytest.skip("LiveSession lacks a creator field; non-admin restore cannot be validated")

    member, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    # mine
    sess_mine = await _mk_session(db_session, org_id=org.id, creator_id=member.id)
    m1 = await _add_log(db_session, org_id=org.id, session_id=sess_mine.id, is_deleted=True, deleted_at=_utcnow())
    m2 = await _add_log(db_session, org_id=org.id, session_id=sess_mine.id, is_deleted=True, deleted_at=_utcnow())

    # not mine
    sess_other = await _mk_session(db_session, org_id=org.id, creator_id=None)
    o1 = await _add_log(db_session, org_id=org.id, session_id=sess_other.id, is_deleted=True, deleted_at=_utcnow())

    r = await async_client.post(
        f"{BASE}/access-log/bulk-restore",
        headers=headers,
        params={"strict": False},
        json=[str(m1.id), str(m2.id), str(o1.id)],
    )
    assert r.status_code == 200
    body = r.json()
    assert body["restored_count"] == 2
    assert set(body["restored_ids"]) == {str(m1.id), str(m2.id)}
    assert str(o1.id) in set(body["skipped_unauthorized"])

    if hasattr(SessionAccessLog, "is_deleted"):
        assert (await _get_log(db_session, m1.id)).is_deleted is False
        assert (await _get_log(db_session, m2.id)).is_deleted is False
        assert (await _get_log(db_session, o1.id)).is_deleted is True


@pytest.mark.anyio
async def test_bulk_restore__501_when_soft_delete_not_supported(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id)
    l1 = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=True, deleted_at=_utcnow())

    original_hasattr = builtins.hasattr

    def fake_hasattr(obj, name):
        if obj is SessionAccessLog and name == "is_deleted":
            return False
        return original_hasattr(obj, name)

    monkeypatch.setattr(builtins, "hasattr", fake_hasattr, raising=True)

    r = await async_client.post(
        f"{BASE}/access-log/bulk-restore",
        headers=headers,
        json=[str(l1.id)],
    )
    assert r.status_code == 501


@pytest.mark.anyio
async def test_bulk_restore__200_audit_failure_non_blocking(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id)
    l1 = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=True, deleted_at=_utcnow())

    import app.api.v1.course.live.security as sec

    async def boom(**kwargs):
        raise RuntimeError("audit down")

    monkeypatch.setattr(sec, "log_org_event", boom, raising=True)

    r = await async_client.post(
        f"{BASE}/access-log/bulk-restore",
        headers=headers,
        json=[str(l1.id)],
    )
    assert r.status_code == 200
    if hasattr(SessionAccessLog, "is_deleted"):
        assert (await _get_log(db_session, l1.id)).is_deleted is False


@pytest.mark.anyio
async def test_bulk_restore__200_dedup_ids_restore_once(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id)
    a = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=True, deleted_at=_utcnow())
    b = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=True, deleted_at=_utcnow())

    # duplicate A multiple times
    payload = [str(a.id), str(a.id), str(b.id), str(a.id)]

    r = await async_client.post(
        f"{BASE}/access-log/bulk-restore",
        headers=headers,
        json=payload,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["restored_count"] == 2
    assert set(body["restored_ids"]) == {str(a.id), str(b.id)}

    if hasattr(SessionAccessLog, "is_deleted"):
        assert (await _get_log(db_session, a.id)).is_deleted is False
        assert (await _get_log(db_session, b.id)).is_deleted is False


@pytest.mark.anyio
async def test_bulk_restore__org_scoping_missing_ids_for_other_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org_a = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess_a = await _mk_session(db_session, org_id=org_a.id)
    a1 = await _add_log(db_session, org_id=org_a.id, session_id=sess_a.id, is_deleted=True, deleted_at=_utcnow())

    # org B log will be "missing" from the perspective of org A
    org_b_id = uuid4()
    await _ensure_org_exists(db_session, org_b_id)
    sess_b = await _mk_session(db_session, org_id=org_b_id)
    b1 = await _add_log(db_session, org_id=org_b_id, session_id=sess_b.id, is_deleted=True, deleted_at=_utcnow())

    r = await async_client.post(
        f"{BASE}/access-log/bulk-restore",
        headers=headers,
        params={"strict": False},
        json=[str(a1.id), str(b1.id)],
    )
    assert r.status_code == 200
    body = r.json()
    assert body["restored_count"] == 1
    assert set(body["restored_ids"]) == {str(a1.id)}
    assert str(b1.id) in set(body["missing_ids"])

    if hasattr(SessionAccessLog, "is_deleted"):
        assert (await _get_log(db_session, a1.id)).is_deleted is False
