# tests/test_live/test_bulk_soft_delete_access_logs.py

import builtins
import pytest
from httpx import AsyncClient
from typing import Optional, List
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.session_access_log import SessionAccessLog
from app.db.models.live_sessions import LiveSession
from app.db.models.organization import Organization
from app.schemas.enums import OrgRole

BASE = "/api/v1/course/live/security"


# ---------- helpers ----------

def _utcnow() -> datetime:
    # naive UTC (matches common DB defaults)
    return datetime.now(timezone.utc).replace(microsecond=0)


async def _ensure_org_exists(db: AsyncSession, org_id: UUID, *, name: Optional[str] = None, slug: Optional[str] = None):
    """Create an Organization row if not present (handles NOT NULL slug/name)."""
    exists = (
        await db.execute(select(Organization).where(Organization.id == org_id).limit(1))
    ).scalar_one_or_none()
    if exists:
        return exists
    row = Organization(
        id=org_id,
        name=name or f"org-{str(org_id)[:8]}",
        slug=slug or f"slug-{str(org_id)[:8]}",
        is_active=True,
        created_at=_utcnow(),
        updated_at=_utcnow(),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


def _creator_attr() -> Optional[str]:
    for attr in ("instructor_id", "created_by", "owner_user_id", "creator_user_id"):
        if hasattr(LiveSession, attr):
            return attr
    return None


async def _mk_session(
    db: AsyncSession,
    *,
    org_id: UUID,
    title: str = "Session",
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    creator_id: Optional[UUID] = None,
    is_deleted: bool = False,
) -> LiveSession:
    """Create a minimal LiveSession row that satisfies your schema."""
    await _ensure_org_exists(db, org_id)  # keep FK happy
    now = _utcnow()
    st = start or now
    et = end or (st + timedelta(hours=1))

    data = dict(title=title, organization_id=org_id)

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

    # Only set creator if provided (avoid FK to non-existent user)
    ca = _creator_attr()
    if ca and creator_id is not None:
        data[ca] = creator_id

    sess = LiveSession(**data)
    db.add(sess)
    await db.commit()
    await db.refresh(sess)
    return sess


async def _add_log(
    db: AsyncSession,
    *,
    org_id: UUID,
    session_id: UUID,
    user_id: Optional[UUID] = None,
    ip: str = "203.0.113.10",
    result: str = "ALLOWED",
    success: bool = True,
    reason: str = "ok",
    accessed_at: Optional[datetime] = None,
    is_deleted: Optional[bool] = None,
    deleted_at: Optional[datetime] = None,
) -> SessionAccessLog:
    row = SessionAccessLog(
        id=uuid4(),
        org_id=org_id,
        session_id=session_id,
        user_id=user_id,
        ip_address=ip,
        user_agent="pytest",
        token_jti=str(uuid4()),
        result=result,
        success=success,
        reason=reason,
        accessed_at=accessed_at or _utcnow(),
    )
    if hasattr(SessionAccessLog, "is_deleted") and is_deleted is not None:
        row.is_deleted = is_deleted
    if hasattr(SessionAccessLog, "deleted_at") and deleted_at is not None:
        row.deleted_at = deleted_at

    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


async def _get_log(db: AsyncSession, log_id: UUID) -> SessionAccessLog | None:
    return (
        await db.execute(select(SessionAccessLog).where(SessionAccessLog.id == log_id).limit(1))
    ).scalar_one_or_none()


# ---------- tests ----------

@pytest.mark.anyio
async def test_bulk_soft_delete__400_empty_payload(async_client: AsyncClient, org_user_with_token):
    actor, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    # Empty list should trigger 400 from route's validation
    r = await async_client.post(f"{BASE}/access-log/bulk-delete", headers=headers, json={"log_ids": []})
    assert r.status_code == 400
    assert "log_ids" in r.text.lower()


@pytest.mark.anyio
async def test_bulk_soft_delete__501_when_soft_delete_not_supported(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id)
    log = await _add_log(db_session, org_id=org.id, session_id=sess.id)

    import app.api.v1.course.live.security as sec

    original_hasattr = builtins.hasattr

    def fake_hasattr(obj, name):
        if obj is SessionAccessLog and name == "is_deleted":
            return False
        return original_hasattr(obj, name)

    monkeypatch.setattr(builtins, "hasattr", fake_hasattr, raising=True)

    r = await async_client.post(
        f"{BASE}/access-log/bulk-delete",
        headers=headers,
        json={"log_ids": [str(log.id)]},
    )
    assert r.status_code == 501


@pytest.mark.anyio
async def test_bulk_soft_delete__200_admin_deletes_in_org_only_and_idempotent(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Admin in org A
    admin, headers, org_a = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess_a = await _mk_session(db_session, org_id=org_a.id)

    # Two active + one already-deleted in org A
    a1 = await _add_log(db_session, org_id=org_a.id, session_id=sess_a.id, is_deleted=False)
    a2 = await _add_log(db_session, org_id=org_a.id, session_id=sess_a.id, is_deleted=False)
    a3 = await _add_log(db_session, org_id=org_a.id, session_id=sess_a.id, is_deleted=True, deleted_at=_utcnow() - timedelta(days=1))

    # Another org B (ensure org exists) → should be "missing" for org A call
    org_b_id = uuid4()
    await _ensure_org_exists(db_session, org_b_id)
    sess_b = await _mk_session(db_session, org_id=org_b_id)
    b1 = await _add_log(db_session, org_id=org_b_id, session_id=sess_b.id, is_deleted=False)

    payload = {"log_ids": [str(a1.id), str(a2.id), str(a3.id), str(b1.id)], "strict": False}
    r = await async_client.post(f"{BASE}/access-log/bulk-delete", headers=headers, json=payload)
    assert r.status_code == 200, r.text
    data = r.json()

    # Admin: both active A logs should be deleted; A3 reported already_deleted; B1 is missing
    assert set(data["deleted"]) == {str(a1.id), str(a2.id)}
    assert set(data["already_deleted"]) == {str(a3.id)}
    assert set(data["missing"]) == {str(b1.id)}
    assert data["unauthorized"] == []

    # DB: a1/a2 flipped to deleted with deleted_at
    for lid in (a1.id, a2.id):
        row = await _get_log(db_session, lid)
        assert row and getattr(row, "is_deleted", False) is True
        if hasattr(row, "deleted_at"):
            assert row.deleted_at is not None

    # DB: b1 unchanged (other org)
    row_b1 = await _get_log(db_session, b1.id)
    assert row_b1 and (getattr(row_b1, "is_deleted", False) is False)


@pytest.mark.anyio
async def test_bulk_soft_delete__400_strict_true_with_missing_already_deleted_unauthorized(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Non-admin member
    member, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    # Session that's "mine" (creator = member.id) if model supports it
    sess_mine = await _mk_session(db_session, org_id=org.id, creator_id=member.id)

    # Session that's NOT mine: leave creator unset (admin-only -> unauthorized for member)
    sess_other = await _mk_session(db_session, org_id=org.id, creator_id=None)

    # Logs:
    mine_active = await _add_log(db_session, org_id=org.id, session_id=sess_mine.id, is_deleted=False)
    mine_already = await _add_log(db_session, org_id=org.id, session_id=sess_mine.id, is_deleted=True, deleted_at=_utcnow())
    other_active = await _add_log(db_session, org_id=org.id, session_id=sess_other.id, is_deleted=False)
    missing_id = uuid4()

    payload = {"log_ids": [str(mine_active.id), str(mine_already.id), str(other_active.id), str(missing_id)], "strict": True}
    r = await async_client.post(f"{BASE}/access-log/bulk-delete", headers=headers, json=payload)
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    # all three buckets present
    assert str(missing_id) in set(detail["missing_ids"])
    assert str(mine_already.id) in set(detail["already_deleted"])
    assert str(other_active.id) in set(detail["unauthorized_ids"])

    # Ensure no changes were written in strict=True error path
    row = await _get_log(db_session, mine_active.id)
    assert row and (getattr(row, "is_deleted", False) is False)


@pytest.mark.anyio
async def test_bulk_soft_delete__200_strict_false_partial_delete(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    member, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    sess_mine = await _mk_session(db_session, org_id=org.id, creator_id=member.id)
    sess_other = await _mk_session(db_session, org_id=org.id, creator_id=None)

    mine_active = await _add_log(db_session, org_id=org.id, session_id=sess_mine.id, is_deleted=False)
    mine_already = await _add_log(db_session, org_id=org.id, session_id=sess_mine.id, is_deleted=True, deleted_at=_utcnow())
    other_active = await _add_log(db_session, org_id=org.id, session_id=sess_other.id, is_deleted=False)
    missing_id = uuid4()

    payload = {"log_ids": [str(mine_active.id), str(mine_already.id), str(other_active.id), str(missing_id)], "strict": False}
    r = await async_client.post(f"{BASE}/access-log/bulk-delete", headers=headers, json=payload)
    assert r.status_code == 200, r.text
    data = r.json()

    # Only my active log should be deleted
    assert set(data["deleted"]) == {str(mine_active.id)}
    assert set(data["already_deleted"]) == {str(mine_already.id)}
    assert set(data["unauthorized"]) == {str(other_active.id)}
    assert set(data["missing"]) == {str(missing_id)}

    # DB reflects the single deletion
    row = await _get_log(db_session, mine_active.id)
    assert row and getattr(row, "is_deleted", False) is True


@pytest.mark.anyio
async def test_bulk_soft_delete__200_audit_failure_non_blocking(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id)
    l1 = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=False)

    import app.api.v1.course.live.security as sec

    async def boom(**kwargs):  # simulate audit logger failure
        raise RuntimeError("audit down")

    monkeypatch.setattr(sec, "log_org_event", boom, raising=True)

    r = await async_client.post(
        f"{BASE}/access-log/bulk-delete",
        headers=headers,
        json={"log_ids": [str(l1.id)], "strict": False},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert set(data["deleted"]) == {str(l1.id)}
