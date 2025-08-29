# tests/test_live/test_bulk_check_access_log_status.py

import builtins
import pytest
from httpx import AsyncClient
from uuid import uuid4, UUID
from typing import Optional, Dict, Set, List
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
    return datetime.now(timezone.utc).replace(microsecond=0)


async def _ensure_org_exists(
    db: AsyncSession,
    org_id: UUID,
    *,
    name: Optional[str] = None,
    slug: Optional[str] = None,
):
    """Create an Organization row if not present (handles NOT NULL slug/name)."""
    existing = (
        await db.execute(select(Organization).where(Organization.id == org_id).limit(1))
    ).scalar_one_or_none()
    if existing:
        return existing
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
    """Create a minimal LiveSession row that satisfies your schema (and avoids FKs)."""
    await _ensure_org_exists(db, org_id)
    now = _utcnow()
    st = start or now
    et = end or (st + timedelta(hours=1))

    data = dict(title=title, organization_id=org_id)

    # start / end fields vary by schema
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

    # Only set creator if provided AND field exists (avoids FK to non-existent users)
    ca = _creator_attr()
    if ca and creator_id is not None:
        data[ca] = creator_id

    s = LiveSession(**data)
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


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


def _qs_for_ids(ids: List[UUID]) -> List[tuple[str, str]]:
    """Encode ?log_ids=<id>&log_ids=<id>... for httpx."""
    return [("log_ids", str(x)) for x in ids]


# ---------- tests ----------

@pytest.mark.anyio
async def test_bulk_status__422_when_missing_required_param(async_client: AsyncClient, org_user_with_token):
    # Missing required query param -> validation error from FastAPI/Pydantic
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.get(f"{BASE}/access-log/bulk-status", headers=headers)
    assert r.status_code == 422


@pytest.mark.anyio
async def test_bulk_status__400_when_too_many_ids(async_client: AsyncClient, org_user_with_token):
    actor, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    too_many = [uuid4() for _ in range(1001)]
    r = await async_client.get(
        f"{BASE}/access-log/bulk-status", headers=headers, params=_qs_for_ids(too_many)
    )
    assert r.status_code == 400
    assert "too many" in r.text.lower()


@pytest.mark.anyio
async def test_bulk_status__200_admin_sees_all_in_org_and_reports_missing(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org_a = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess_a = await _mk_session(db_session, org_id=org_a.id)

    # In-org logs
    active = await _add_log(db_session, org_id=org_a.id, session_id=sess_a.id, is_deleted=False)
    old_dt = _utcnow() - timedelta(days=7)
    deleted = await _add_log(
        db_session, org_id=org_a.id, session_id=sess_a.id, is_deleted=True, deleted_at=old_dt
    )

    # Another org's log -> should be treated as 'missing'
    org_b = uuid4()
    await _ensure_org_exists(db_session, org_b)
    sess_b = await _mk_session(db_session, org_id=org_b)
    foreign = await _add_log(db_session, org_id=org_b, session_id=sess_b.id, is_deleted=False)

    ids = [deleted.id, active.id, foreign.id]
    r = await async_client.get(
        f"{BASE}/access-log/bulk-status", headers=headers, params=_qs_for_ids(ids)
    )
    assert r.status_code == 200, r.text
    data = r.json()

    # Only in-org logs appear in "status"
    status_ids = [x["id"] for x in data["status"]]
    assert status_ids == [str(deleted.id), str(active.id)]  # preserves order of *provided* unique IDs

    # deleted entry includes deleted_at (if model has it)
    deleted_entry = data["status"][0]
    assert deleted_entry["is_deleted"] is True
    if hasattr(SessionAccessLog, "deleted_at"):
        assert deleted_entry["deleted_at"] is not None

    # active entry
    active_entry = data["status"][1]
    assert active_entry["is_deleted"] is False
    assert active_entry["deleted_at"] is None

    # foreign is reported as missing (since org-scoped fetch didn't return it)
    assert set(data["missing"]) == {str(foreign.id)}
    assert data["unauthorized"] == []


@pytest.mark.anyio
async def test_bulk_status__200_non_admin_only_own_sessions_and_no_leak(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # If LiveSession has no creator attribute, non-admin can't own any; skip this test.
    if _creator_attr() is None:
        pytest.skip("LiveSession lacks a creator field; non-admin ownership path not testable")

    member, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    # "Mine"
    sess_mine = await _mk_session(db_session, org_id=org.id, creator_id=member.id)
    l_mine = await _add_log(db_session, org_id=org.id, session_id=sess_mine.id, is_deleted=False)

    # "Not mine" -> leave creator unset (admin-only); member shouldn't see it
    sess_other = await _mk_session(db_session, org_id=org.id, creator_id=None)
    l_other = await _add_log(db_session, org_id=org.id, session_id=sess_other.id, is_deleted=False)

    # Include one missing UUID as well
    missing = uuid4()

    ids = [l_other.id, l_mine.id, missing]
    r = await async_client.get(
        f"{BASE}/access-log/bulk-status", headers=headers, params=_qs_for_ids(ids)
    )
    assert r.status_code == 200, r.text
    data = r.json()

    # Only "mine" appears in status
    status_ids = [x["id"] for x in data["status"]]
    assert status_ids == [str(l_mine.id)]

    # other is unauthorized; missing reported
    assert set(data["unauthorized"]) == {str(l_other.id)}
    assert set(data["missing"]) == {str(missing)}


@pytest.mark.anyio
async def test_bulk_status__404_strict_on_any_missing_or_unauthorized(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    if _creator_attr() is None:
        pytest.skip("LiveSession lacks a creator field; non-admin ownership path not testable")

    member, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    sess_mine = await _mk_session(db_session, org_id=org.id, creator_id=member.id)
    my_log = await _add_log(db_session, org_id=org.id, session_id=sess_mine.id, is_deleted=False)

    sess_other = await _mk_session(db_session, org_id=org.id, creator_id=None)
    other_log = await _add_log(db_session, org_id=org.id, session_id=sess_other.id, is_deleted=False)

    missing = uuid4()

    ids = [my_log.id, other_log.id, missing]
    params = _qs_for_ids(ids) + [("strict", "true")]
    r = await async_client.get(f"{BASE}/access-log/bulk-status", headers=headers, params=params)
    assert r.status_code == 404, r.text
    detail = r.json()["detail"]
    # strict returns only the error buckets
    assert set(detail["missing"]) == {str(missing)}
    assert set(detail["unauthorized"]) == {str(other_log.id)}


@pytest.mark.anyio
async def test_bulk_status__200_audit_failure_non_blocking(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id)
    l1 = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=False)

    import app.api.v1.course.live.security as sec

    async def boom(**kwargs):
        raise RuntimeError("audit down")

    monkeypatch.setattr(sec, "log_org_event", boom, raising=True)

    r = await async_client.get(
        f"{BASE}/access-log/bulk-status", headers=headers, params=_qs_for_ids([l1.id])
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert [x["id"] for x in data["status"]] == [str(l1.id)]


@pytest.mark.anyio
async def test_bulk_status__200_preserves_order_and_deduplicates(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id)
    a = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=False)
    b = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=True, deleted_at=_utcnow())

    # Order: B, A, B (dup). Should return B, A once each in that order.
    ids = [b.id, a.id, b.id]
    r = await async_client.get(
        f"{BASE}/access-log/bulk-status", headers=headers, params=_qs_for_ids(ids)
    )
    assert r.status_code == 200, r.text
    status_ids = [x["id"] for x in r.json()["status"]]
    assert status_ids == [str(b.id), str(a.id)]
