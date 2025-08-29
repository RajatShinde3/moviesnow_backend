# tests/test_live/test_purge_old_access_logs.py

import builtins
import pytest
from httpx import AsyncClient
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.schemas.enums import OrgRole
from app.db.models.organization import Organization
from app.db.models.live_sessions import LiveSession
from app.db.models.session_access_log import SessionAccessLog

BASE = "/api/v1/course/live/security"


# ---------- helpers ----------

def _utcnow():
    return datetime.now(timezone.utc)

async def _ensure_org_exists(db: AsyncSession, org_id: UUID):
    """Create a minimal Organization row (for FK safety) if it doesn't exist."""
    row = (await db.execute(select(Organization).where(Organization.id == org_id))).scalar_one_or_none()
    if row:
        return row

    name = f"org-{str(org_id)[:8]}"
    payload = {"id": org_id}
    if hasattr(Organization, "name"):
        payload["name"] = name
    if hasattr(Organization, "slug"):
        payload["slug"] = name
    if hasattr(Organization, "is_active"):
        payload["is_active"] = True

    row = Organization(**payload)
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row

async def _mk_session(
    db: AsyncSession,
    *,
    org_id: UUID,
    title: str = "Session",
    start: datetime | None = None,
    end: datetime | None = None,
) -> LiveSession:
    """Create a LiveSession with flexible field names (matches your schema)."""
    now = _utcnow().replace(microsecond=0)
    st = start or now
    et = end or (st + timedelta(hours=1))

    data = dict(title=title, organization_id=org_id)
    # start field
    for attr in ("start_time", "scheduled_at", "starts_at", "start_at"):
        if hasattr(LiveSession, attr):
            data[attr] = st
            break
    # end field
    for attr in ("end_time", "ends_at"):
        if hasattr(LiveSession, attr):
            data[attr] = et
            break
    if hasattr(LiveSession, "is_deleted"):
        data["is_deleted"] = False

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
    is_deleted: bool = False,
    deleted_at: datetime | None = None,
    result: str = "ALLOWED",
):
    """Insert a SessionAccessLog row; control soft-delete state."""
    kwargs = dict(
        id=uuid4(),
        org_id=org_id,
        session_id=session_id,
        user_id=None,
        accessed_at=_utcnow(),
        ip_address="203.0.113.9",
        user_agent="pytest",
        token_jti=str(uuid4()),
        result=result,
        success=True,
        reason="ok",
    )
    if hasattr(SessionAccessLog, "is_deleted"):
        kwargs["is_deleted"] = bool(is_deleted)
    if hasattr(SessionAccessLog, "deleted_at"):
        kwargs["deleted_at"] = deleted_at

    row = SessionAccessLog(**kwargs)
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


# ---------- tests ----------

@pytest.mark.anyio
async def test_purge__200_deletes_only_older_soft_deleted_in_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Admin in org A
    actor, headers, org_a = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # org A session
    sess_a = await _mk_session(db_session, org_id=org_a.id)

    # Eligible (soft-deleted and OLD)
    old_dt = _utcnow() - timedelta(days=40)
    log_old = await _add_log(
        db_session, org_id=org_a.id, session_id=sess_a.id,
        is_deleted=True, deleted_at=old_dt
    )

    # Soft-deleted but NOT old enough
    recent_dt = _utcnow() - timedelta(days=10)
    log_recent = await _add_log(
        db_session, org_id=org_a.id, session_id=sess_a.id,
        is_deleted=True, deleted_at=recent_dt
    )

    # Not deleted
    log_active = await _add_log(
        db_session, org_id=org_a.id, session_id=sess_a.id,
        is_deleted=False, deleted_at=None
    )

    # Another org B (should not be affected)
    org_b_id = uuid4()
    await _ensure_org_exists(db_session, org_b_id)
    sess_b = await _mk_session(db_session, org_id=org_b_id)
    _ = await _add_log(
        db_session, org_id=org_b_id, session_id=sess_b.id,
        is_deleted=True, deleted_at=old_dt
    )

    # Purge with threshold 30 days → only log_old should be deleted
    r = await async_client.delete(f"{BASE}/access-log/purge-old", headers=headers, params={"days": 30})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["purged_count"] == 1
    assert "deleted" in body["detail"].lower()

    # Verify in DB
    row_old = (
        await db_session.execute(select(SessionAccessLog).where(SessionAccessLog.id == log_old.id))
    ).scalar_one_or_none()
    row_recent = (
        await db_session.execute(select(SessionAccessLog).where(SessionAccessLog.id == log_recent.id))
    ).scalar_one_or_none()
    row_active = (
        await db_session.execute(select(SessionAccessLog).where(SessionAccessLog.id == log_active.id))
    ).scalar_one_or_none()

    assert row_old is None  # purged
    assert row_recent is not None  # still there
    assert row_active is not None  # still there


@pytest.mark.anyio
async def test_purge__200_no_eligible_returns_zero(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id)

    # All logs are either not deleted or too recent
    _ = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=False)
    _ = await _add_log(
        db_session, org_id=org.id, session_id=sess.id, is_deleted=True,
        deleted_at=_utcnow() - timedelta(days=5)
    )

    r = await async_client.delete(f"{BASE}/access-log/purge-old", headers=headers, params={"days": 30})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["purged_count"] == 0
    assert "no soft-deleted" in body["detail"].lower()


@pytest.mark.anyio
async def test_purge__403_non_admin_forbidden(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    # Low-privilege member; avoid coupling to role logic by stubbing require_org_admin
    member, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    import app.api.v1.course.live.security as sec
    from fastapi import HTTPException

    def deny(*_a, **_k):
        raise HTTPException(status_code=403, detail="Forbidden")

    monkeypatch.setattr(sec, "require_org_admin", deny, raising=True)

    r = await async_client.delete(f"{BASE}/access-log/purge-old", headers=headers)
    assert r.status_code == 403


@pytest.mark.anyio
async def test_purge__501_when_soft_delete_not_supported(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    # Simulate model without soft-delete fields via hasattr patch
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    original_hasattr = builtins.hasattr

    def fake_hasattr(obj, name):
        if obj is SessionAccessLog and name in ("is_deleted", "deleted_at"):
            return False
        return original_hasattr(obj, name)

    monkeypatch.setattr(builtins, "hasattr", fake_hasattr, raising=True)

    r = await async_client.delete(f"{BASE}/access-log/purge-old", headers=headers)
    assert r.status_code == 501
    assert "not supported" in r.text.lower()


@pytest.mark.anyio
async def test_purge__200_audit_failure_non_blocking(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id)

    # Create one eligible
    old_dt = _utcnow() - timedelta(days=120)
    _ = await _add_log(
        db_session, org_id=org.id, session_id=sess.id, is_deleted=True, deleted_at=old_dt
    )

    import app.api.v1.course.live.security as sec
    async def boom(**kwargs): raise RuntimeError("audit down")

    monkeypatch.setattr(sec, "log_org_event", boom, raising=True)

    r = await async_client.delete(f"{BASE}/access-log/purge-old", headers=headers, params={"days": 30})
    assert r.status_code == 200
    assert r.json()["purged_count"] == 1


@pytest.mark.anyio
async def test_purge__422_invalid_days_param(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    # Too small
    r = await async_client.delete(f"{BASE}/access-log/purge-old", headers=headers, params={"days": 0})
    assert r.status_code == 422
    # Too large
    r = await async_client.delete(f"{BASE}/access-log/purge-old", headers=headers, params={"days": 3651})
    assert r.status_code == 422
    # Non-int
    r = await async_client.delete(f"{BASE}/access-log/purge-old", headers=headers, params={"days": "abc"})
    assert r.status_code == 422
