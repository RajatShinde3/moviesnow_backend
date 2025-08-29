# tests/test_live/test_restore_access_log.py

import builtins
import pytest
from httpx import AsyncClient
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.schemas.enums import OrgRole
from app.db.models.live_sessions import LiveSession
from app.db.models.session_access_log import SessionAccessLog
from app.db.models.organization import Organization  # for FK safety

BASE = "/api/v1/course/live/security"


# ---------- helpers ----------

def _utcnow():
    return datetime.now(timezone.utc)

async def _ensure_org_exists(db: AsyncSession, org_id: UUID):
    """Ensure an Organization row exists (FK-friendly)."""
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
    """Create a LiveSession with flexible field names."""
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
    user_id: UUID | None = None,
    is_deleted: bool = False,
):
    """Insert a SessionAccessLog row with required fields; control deleted state."""
    kwargs = dict(
        id=uuid4(),
        org_id=org_id,
        session_id=session_id,
        user_id=user_id,
        accessed_at=_utcnow(),
        ip_address="203.0.113.8",
        user_agent="pytest",
        token_jti=str(uuid4()),
        result="ALLOWED",
        success=True,
        reason="ok",
    )
    if hasattr(SessionAccessLog, "is_deleted"):
        kwargs["is_deleted"] = bool(is_deleted)
    if hasattr(SessionAccessLog, "deleted_at"):
        kwargs["deleted_at"] = (_utcnow() if is_deleted else None)

    row = SessionAccessLog(**kwargs)
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


# ---------- tests ----------

@pytest.mark.anyio
async def test_restore__200_admin_success(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Admin in org A
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Create session + soft-deleted log in org A
    session = await _mk_session(db_session, org_id=org.id)
    log = await _add_log(db_session, org_id=org.id, session_id=session.id, user_id=actor.id, is_deleted=True)

    r = await async_client.post(f"{BASE}/access-log/{log.id}/restore", headers=headers)
    assert r.status_code == 200, r.text
    assert "restored" in r.text.lower()

    # Verify restored
    fetched = (
        await db_session.execute(select(SessionAccessLog).where(SessionAccessLog.id == log.id))
    ).scalar_one()
    if hasattr(SessionAccessLog, "is_deleted"):
        assert fetched.is_deleted is False
    if hasattr(SessionAccessLog, "deleted_at"):
        assert fetched.deleted_at is None


@pytest.mark.anyio
async def test_restore__200_audit_failure_non_blocking(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id)
    log = await _add_log(db_session, org_id=org.id, session_id=session.id, user_id=actor.id, is_deleted=True)

    import app.api.v1.course.live.security as sec
    async def boom(**kwargs): raise RuntimeError("audit down")
    monkeypatch.setattr(sec, "log_org_event", boom, raising=True)

    r = await async_client.post(f"{BASE}/access-log/{log.id}/restore", headers=headers)
    assert r.status_code == 200, r.text


@pytest.mark.anyio
async def test_restore__403_forbidden_when_not_admin_or_creator(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    # Low-privilege member
    member, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    session = await _mk_session(db_session, org_id=org.id)
    log = await _add_log(db_session, org_id=org.id, session_id=session.id, user_id=member.id, is_deleted=True)

    from fastapi import HTTPException
    import app.api.v1.course.live.security as sec
    def deny(*_a, **_k): raise HTTPException(status_code=403, detail="Forbidden")
    monkeypatch.setattr(sec, "require_admin_or_creator_from_session", deny, raising=True)

    r = await async_client.post(f"{BASE}/access-log/{log.id}/restore", headers=headers)
    assert r.status_code == 403


@pytest.mark.anyio
async def test_restore__404_when_log_missing_or_not_deleted(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id)
    # Not soft-deleted
    log = await _add_log(db_session, org_id=org.id, session_id=session.id, user_id=actor.id, is_deleted=False)

    r = await async_client.post(f"{BASE}/access-log/{log.id}/restore", headers=headers)
    assert r.status_code == 404
    assert "not found" in r.text.lower() or "not deleted" in r.text.lower()


@pytest.mark.anyio
async def test_restore__404_when_session_not_in_caller_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Caller in org A
    actor, headers, org_a = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Create org B + session in B
    org_b_id = uuid4()
    await _ensure_org_exists(db_session, org_b_id)
    session_b = await _mk_session(db_session, org_id=org_b_id)

    # Create a soft-deleted log in org A that references session in org B
    log = await _add_log(db_session, org_id=org_a.id, session_id=session_b.id, user_id=actor.id, is_deleted=True)

    # The route checks session under caller's org A -> should 404
    r = await async_client.post(f"{BASE}/access-log/{log.id}/restore", headers=headers)
    assert r.status_code == 404
    assert "session not found" in r.text.lower()


@pytest.mark.anyio
async def test_restore__501_when_soft_delete_not_supported(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    # Make the route believe soft-delete isn't supported by faking hasattr
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id)
    log = await _add_log(db_session, org_id=org.id, session_id=session.id, user_id=actor.id, is_deleted=True)

    original_hasattr = builtins.hasattr

    def fake_hasattr(obj, name):
        if obj is SessionAccessLog and name == "is_deleted":
            return False
        return original_hasattr(obj, name)

    monkeypatch.setattr(builtins, "hasattr", fake_hasattr, raising=True)

    r = await async_client.post(f"{BASE}/access-log/{log.id}/restore", headers=headers)
    assert r.status_code == 501
    assert "not supported" in r.text.lower()
