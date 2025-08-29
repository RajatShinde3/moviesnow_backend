# tests/test_live/test_get_access_log_by_id.py

import pytest
from httpx import AsyncClient
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.db.models.live_sessions import LiveSession
from app.db.models.session_access_log import SessionAccessLog
from app.db.models.organization import Organization


BASE = "/api/v1/course/live/security"  # same prefix as other live/security tests


# ---------- helpers ----------

def _utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0)

async def _ensure_org_exists(db: AsyncSession, org_id: UUID):
    """Create a minimal Organization row satisfying NOT NULL constraints."""
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

async def _mk_session(
    db: AsyncSession,
    *,
    org_id: UUID,
    title: str = "S",
    start: datetime | None = None,
    end: datetime | None = None,
    is_deleted: bool = False,
):
    """Create a minimal LiveSession with fields present in your model."""
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
    ip: str = "127.0.0.1",
    result: str = "ALLOWED",
    success: bool = True,
    reason: str = "ok",
    accessed_at: datetime | None = None,
    is_deleted: bool | None = None,
    deleted_at: datetime | None = None,
):
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
    # optional soft-delete fields if present on the model
    if hasattr(SessionAccessLog, "is_deleted") and is_deleted is not None:
        setattr(row, "is_deleted", is_deleted)
    if hasattr(SessionAccessLog, "deleted_at") and deleted_at is not None:
        setattr(row, "deleted_at", deleted_at)

    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


# ---------- tests ----------

@pytest.mark.anyio
async def test_get_access_log_by_id__200_ok(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id)
    log = await _add_log(db_session, org_id=org.id, session_id=sess.id, user_id=actor.id)

    r = await async_client.get(f"{BASE}/access-log/{log.id}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == str(log.id)
    assert body["org_id"] == str(org.id)
    assert body["session_id"] == str(sess.id)


@pytest.mark.anyio
async def test_get_access_log_by_id__404_not_in_caller_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    actor, headers, org_a = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    # Create separate org B + session B + log in org B
    org_b = uuid4()
    await _ensure_org_exists(db_session, org_b)
    sess_b = await _mk_session(db_session, org_id=org_b)
    log_b = await _add_log(db_session, org_id=org_b, session_id=sess_b.id, user_id=actor.id)

    r = await async_client.get(f"{BASE}/access-log/{log_b.id}", headers=headers)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_get_access_log_by_id__404_soft_deleted_log(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id)
    # mark as soft-deleted if model supports it
    log = await _add_log(
        db_session, org_id=org.id, session_id=sess.id, user_id=actor.id,
        is_deleted=True, deleted_at=_utcnow()
    )

    r = await async_client.get(f"{BASE}/access-log/{log.id}", headers=headers)
    # Route filters out deleted logs → 404
    assert r.status_code == 404


@pytest.mark.anyio
async def test_get_access_log_by_id__404_when_session_not_in_caller_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Caller in org A
    actor, headers, org_a = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Create a session in org B
    org_b = uuid4()
    await _ensure_org_exists(db_session, org_b)
    sess_b = await _mk_session(db_session, org_id=org_b)

    # Create log in org A that references session in org B (cross-tenant mismatch)
    log = await _add_log(db_session, org_id=org_a.id, session_id=sess_b.id, user_id=actor.id)

    r = await async_client.get(f"{BASE}/access-log/{log.id}", headers=headers)
    # Route finds log (org A) but then can't find matching session in org A → 404
    assert r.status_code == 404


@pytest.mark.anyio
async def test_get_access_log_by_id__403_requires_admin_or_creator(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    member, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id)
    log = await _add_log(db_session, org_id=org.id, session_id=sess.id, user_id=member.id)

    import app.api.v1.course.live.security as sec
    from fastapi import HTTPException

    def deny(*_a, **_k):
        raise HTTPException(status_code=403, detail="Forbidden")

    # force the authorization helper to deny
    monkeypatch.setattr(sec, "require_admin_or_creator_from_session", deny, raising=True)

    r = await async_client.get(f"{BASE}/access-log/{log.id}", headers=headers)
    assert r.status_code == 403


@pytest.mark.anyio
async def test_get_access_log_by_id__200_audit_failure_non_blocking(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id)
    log = await _add_log(db_session, org_id=org.id, session_id=sess.id, user_id=actor.id)

    import app.api.v1.course.live.security as sec

    async def boom(**kwargs):
        raise RuntimeError("audit down")

    monkeypatch.setattr(sec, "log_org_event", boom, raising=True)

    r = await async_client.get(f"{BASE}/access-log/{log.id}", headers=headers)
    assert r.status_code == 200
