# tests/test_live/test_access_log_summary.py

import builtins
import pytest
from httpx import AsyncClient
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.live_sessions import LiveSession
from app.db.models.session_access_log import SessionAccessLog
from app.schemas.enums import OrgRole

BASE = "/api/v1/course/live/security"


# ---------- helpers ----------

def _utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0)

async def _mk_session(
    db: AsyncSession,
    *,
    org_id: UUID,
    title: str = "Session",
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    creator_id: Optional[UUID] = None,
) -> LiveSession:
    """Create a minimal LiveSession; only set creator/instructor when a real user id is provided."""
    now = _utcnow()
    st = start or now
    et = end or (st + timedelta(hours=1))

    data = dict(title=title, organization_id=org_id)

    # handle various time column names in your model
    for attr in ("start_time", "scheduled_at", "starts_at", "start_at"):
        if hasattr(LiveSession, attr):
            data[attr] = st
            break
    for attr in ("end_time", "ends_at"):
        if hasattr(LiveSession, attr):
            data[attr] = et
            break

    if hasattr(LiveSession, "is_deleted"):
        data["is_deleted"] = False

    # only set a creator/instructor FK if we have a real user id (prevents FK violations)
    if creator_id:
        for attr in ("instructor_id", "created_by", "owner_user_id", "creator_user_id"):
            if hasattr(LiveSession, attr):
                data[attr] = creator_id
                break

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
    result: str = "allowed",            # enums in your API appear lowercase (allowed/blocked/...)
    success: bool = True,
    ip: str = "203.0.113.10",
    accessed_at: Optional[datetime] = None,
    is_deleted: Optional[bool] = None,
    deleted_at: Optional[datetime] = None,
    reason: str = "ok",
    token_jti: Optional[str] = None,
    user_agent: str = "pytest",
) -> SessionAccessLog:
    row = SessionAccessLog(
        id=uuid4(),
        org_id=org_id,
        session_id=session_id,
        user_id=user_id,
        accessed_at=accessed_at or _utcnow(),
        ip_address=ip,
        user_agent=user_agent,
        token_jti=token_jti or str(uuid4()),
        success=success,
        reason=reason,
        result=result,  # e.g. "allowed", "blocked", "expired", "revoked"
    )
    if hasattr(SessionAccessLog, "is_deleted") and is_deleted is not None:
        setattr(row, "is_deleted", bool(is_deleted))
    if hasattr(SessionAccessLog, "deleted_at") and deleted_at is not None:
        setattr(row, "deleted_at", deleted_at)

    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


# ---------- tests ----------

@pytest.mark.anyio
async def test_summary__400_bad_time_range(async_client: AsyncClient, org_user_with_token):
    actor, headers, _org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    start = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    end = datetime.now(timezone.utc).isoformat()
    r = await async_client.get(f"{BASE}/access-log/summary", headers=headers, params={"start_date": start, "end_date": end})
    assert r.status_code == 400
    assert "start_date" in r.text.lower()


@pytest.mark.anyio
async def test_summary__403_org_wide_requires_admin(async_client: AsyncClient, org_user_with_token, monkeypatch):
    # caller is not admin; stub require_org_admin to force 403 without coupling to role logic
    member, headers, _org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    import app.api.v1.course.live.security as sec
    from fastapi import HTTPException

    def deny(*_a, **_k):
        raise HTTPException(status_code=403, detail="Forbidden")
    monkeypatch.setattr(sec, "require_org_admin", deny, raising=True)

    r = await async_client.get(f"{BASE}/access-log/summary", headers=headers)
    assert r.status_code == 403


@pytest.mark.anyio
async def test_summary__404_session_not_found(async_client: AsyncClient, org_user_with_token):
    actor, headers, _org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.get(f"{BASE}/access-log/summary", headers=headers, params={"session_id": str(uuid4())})
    assert r.status_code == 404
    assert "session not found" in r.text.lower()


@pytest.mark.anyio
async def test_summary__200_org_wide_counts_excludes_soft_deleted(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess1 = await _mk_session(db_session, org_id=org.id, creator_id=actor.id)
    sess2 = await _mk_session(db_session, org_id=org.id, creator_id=actor.id)

    # active logs
    a1 = await _add_log(db_session, org_id=org.id, session_id=sess1.id, user_id=actor.id, result="allowed")
    a2 = await _add_log(db_session, org_id=org.id, session_id=sess1.id, result="blocked")
    a3 = await _add_log(db_session, org_id=org.id, session_id=sess2.id, result="expired")

    # soft-deleted log (should not count)
    _ = await _add_log(db_session, org_id=org.id, session_id=sess2.id, result="revoked", is_deleted=True, deleted_at=_utcnow())

    r = await async_client.get(f"{BASE}/access-log/summary", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()

    total = body["total"]
    results = body["results"]
    # Normalize keys to lowercase for assertions
    results_lower = {k.lower(): v for k, v in results.items()}

    assert total == (results_lower.get("allowed", 0)
                     + results_lower.get("blocked", 0)
                     + results_lower.get("expired", 0)
                     + results_lower.get("revoked", 0)
                     + sum(v for k, v in results_lower.items()
                           if k not in {"allowed", "blocked", "expired", "revoked"}))  # if other enum buckets exist

    # At minimum, these three buckets should reflect counts 2+1+1 (soft-deleted excluded)
    assert results_lower.get("allowed", 0) >= 1
    assert results_lower.get("blocked", 0) >= 1
    assert results_lower.get("expired", 0) >= 1
    # revoked was soft-deleted, should be 0 here
    assert results_lower.get("revoked", 0) == 0


@pytest.mark.anyio
async def test_summary__200_session_specific_counts_and_filters(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id, creator_id=actor.id)
    other_sess = await _mk_session(db_session, org_id=org.id, creator_id=actor.id)

    now = _utcnow()
    # target session logs
    _ = await _add_log(db_session, org_id=org.id, session_id=sess.id, user_id=actor.id, result="allowed", accessed_at=now - timedelta(minutes=20))
    _ = await _add_log(db_session, org_id=org.id, session_id=sess.id, user_id=actor.id, result="blocked", accessed_at=now - timedelta(minutes=10))
    # other session log (should not be counted when filtering by session_id)
    _ = await _add_log(db_session, org_id=org.id, session_id=other_sess.id, result="allowed", accessed_at=now - timedelta(minutes=5))

    params = {
        "session_id": str(sess.id),
        "start_date": (now - timedelta(minutes=30)).isoformat(),
        "end_date": (now - timedelta(minutes=1)).isoformat(),
    }
    r = await async_client.get(f"{BASE}/access-log/summary", headers=headers, params=params)
    assert r.status_code == 200, r.text
    body = r.json()

    # Only two logs for target session within window
    assert body["total"] == 2
    results_lower = {k.lower(): v for k, v in body["results"].items()}
    assert results_lower.get("allowed", 0) == 1
    assert results_lower.get("blocked", 0) == 1


@pytest.mark.anyio
async def test_summary__200_user_id_filter(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id, creator_id=actor.id)

    # two by actor, one not by actor (user_id=None → avoids FK)
    await _add_log(db_session, org_id=org.id, session_id=sess.id, user_id=actor.id, result="allowed")
    await _add_log(db_session, org_id=org.id, session_id=sess.id, user_id=actor.id, result="blocked")
    await _add_log(db_session, org_id=org.id, session_id=sess.id, user_id=None,     result="allowed")

    r = await async_client.get(
        f"{BASE}/access-log/summary",
        headers=headers,
        params={"session_id": str(sess.id), "user_id": str(actor.id)},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 2
    results_lower = {k.lower(): v for k, v in body["results"].items()}
    assert results_lower.get("allowed", 0) == 1
    assert results_lower.get("blocked", 0) == 1



@pytest.mark.anyio
async def test_summary__200_audit_failure_non_blocking(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id, creator_id=actor.id)
    _ = await _add_log(db_session, org_id=org.id, session_id=sess.id, user_id=actor.id, result="allowed")

    import app.api.v1.course.live.security as sec
    async def boom(**kwargs): raise RuntimeError("audit down")

    monkeypatch.setattr(sec, "log_org_event", boom, raising=True)

    r = await async_client.get(f"{BASE}/access-log/summary", headers=headers, params={"session_id": str(sess.id)})
    assert r.status_code == 200
