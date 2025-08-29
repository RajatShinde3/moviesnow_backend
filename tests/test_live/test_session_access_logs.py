# tests/test_live/test_session_access_logs.py

import pytest
from httpx import AsyncClient
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.live_sessions import LiveSession
from app.db.models.session_access_log import SessionAccessLog
from app.db.models.organization import Organization  # <-- ensure FK org exists
from app.schemas.enums import OrgRole

BASE = "/api/v1/course/live/security"


# ---------- helpers ----------

def _utc_now():
    # naive UTC to match typical DB defaults
    return datetime.now(timezone.utc)


async def _ensure_org_exists(db: AsyncSession, org_id: UUID) -> Organization:
    """Create an Organization row if it doesn't already exist (for FK safety)."""
    existing = (
        await db.execute(select(Organization).where(Organization.id == org_id).limit(1))
    ).scalar_one_or_none()
    if existing:
        return existing
    org = Organization(
        id=org_id,
        name=f"Other Org {org_id.hex[:6]}",
        slug=f"other-org-{org_id.hex[:6]}",
        created_at=_utc_now(),
        updated_at=_utc_now(),
    )
    db.add(org)
    await db.commit()
    await db.refresh(org)
    return org


async def _add_log(
    db: AsyncSession,
    *,
    org_id,
    session_id,
    user_id=None,
    ip="127.0.0.1",
    result="ALLOWED",
    success=True,
    reason="ok",
    accessed_at=None,
    token_jti=None,
    user_agent="pytest",
):
    row = SessionAccessLog(
        id=uuid4(),
        org_id=org_id,
        session_id=session_id,
        user_id=user_id,
        ip_address=ip,
        user_agent=user_agent,
        token_jti=token_jti or str(uuid4()),
        result=result,
        success=success,
        reason=reason,
        accessed_at=accessed_at or _utc_now(),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


async def _mk_session(
    db: AsyncSession,
    *,
    org_id: UUID,
    title: str = "S",
    start: datetime | None = None,
    end: datetime | None = None,
    is_deleted: bool = False,
    course_id: Optional[UUID] = None,
) -> LiveSession:
    """Create a minimal LiveSession that satisfies NOT NULL fields if present."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
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
    if course_id is not None and hasattr(LiveSession, "course_id"):
        data["course_id"] = course_id

    s = LiveSession(**data)
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


# ---------- tests ----------

@pytest.mark.anyio
async def test_access_logs__200_basic_list_and_ordering(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # actor is admin -> can view
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # make a live session for this org
    session = await _mk_session(db_session, org_id=org.id)

    # seed a few logs (different times, same session/org)
    now = _utc_now()
    l1 = await _add_log(
        db_session, org_id=org.id, session_id=session.id, user_id=actor.id,
        ip="10.0.0.1", result="ALLOWED", success=True, accessed_at=now - timedelta(minutes=2)
    )
    l2 = await _add_log(
        db_session, org_id=org.id, session_id=session.id, user_id=None,
        ip="203.0.113.50", result="BLOCKED", success=False, accessed_at=now - timedelta(minutes=1)
    )

    # this log belongs to another org -> must not show up (ensure FK org exists)
    other_org_id = uuid4()
    await _ensure_org_exists(db_session, other_org_id)
    await _add_log(
        db_session, org_id=other_org_id, session_id=session.id, user_id=None,
        ip="198.51.100.1", result="ALLOWED", success=True, accessed_at=now - timedelta(minutes=3)
    )

    r = await async_client.get(f"{BASE}/sessions/{str(session.id)}/access-log", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()

    # Only the two logs from our org/session; ordered by accessed_at desc (most recent first)
    assert len(data) == 2
    # Returned order should be l2, l1
    returned_ids = [d["id"] for d in data]
    assert returned_ids == [str(l2.id), str(l1.id)]

    # spot-check shape
# spot-check shape
    assert data[0]["session_id"] == str(session.id)
    assert data[0]["org_id"] == str(org.id)
    assert data[0]["result"].upper() in ("ALLOWED", "BLOCKED")
    assert isinstance(data[0]["success"], bool)
    assert "accessed_at" in data[0]



@pytest.mark.anyio
async def test_access_logs__filters_user_ip_result_success_and_time(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id)

    now = _utc_now()
    # 3 logs varying fields
    log_a = await _add_log(
        db_session, org_id=org.id, session_id=session.id, user_id=actor.id,
        ip="203.0.113.77", result="ALLOWED", success=True, accessed_at=now - timedelta(minutes=30)
    )
    log_b = await _add_log(
        db_session, org_id=org.id, session_id=session.id, user_id=None,
        ip="198.51.100.5", result="BLOCKED", success=False, accessed_at=now - timedelta(minutes=20)
    )
    log_c = await _add_log(
        db_session, org_id=org.id, session_id=session.id, user_id=None,
        ip="203.0.113.88", result="EXPIRED", success=False, accessed_at=now - timedelta(minutes=10)
    )

    # user_id filter
    r = await async_client.get(
        f"{BASE}/sessions/{session.id}/access-log", headers=headers, params={"user_id": str(actor.id)}
    )
    assert r.status_code == 200
    ids = [x["id"] for x in r.json()]
    assert ids == [str(log_a.id)]

    # ip partial filter ("203.0.113")
    r = await async_client.get(
        f"{BASE}/sessions/{session.id}/access-log", headers=headers, params={"ip": "203.0.113"}
    )
    assert r.status_code == 200
    ids = [x["id"] for x in r.json()]
    assert set(ids) == {str(log_c.id), str(log_a.id)}

    # result filter (BLOCKED)
    r = await async_client.get(
        f"{BASE}/sessions/{session.id}/access-log", headers=headers, params={"result": "BLOCKED"}
    )
    assert r.status_code == 200
    ids = [x["id"] for x in r.json()]
    assert ids == [str(log_b.id)]

    # success=false
    r = await async_client.get(
        f"{BASE}/sessions/{session.id}/access-log", headers=headers, params={"success": False}
    )
    assert r.status_code == 200
    ids = [x["id"] for x in r.json()]
    assert set(ids) == {str(log_b.id), str(log_c.id)}

    # time window (between b and c only)
    start = (now - timedelta(minutes=25)).isoformat()
    end = (now - timedelta(minutes=5)).isoformat()
    r = await async_client.get(
        f"{BASE}/sessions/{session.id}/access-log",
        headers=headers,
        params={"start_date": start, "end_date": end},
    )
    assert r.status_code == 200
    ids = [x["id"] for x in r.json()]
    assert set(ids) == {str(log_c.id), str(log_b.id)}


@pytest.mark.anyio
async def test_access_logs__pagination_vs_export(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id)

    now = _utc_now()
    # 3 logs
    l1 = await _add_log(db_session, org_id=org.id, session_id=session.id, accessed_at=now - timedelta(minutes=3))
    l2 = await _add_log(db_session, org_id=org.id, session_id=session.id, accessed_at=now - timedelta(minutes=2))
    l3 = await _add_log(db_session, org_id=org.id, session_id=session.id, accessed_at=now - timedelta(minutes=1))

    # pagination: limit=1, offset=1 -> should return the 2nd most recent (l2)
    r = await async_client.get(
        f"{BASE}/sessions/{session.id}/access-log", headers=headers, params={"limit": 1, "offset": 1}
    )
    assert r.status_code == 200
    ids = [x["id"] for x in r.json()]
    assert ids == [str(l2.id)]

    # export=true should ignore limit/offset and return all three
    r = await async_client.get(
        f"{BASE}/sessions/{session.id}/access-log",
        headers=headers,
        params={"export": True, "limit": 1, "offset": 2},
    )
    assert r.status_code == 200
    ids = [x["id"] for x in r.json()]
    assert set(ids) == {str(l1.id), str(l2.id), str(l3.id)}


@pytest.mark.anyio
async def test_access_logs__400_bad_inputs(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id)

    # start_date > end_date
    end = _utc_now().isoformat()
    start = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    r = await async_client.get(
        f"{BASE}/sessions/{session.id}/access-log", headers=headers, params={"start_date": start, "end_date": end}
    )
    assert r.status_code == 400
    assert "start_date" in r.text.lower()

    # invalid result filter
    r = await async_client.get(
        f"{BASE}/sessions/{session.id}/access-log", headers=headers, params={"result": "NOT_A_RESULT"}
    )
    assert r.status_code == 400
    assert "invalid result" in r.text.lower()

    # ip too long
    r = await async_client.get(
        f"{BASE}/sessions/{session.id}/access-log", headers=headers, params={"ip": "x" * 65}
    )
    assert r.status_code == 400
    assert "ip" in r.text.lower()


@pytest.mark.anyio
async def test_access_logs__404_session_not_found(async_client: AsyncClient, org_user_with_token):
    _, headers, _org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    missing = uuid4()
    r = await async_client.get(f"{BASE}/sessions/{missing}/access-log", headers=headers)
    assert r.status_code == 404
    assert "not found" in r.text.lower()


@pytest.mark.anyio
async def test_access_logs__403_requires_admin_or_creator(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    # caller is a low-privilege member
    member, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    session = await _mk_session(db_session, org_id=org.id)

    # Force the authorization helper to raise 403 for this call to avoid coupling to your role logic
    import app.api.v1.course.live.security as sec
    from fastapi import HTTPException

    def no_access(*_a, **_k):  # raise the same way your helper would
        raise HTTPException(status_code=403, detail="Forbidden")

    monkeypatch.setattr(sec, "require_admin_or_creator_from_session", no_access, raising=True)

    r = await async_client.get(f"{BASE}/sessions/{session.id}/access-log", headers=headers)
    assert r.status_code == 403
