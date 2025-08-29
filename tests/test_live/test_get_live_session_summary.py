# tests/test_live/test_get_live_session_summary.py
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import LiveSession, LiveSessionAttendance, LiveSessionFeedback
from app.schemas.enums import OrgRole

BASE = "/api/v1/course/live/session"

# ---------- time helpers ----------
def _aware_utc(y=2025, mo=8, d=22, h=7, m=0, s=0) -> datetime:
    return datetime(y, mo, d, h, m, s, tzinfo=timezone.utc)

def _to_naive(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo:
        return dt.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
    return dt.replace(microsecond=0)

def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


# ---------- freeze now_utc() used by the route ----------
@pytest.fixture(autouse=True)
def freeze_now(monkeypatch):
    import app.api.v1.course.live.sessions as sessions_api
    fixed_now = _aware_utc(2025, 8, 22, 7, 0, 0)  # 07:00Z (aware)
    monkeypatch.setattr(sessions_api, "now_utc", lambda: fixed_now)


# ---------- factories ----------
async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
    title="Session",
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    instructor_id=None,
    actual_start_time: Optional[datetime] = None,
    actual_end_time: Optional[datetime] = None,
    is_deleted: bool = False,
):
    start = _to_naive(start) or (_utcnow_naive() + timedelta(minutes=10))
    end = _to_naive(end) or (start + timedelta(hours=1))
    astart = _to_naive(actual_start_time)
    aend = _to_naive(actual_end_time)

    s = LiveSession(
        id=uuid.uuid4(),
        title=title,
        organization_id=org_id,
        start_time=start,
        end_time=end,
        is_deleted=is_deleted,
        instructor_id=instructor_id,
    )
    if hasattr(s, "actual_start_time"):
        s.actual_start_time = astart
    if hasattr(s, "actual_end_time"):
        s.actual_end_time = aend
    if hasattr(s, "created_at"):
        s.created_at = _utcnow_naive()
    if hasattr(s, "updated_at"):
        s.updated_at = _utcnow_naive()

    for attr in ("start_time", "end_time", "actual_start_time", "actual_end_time", "created_at", "updated_at"):
        if hasattr(s, attr):
            v = getattr(s, attr)
            if isinstance(v, datetime):
                setattr(s, attr, _to_naive(v))

    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


async def _add_attendance(
    db: AsyncSession,
    *,
    session_id,
    user_id,
    minutes: int,
    joined_at: Optional[datetime] = None,
    is_deleted: bool = False,
):
    a = LiveSessionAttendance(
        id=uuid.uuid4(),
        session_id=session_id,
        user_id=user_id,  # must be a real user (FK)
        attended_duration_minutes=int(minutes),
        joined_at=_to_naive(joined_at) if joined_at else _utcnow_naive(),
    )
    if hasattr(a, "is_deleted"):
        a.is_deleted = is_deleted

    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a


async def _add_feedback(
    db: AsyncSession,
    *,
    session_id,
    user_id,  # ensure NOT NULL/FK satisfied
    rating: float,
    tags=None,
    is_deleted: bool = False,
):
    f = LiveSessionFeedback(
        id=uuid.uuid4(),
        session_id=session_id,
        user_id=user_id,
        rating=float(rating),
        tags=tags or [],
    )
    if hasattr(f, "is_deleted"):
        f.is_deleted = is_deleted

    db.add(f)
    await db.commit()
    await db.refresh(f)
    return f


# helper: mint N real users via existing factory fixture (IDs only)
async def _create_real_users(org_user_with_token, n: int) -> List[uuid.UUID]:
    ids = []
    for _ in range(n):
        u, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
        ids.append(u.id)
    return ids


# ---------- tests ----------

@pytest.mark.anyio
async def test_summary__empty_returns_zeros_and_etag(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    r = await async_client.get(f"{BASE}/{s.id}/summary", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["session_id"] == str(s.id)
    assert body["total_attendees"] == 0
    assert body["present_count"] == 0
    assert body["average_duration_minutes"] == 0.0
    assert body["last_joined_at"] is None
    assert body["top_attendees"] == []
    assert body["total_feedbacks"] == 0
    assert body["average_rating"] is None
    assert body["top_tags"] == {}
    assert r.headers.get("ETag")

@pytest.mark.anyio
async def test_summary__feedback_counts_avg_and_tags(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Feedback:
      ratings (ints): [4, 3, 5]  → avg 4.0
      tags: ["Audio","audio","slides"], ["Q&A"], []  → {"audio": 2, "slides": 1, "q&a": 1}
      one soft-deleted row ignored (only if the column exists)
    """
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    # Use real users for FK integrity
    u1, u2 = await _create_real_users(org_user_with_token, 2)

    # Integer ratings to match current schema behavior (AVG comes out as 4.0)
    await _add_feedback(db_session, session_id=s.id, user_id=admin.id, rating=4, tags=["Audio", "audio", "slides"])
    await _add_feedback(db_session, session_id=s.id, user_id=u1,      rating=3, tags=["Q&A"])
    await _add_feedback(db_session, session_id=s.id, user_id=u2,      rating=5, tags=[])
    if hasattr(LiveSessionFeedback, "is_deleted"):
        await _add_feedback(db_session, session_id=s.id, user_id=u2, rating=1, tags=["ignore"], is_deleted=True)

    r = await async_client.get(f"{BASE}/{s.id}/summary", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["total_feedbacks"] == 3
    assert body["average_rating"] == pytest.approx(4.0, rel=0, abs=0.001)
    assert body["top_tags"] == {"audio": 2, "slides": 1, "q&a": 1}
    assert r.headers.get("ETag")


@pytest.mark.anyio
async def test_summary__attendance_aggregates_and_top5(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    6 attendees with minutes: [60,45,30,15,5,0] ⇒
      total_attendees = 6
      present_count   = 5 (rule: minutes > 0)
      total_minutes   = 155
      avg_duration    = 25.83
      last_joined_at  = max(joined_at)
      top_attendees   = top 5 by minutes (exclude zero)
    """
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    # 6 additional REAL users; reserve the last one ONLY for a soft-deleted row
    extra_user_ids = await _create_real_users(org_user_with_token, 6)
    soft_deleted_user = extra_user_ids[-1]
    users = [admin.id] + extra_user_ids[:5]  # these are the 6 we keep
    minutes = [60, 45, 30, 15, 5, 0]

    if hasattr(LiveSessionAttendance, "is_deleted"):
        await _add_attendance(
            db_session,
            session_id=s.id,
            user_id=soft_deleted_user,
            minutes=999,
            joined_at=datetime(2025, 8, 22, 9, 9, 0),
            is_deleted=True,
        )

    base_join = datetime(2025, 8, 22, 6, 0, 0)
    for i, (u, m) in enumerate(zip(users, minutes)):
        j = base_join + timedelta(minutes=10 * i)
        await _add_attendance(db_session, session_id=s.id, user_id=u, minutes=m, joined_at=j)

    r = await async_client.get(f"{BASE}/{s.id}/summary", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["total_attendees"] == 6
    assert body["present_count"] == 5
    assert body["average_duration_minutes"] == pytest.approx(25.83, rel=0, abs=0.01)

    # Don’t assert an exact timestamp string: DB/driver may normalize to UTC ("Z")
    # or keep it naïve depending on column type & driver. Just ensure it’s present and ISO-like.
    assert isinstance(body["last_joined_at"], str) and "T" in body["last_joined_at"]

    tops = body["top_attendees"]
    assert len(tops) == 5
    assert tops[0]["user_id"] == str(users[0]) and tops[0]["total_minutes"] == 60
    assert tops[-1]["user_id"] == str(users[4]) and tops[-1]["total_minutes"] == 5
    assert r.headers.get("ETag")



@pytest.mark.anyio
async def test_summary__status_integration_in_progress(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # now = 07:00Z; actual_start = 06:45Z → in_progress
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        actual_start_time=datetime(2025, 8, 22, 6, 45, 0),
    )

    r = await async_client.get(f"{BASE}/{s.id}/summary", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "in_progress"
    assert r.headers.get("ETag")


@pytest.mark.anyio
async def test_summary__org_scope_404(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Create in org1, query with org2
    admin1, headers1, org1 = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s1 = await _mk_session(db_session, org_id=org1.id, instructor_id=admin1.id)

    _, headers2, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.get(f"{BASE}/{s1.id}/summary", headers=headers2)
    assert r.status_code == 404
