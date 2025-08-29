# tests/test_live/test_list_attendees.py
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.db.models import LiveSession, LiveSessionAttendance

BASE = "/api/v1/course/live/session"


# --------- time helpers (naive UTC) ----------
def _utcnow_naive() -> datetime:
    # use naive UTC to avoid tz-aware/naive driver mismatches where columns are "WITHOUT TIME ZONE"
    return datetime.now(timezone.utc).replace(microsecond=0)


# --------- autouse patch: keep route time utils naive-UTC ----------
@pytest.fixture(autouse=True)
def patch_naive_time(monkeypatch):
    """
    Normalize any datetime to naive UTC inside the route:
      - now_utc(): naive UTC
      - ensure_aware_utc(x): returns naive UTC (strip tz if present)
    """
    import app.api.v1.course.live.sessions as sessions_api

    monkeypatch.setattr(sessions_api, "now_utc", lambda: _utcnow_naive())

    def _to_naive(dt):
        if isinstance(dt, datetime):
            if dt.tzinfo is not None:
                return dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        return dt

    monkeypatch.setattr(sessions_api, "ensure_aware_utc", _to_naive)


# --------- helpers to create rows ----------
async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
    title="Session",
    start=None,
    end=None,
    instructor_id=None,
    is_deleted=False,
) -> LiveSession:
    start = start or (_utcnow_naive() + timedelta(hours=1))
    end = end or (start + timedelta(hours=1))
    s = LiveSession(
        id=uuid.uuid4(),
        title=title,
        organization_id=org_id,
        start_time=start,
        end_time=end,
        is_deleted=is_deleted,
        instructor_id=instructor_id,
        created_at=_utcnow_naive(),
        updated_at=_utcnow_naive(),
    )
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


async def _mk_attendance(
    db: AsyncSession,
    *,
    session_id,
    user_id,
    joined=None,
    left=None,
    is_deleted: bool | None = None,
) -> LiveSessionAttendance:
    joined = joined or (_utcnow_naive() + timedelta(minutes=10))
    left = left or (joined + timedelta(minutes=20))
    a = LiveSessionAttendance(
        id=uuid.uuid4(),
        session_id=session_id,
        user_id=user_id,
        joined_at=joined,
        left_at=left,
        attended_duration_minutes=int(max(0, (left - joined).total_seconds()) // 60),
        created_at=_utcnow_naive(),
        updated_at=_utcnow_naive(),
    )
    # Optional soft-delete flag if model supports it
    if is_deleted is not None and hasattr(LiveSessionAttendance, "is_deleted"):
        setattr(a, "is_deleted", is_deleted)

    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a


# =========================
#          TESTS
# =========================

@pytest.mark.anyio
async def test_attendees__200_empty_and_headers(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    r = await async_client.get(f"{BASE}/{s.id}/attendees", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json() == []

    # pagination headers
    assert r.headers.get("X-Total-Count") == "0"
    assert r.headers.get("X-Page-Offset") == "0"
    assert r.headers.get("X-Page-Limit") == "10"  # default limit


@pytest.mark.anyio
async def test_attendees__404_wrong_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # create session in org1
    admin1, headers1, org1 = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org1.id, instructor_id=admin1.id)

    # caller from org2
    _, headers2, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    r = await async_client.get(f"{BASE}/{s.id}/attendees", headers=headers2)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_attendees__404_soft_deleted_session(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, is_deleted=True)

    r = await async_client.get(f"{BASE}/{s.id}/attendees", headers=headers)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_attendees__excludes_soft_deleted_rows_if_supported(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    # Use a different user for the second attendance to avoid (user_id, session_id) uniqueness violations.
    member, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    # one visible, one soft-deleted (if column exists)
    a1 = await _mk_attendance(db_session, session_id=s.id, user_id=admin.id, is_deleted=False)
    a2 = await _mk_attendance(db_session, session_id=s.id, user_id=member.id, is_deleted=True)

    r = await async_client.get(f"{BASE}/{s.id}/attendees", headers=headers)
    assert r.status_code == 200, r.text
    ids = [row["id"] for row in r.json()]

    if hasattr(LiveSessionAttendance, "is_deleted"):
        # soft-deleted attendance should be excluded
        assert str(a1.id) in ids and str(a2.id) not in ids
        assert r.headers.get("X-Total-Count") == "1"
    else:
        # model doesn't have is_deleted → both rows should be included
        assert str(a1.id) in ids and str(a2.id) in ids
        assert r.headers.get("X-Total-Count") == "2"



@pytest.mark.anyio
async def test_attendees__sorted_desc_and_paginated_with_tiebreaker(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Verify stable ordering by primary timestamp DESC with ID DESC tiebreaker,
    and correct pagination headers.

    NOTE: Attendance has a unique (user_id, session_id) constraint, so we create
    distinct users for each attendance row.
    """
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    base = s.start_time + timedelta(minutes=1)

    # Prepare 12 distinct users (first is admin, rest are newly created)
    user_ids = [admin.id]
    for _ in range(11):
        u, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
        user_ids.append(u.id)

    created = []

    # Create 10 attendees with increasing joined_at
    for i in range(10):
        a = await _mk_attendance(
            db_session,
            session_id=s.id,
            user_id=user_ids[i],
            joined=base + timedelta(minutes=i),
            left=base + timedelta(minutes=i + 10),
        )
        created.append(a)

    # Add two with the exact same joined_at to exercise the id DESC tiebreaker
    same_ts = base + timedelta(minutes=5)
    a_same1 = await _mk_attendance(
        db_session, session_id=s.id, user_id=user_ids[10], joined=same_ts, left=same_ts + timedelta(minutes=10)
    )
    a_same2 = await _mk_attendance(
        db_session, session_id=s.id, user_id=user_ids[11], joined=same_ts, left=same_ts + timedelta(minutes=8)
    )
    created.extend([a_same1, a_same2])

    # Build expected order: primary timestamp desc, then id desc
    def _key(a: LiveSessionAttendance):
        j = a.joined_at
        if isinstance(j, datetime) and j.tzinfo is not None:
            j = j.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
        else:
            j = j.replace(microsecond=0)
        return (j, str(a.id))

    expected_sorted = sorted(created, key=_key, reverse=True)

    # Request skip/limit window
    skip, limit = 5, 5
    r = await async_client.get(f"{BASE}/{s.id}/attendees?skip={skip}&limit={limit}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()

    # Check headers
    assert r.headers.get("X-Total-Count") == str(len(created))
    assert r.headers.get("X-Page-Offset") == str(skip)
    assert r.headers.get("X-Page-Limit") == str(limit)

    # Expected page slice
    expected_ids = [str(a.id) for a in expected_sorted[skip: skip + limit]]
    got_ids = [row["id"] for row in body]
    assert got_ids == expected_ids
