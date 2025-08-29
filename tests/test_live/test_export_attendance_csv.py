# tests/test_live/test_export_attendance_csv.py

import csv
import io
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.db.models import LiveSession, LiveSessionAttendance, User

BASE = "/api/v1/course/live/session"


# ---------- tiny time helpers (naive UTC) ----------
def _utcnow_naive() -> datetime:
    # Naive UTC to keep inserts consistent when DB columns are TIMESTAMP WITHOUT TIME ZONE
    return datetime.now(timezone.utc).replace(microsecond=0)


# ---------- builders ----------
async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
    title: str = "S",
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    instructor_id=None,
    is_deleted: bool = False,
):
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
    joined: Optional[datetime] = None,
    left: Optional[datetime] = None,
    duration: Optional[int] = None,
    is_present: Optional[bool] = None,
    feedback: Optional[str] = None,
    admin_note: Optional[str] = None,
    is_deleted: Optional[bool] = None,
    source_type: Optional[str] = None,
):
    joined = joined or (_utcnow_naive() + timedelta(minutes=10))
    left = left or (joined + timedelta(minutes=20))
    if duration is None and joined and left:
        duration = max(0, int((left - joined).total_seconds() // 60))

    a = LiveSessionAttendance(
        id=uuid.uuid4(),
        session_id=session_id,
        user_id=user_id,
        joined_at=joined,
        left_at=left,
        attended_duration_minutes=duration,
        is_present=is_present if is_present is not None else (duration or 0) > 0,
        feedback=feedback,
        admin_note=admin_note,
        created_at=_utcnow_naive(),
        updated_at=_utcnow_naive(),
    )
    # optional columns
    if hasattr(LiveSessionAttendance, "is_deleted") and is_deleted is not None:
        setattr(a, "is_deleted", is_deleted)
    if hasattr(LiveSessionAttendance, "source_type") and source_type is not None:
        setattr(a, "source_type", source_type)

    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a


# ---------- CSV helpers ----------
def _rows_from_csv_text(text: str):
    # strip potential UTF-8 BOM only at very start (Excel compat)
    if text.startswith("\ufeff"):
        text = text.lstrip("\ufeff")
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    return rows[0], rows[1:]


# =========================
#          TESTS
# =========================

@pytest.mark.anyio
async def test_export_csv__basic_with_names_feedback_and_bom(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    base = s.start_time + timedelta(minutes=1)

    # create three distinct users for uniqueness (user_id, session_id)
    u1, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    u2, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    u3, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    # 3 rows with increasing joined_at (ascending expected in CSV)
    a1 = await _mk_attendance(db_session, session_id=s.id, user_id=u1.id, joined=base + timedelta(minutes=0), left=base + timedelta(minutes=5), feedback="f1", source_type="manual")
    a2 = await _mk_attendance(db_session, session_id=s.id, user_id=u2.id, joined=base + timedelta(minutes=1), left=base + timedelta(minutes=7), feedback="f2", source_type="auto")
    a3 = await _mk_attendance(db_session, session_id=s.id, user_id=u3.id, joined=base + timedelta(minutes=2), left=base + timedelta(minutes=9), feedback="f3", source_type="api")

    r = await async_client.get(
        f"{BASE}/{s.id}/attendance/export",
        headers=headers,
        params=dict(include_user_name=True, include_feedback=True, excel_compat=True),
    )
    assert r.status_code == 200, r.text
    disp = r.headers.get("Content-Disposition", "")
    assert "attachment;" in disp and "attendance_" in disp and disp.endswith('.csv"')

    # With excel_compat=True, text should start with BOM
    assert r.text.startswith("\ufeff")

    header, rows = _rows_from_csv_text(r.text)
    # Header columns
    expected = ["user_id", "user_name", "joined_at", "left_at", "present", "duration_minutes", "feedback"]
    if hasattr(LiveSessionAttendance, "source_type"):
        expected.append("source_type")
    assert header == expected

    # 3 rows ascending by joined_at
    assert [len(rows), rows[0][0], rows[1][0], rows[2][0]] == [3, str(u1.id), str(u2.id), str(u3.id)]
    # spot-check present and duration
    for rec, a in zip(rows, [a1, a2, a3]):
        present, duration = rec[4], int(rec[5])
        assert present in ("Yes", "No")
        assert duration == a.attended_duration_minutes


@pytest.mark.anyio
async def test_export_csv__present_only_min_duration_and_time_window(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)
    base = s.start_time + timedelta(minutes=1)

    u1, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    u2, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    u3, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    # u1: duration 0 → present_only should exclude
    _ = await _mk_attendance(db_session, session_id=s.id, user_id=u1.id, joined=base, left=base, duration=0, feedback="x")
    # u2: duration 5
    a2 = await _mk_attendance(db_session, session_id=s.id, user_id=u2.id, joined=base + timedelta(minutes=1), left=base + timedelta(minutes=6))
    # u3: duration 12
    a3 = await _mk_attendance(db_session, session_id=s.id, user_id=u3.id, joined=base + timedelta(minutes=2), left=base + timedelta(minutes=14))

    # present_only filters out u1
    r1 = await async_client.get(
        f"{BASE}/{s.id}/attendance/export",
        headers=headers,
        params=dict(present_only=True, include_user_name=False, include_feedback=False, excel_compat=False),
    )
    assert r1.status_code == 200
    assert not r1.text.startswith("\ufeff")  # no BOM
    header, rows = _rows_from_csv_text(r1.text)
    assert header[:5] == ["user_id", "joined_at", "left_at", "present", "duration_minutes"]
    assert [row[0] for row in rows] == [str(u2.id), str(u3.id)]

    # min_duration >= 10 should only include u3
    r2 = await async_client.get(
        f"{BASE}/{s.id}/attendance/export",
        headers=headers,
        params=dict(min_duration=10),
    )
    assert r2.status_code == 200
    _, rows2 = _rows_from_csv_text(r2.text)
    assert [row[0] for row in rows2] == [str(u3.id)]

    # time window: joined_at >= base+1 and < base+2 → only u2
    r3 = await async_client.get(
        f"{BASE}/{s.id}/attendance/export",
        headers=headers,
        params=dict(started_after=(base + timedelta(minutes=1)).isoformat(),
                    started_before=(base + timedelta(minutes=2)).isoformat()),
    )
    assert r3.status_code == 200
    _, rows3 = _rows_from_csv_text(r3.text)
    assert [row[0] for row in rows3] == [str(u2.id)]


@pytest.mark.anyio
async def test_export_csv__shape_without_names_and_feedback_and_no_bom(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)
    base = s.start_time + timedelta(minutes=2)

    u, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    await _mk_attendance(db_session, session_id=s.id, user_id=u.id, joined=base, left=base + timedelta(minutes=3))

    r = await async_client.get(
        f"{BASE}/{s.id}/attendance/export",
        headers=headers,
        params=dict(include_user_name=False, include_feedback=False, excel_compat=False),
    )
    assert r.status_code == 200
    assert not r.text.startswith("\ufeff")
    header, rows = _rows_from_csv_text(r.text)
    # no user_name, no feedback column
    expected = ["user_id", "joined_at", "left_at", "present", "duration_minutes"]
    if hasattr(LiveSessionAttendance, "source_type"):
        expected.append("source_type")
    assert header == expected
    assert len(rows) == 1


@pytest.mark.anyio
async def test_export_csv__validation_400_and_empty_window_equal_bounds_and_404_and_403(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, get_auth_headers
):
    admin, admin_headers, org1 = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s1 = await _mk_session(db_session, org_id=org1.id, instructor_id=admin.id)
    base = s1.start_time + timedelta(minutes=1)
    uA, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    await _mk_attendance(db_session, session_id=s1.id, user_id=uA.id, joined=base, left=base + timedelta(minutes=5))

    # 400: started_after > started_before
    after = (base + timedelta(minutes=2)).isoformat()
    before = (base + timedelta(minutes=1)).isoformat()
    r_bad = await async_client.get(
        f"{BASE}/{s1.id}/attendance/export",
        headers=admin_headers,
        params=dict(started_after=after, started_before=before),
    )
    assert r_bad.status_code == 400

    # equal bounds → empty result (>= X and < X) but still 200 with header only
    equal = (base + timedelta(minutes=3)).isoformat()
    r_empty = await async_client.get(
        f"{BASE}/{s1.id}/attendance/export",
        headers=admin_headers,
        params=dict(started_after=equal, started_before=equal),
    )
    assert r_empty.status_code == 200
    _, rows_empty = _rows_from_csv_text(r_empty.text)
    assert rows_empty == []

    # 404 (wrong org): another org admin calls against org1's session
    other_admin, other_headers, org2 = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    assert org2.id != org1.id
    r_404 = await async_client.get(f"{BASE}/{s1.id}/attendance/export", headers=other_headers)
    assert r_404.status_code == 404

    # 403 (same org, non-admin & not creator)
    member, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    # Mint headers for the *same* org1 using the fixtures' helper
    member_headers_same_org = await get_auth_headers(member, org1, OrgRole.INTERN)
    r_403 = await async_client.get(f"{BASE}/{s1.id}/attendance/export", headers=member_headers_same_org)
    assert r_403.status_code == 403


@pytest.mark.anyio
async def test_export_csv__sorted_ascending_by_joined_then_id(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Verify stable ordering: joined_at ASC (NULLS LAST) and ATTENDANCE-ID ASC as tiebreaker.
    """
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    base = s.start_time + timedelta(minutes=1)
    # three distinct users; two with same joined_at to test tiebreaker
    u1, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    u2, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    u3, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    a1 = await _mk_attendance(db_session, session_id=s.id, user_id=u1.id,
                              joined=base + timedelta(minutes=0),
                              left=base + timedelta(minutes=4))
    a2 = await _mk_attendance(db_session, session_id=s.id, user_id=u2.id,
                              joined=base + timedelta(minutes=2),
                              left=base + timedelta(minutes=6))
    # same joined_at as a2, different id → tie resolved by ATTENDANCE id ASC
    a3 = await _mk_attendance(db_session, session_id=s.id, user_id=u3.id,
                              joined=a2.joined_at, left=a2.left_at)

    r = await async_client.get(f"{BASE}/{s.id}/attendance/export", headers=headers)
    assert r.status_code == 200

    _, rows = _rows_from_csv_text(r.text)
    user_ids_in_order = [row[0] for row in rows]

    # Build expected by ATTENDANCE id (a2 vs a3) since that's the tiebreaker in SQL
    tie = sorted([(a2.id, a2.user_id), (a3.id, a3.user_id)], key=lambda t: t[0])
    expected = [str(a1.user_id), str(tie[0][1]), str(tie[1][1])]
    assert user_ids_in_order == expected
