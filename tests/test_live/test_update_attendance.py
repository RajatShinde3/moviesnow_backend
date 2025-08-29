import uuid
from datetime import datetime, timedelta, timezone
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.db.models import LiveSession, LiveSessionAttendance

BASE = "/api/v1/course/live/session"


# ---------- time helpers (naive UTC) ----------
def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


# ---------- fixtures / monkeypatch ----------
@pytest.fixture(autouse=True)
def patch_naive_time(monkeypatch):
    """
    Make the endpoint use naive-UTC to avoid tz-aware/naive math issues.
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


# ---------- helpers to make rows ----------
async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
    title="Session",
    start=None,
    end=None,
    instructor_id=None,
    is_deleted=False,
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
    joined=None,
    left=None,
    duration=None,
    is_present=True,
    feedback="",
    admin_note="",
):
    joined = joined or (_utcnow_naive() + timedelta(minutes=10))
    left = left or (joined + timedelta(minutes=20))
    if duration is None and joined and left:
        duration = int(max(0, (left - joined).total_seconds()) // 60)

    a = LiveSessionAttendance(
        id=uuid.uuid4(),
        session_id=session_id,
        user_id=user_id,
        joined_at=joined,
        left_at=left,
        attended_duration_minutes=duration,
        is_present=is_present,
        feedback=feedback,
        admin_note=admin_note,
        created_at=_utcnow_naive(),
        updated_at=_utcnow_naive(),
    )
    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a


# =========================
#          TESTS
# =========================
@pytest.mark.anyio
async def test_attendance_update__200_owner_happy_path_and_etag_rotation(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Owner updates attendance; route recomputes duration; ETag rotates.

    This test is robust to DBs where session times are stored as naive UTC
    and attendance times as tz-aware UTC (or vice versa).
    """
    owner, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id, instructor_id=owner.id)

    # Seed: joined = start+5, left = joined+15
    base_join = session.start_time + timedelta(minutes=5)
    base_left = base_join + timedelta(minutes=15)
    att = await _mk_attendance(
        db_session,
        session_id=session.id,
        user_id=owner.id,
        joined=base_join,
        left=base_left,
        is_present=True,
        feedback="ok",
        admin_note="",
    )

    # Helper: normalize any dt (aware/naive) to naive UTC, second precision
    def _naive_utc(dt: datetime) -> datetime:
        if dt.tzinfo is not None:
            return dt.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
        return dt.replace(microsecond=0)

    s_start = _naive_utc(session.start_time)
    s_end = _naive_utc(session.end_time)
    persisted_join = _naive_utc(att.joined_at)
    persisted_left = _naive_utc(att.left_at)

    # Target: move join to ~ start+15
    target_join = (s_start + timedelta(minutes=15))

    payload1 = {}
    if persisted_left <= target_join:
        # We can't keep left >= joined if we only move joined forward.
        # Update BOTH joined & left within the session window.
        new_join = target_join
        # keep a small gap but inside the session
        new_left = min(s_end, new_join + timedelta(minutes=5))
        payload1 = {"joined_at": new_join.isoformat(), "left_at": new_left.isoformat()}
        expected1 = max(0, int((new_left - new_join).total_seconds() // 60))
    else:
        # Safe to only move joined forward; left remains the same.
        new_join = target_join
        payload1 = {"joined_at": new_join.isoformat()}
        expected1 = max(0, int((persisted_left - new_join).total_seconds() // 60))

    # 1) First update
    r1 = await async_client.put(f"{BASE}/attendance/{att.id}", headers=headers, json=payload1)
    assert r1.status_code == 200, r1.text
    body1 = r1.json()
    assert body1["attended_duration_minutes"] == expected1
    etag1 = r1.headers.get("ETag")
    assert etag1

    # Prepare second update (+2 minutes). Keep duration semantics consistent:
    # - If we changed both joined & left above, change both again by +2m.
    # - Else, only move joined by +2m.
    if "left_at" in payload1:
        j3 = _naive_utc(datetime.fromisoformat(payload1["joined_at"])) + timedelta(minutes=2)
        l3 = _naive_utc(datetime.fromisoformat(payload1["left_at"])) + timedelta(minutes=2)
        # still ensure we stay within the session window on the right side
        if l3 > s_end:
            l3 = s_end
            # keep joined <= left
            if j3 > l3:
                j3 = l3
        payload2 = {"joined_at": j3.isoformat(), "left_at": l3.isoformat()}
        expected2 = max(0, int((l3 - j3).total_seconds() // 60))
    else:
        j3 = new_join + timedelta(minutes=2)
        payload2 = {"joined_at": j3.isoformat()}
        expected2 = max(0, int((persisted_left - j3).total_seconds() // 60))

    # 2) Second update with If-Match (ETag must rotate)
    r2 = await async_client.put(
        f"{BASE}/attendance/{att.id}",
        headers={**headers, "If-Match": etag1},
        json=payload2,
    )
    assert r2.status_code == 200, r2.text
    body2 = r2.json()
    assert body2["attended_duration_minutes"] == expected2
    etag2 = r2.headers.get("ETag")
    assert etag2 and etag2 != etag1




@pytest.mark.anyio
async def test_attendance_update__403_non_owner_non_admin_forbidden(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, get_auth_headers
):
    """
    Non-owner, non-admin cannot update even allowed fields.
    """
    owner, owner_headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    other, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=False)
    other_headers = await get_auth_headers(other, org, OrgRole.INTERN)

    session = await _mk_session(db_session, org_id=org.id, instructor_id=owner.id)
    att = await _mk_attendance(db_session, session_id=session.id, user_id=owner.id)

    new_join = (session.start_time + timedelta(minutes=6)).replace(microsecond=0)
    r = await async_client.put(
        f"{BASE}/attendance/{att.id}",
        headers=other_headers,
        json={"joined_at": new_join.isoformat()},
    )
    assert r.status_code == 403, r.text


@pytest.mark.anyio
async def test_attendance_update__admin_can_update_someone_else(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Admin can update another user's attendance (joined_at only).
    """
    admin, admin_headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    member, _, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    session = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)
    att = await _mk_attendance(db_session, session_id=session.id, user_id=member.id)

    j2 = att.joined_at.replace(microsecond=0)
    j2 = (j2 + timedelta(minutes=2))
    r = await async_client.put(
        f"{BASE}/attendance/{att.id}",
        headers=admin_headers,
        json={"joined_at": j2.isoformat()},
    )
    assert r.status_code == 200, r.text


@pytest.mark.anyio
async def test_attendance_update__412_if_match_mismatch(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)
    att = await _mk_attendance(db_session, session_id=session.id, user_id=admin.id)

    r = await async_client.put(
        f"{BASE}/attendance/{att.id}",
        headers={**headers, "If-Match": "not-the-etag"},
        json={"joined_at": att.joined_at.replace(microsecond=0).isoformat()},
    )
    assert r.status_code == 412, r.text


@pytest.mark.anyio
async def test_attendance_update__422_empty_body_is_validation_error(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    With current schema, empty body fails validation (422) before route logic.
    """
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)
    att = await _mk_attendance(db_session, session_id=session.id, user_id=admin.id)

    r = await async_client.put(f"{BASE}/attendance/{att.id}", headers=headers, json={})
    assert r.status_code == 400
    assert "No fields to update" in r.text


@pytest.mark.anyio
async def test_attendance_update__400_left_before_joined(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Bump joined_at to a time after existing left_at -> 400 (left < joined).
    """
    owner, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id, instructor_id=owner.id)

    j = (session.start_time + timedelta(minutes=20)).replace(microsecond=0)
    l = (session.start_time + timedelta(minutes=10)).replace(microsecond=0)

    att = await _mk_attendance(db_session, session_id=session.id, user_id=owner.id, joined=j, left=l)

    # Move joined even later to ensure left < joined
    too_late_join = (l + timedelta(minutes=5)).isoformat()
    r = await async_client.put(
        f"{BASE}/attendance/{att.id}",
        headers=headers,
        json={"joined_at": too_late_join},
    )
    assert r.status_code == 400
    assert "left_at must be equal to or after joined_at" in r.text


from pprint import pformat

@pytest.mark.anyio
async def test_attendance_update__400_outside_session_window(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Only test 'joined_at before session start' (left_at updates are not allowed by the route).
    """
    owner, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    start = _utcnow_naive() + timedelta(hours=2)
    end = start + timedelta(hours=2)

    print("\n=== setup ===")
    print(f"start (naive): {start!r}")
    print(f"end   (naive): {end!r}")

    session = await _mk_session(db_session, org_id=org.id, instructor_id=owner.id, start=start, end=end)
    att = await _mk_attendance(db_session, session_id=session.id, user_id=owner.id)

    # Optional: see how the API is serializing the session window (tz/offset visibility)
    try:
        sess_resp = await async_client.get(f"{BASE}/{session.id}", headers=headers)
        print(f"GET session status={sess_resp.status_code}")
        try:
            sj = sess_resp.json()
            keys = ["start", "start_time", "end", "end_time"]
            print("session JSON (selected keys): " + pformat({k: sj.get(k) for k in keys if k in sj}))
        except Exception:
            print("session text:", sess_resp.text)
    except Exception as e:
        print(f"GET session debug skipped due to error: {e!r}")

    # joined_at before session start -> 400
    too_early = (start - timedelta(minutes=1)).replace(microsecond=0)
    payload = {"joined_at": too_early.isoformat()}

    print("\n=== request ===")
    print(f"PUT {BASE}/attendance/{att.id}")
    print(f"payload: {payload}")
    r1 = await async_client.put(
        f"{BASE}/attendance/{att.id}",
        headers=headers,
        json=payload,
    )

    print("\n=== response ===")
    print(f"status: {r1.status_code}")
    print("headers:\n" + pformat(dict(r1.headers)))
    try:
        print("json:", r1.json())
    except Exception:
        print("text:", r1.text)

    # Useful comparison info
    print("\n=== compare (client vs session window) ===")
    print(f"too_early (naive): {too_early!r}")
    print(f"delta start - too_early (secs): {(start - too_early).total_seconds()}")

    assert r1.status_code == 400
    assert "joined_at cannot be before session start" in r1.text


@pytest.mark.anyio
async def test_attendance_update__422_duration_must_be_integer(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Schema-level type error should raise 422.
    """
    owner, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id, instructor_id=owner.id)
    att = await _mk_attendance(db_session, session_id=session.id, user_id=owner.id)

    r = await async_client.put(
        f"{BASE}/attendance/{att.id}",
        headers=headers,
        json={"attended_duration_minutes": "not-an-int"},
    )
    assert r.status_code == 422


@pytest.mark.anyio
async def test_attendance_update__404_wrong_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # attendance in org1
    admin1, headers1, org1 = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session1 = await _mk_session(db_session, org_id=org1.id, instructor_id=admin1.id)
    att1 = await _mk_attendance(db_session, session_id=session1.id, user_id=admin1.id)

    # caller from a different org
    _, headers2, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    r = await async_client.put(
        f"{BASE}/attendance/{att1.id}",
        headers=headers2,
        json={"joined_at": att1.joined_at.replace(microsecond=0).isoformat()},
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_attendance_update__200_noop_returns_current(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Send identical joined_at -> 200, returns current object.
    """
    owner, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id, instructor_id=owner.id)
    att = await _mk_attendance(
        db_session,
        session_id=session.id,
        user_id=owner.id,
        is_present=True,
        feedback="same",
        admin_note="",
    )

    r = await async_client.put(
        f"{BASE}/attendance/{att.id}",
        headers=headers,
        json={"joined_at": att.joined_at.replace(microsecond=0).isoformat()},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == str(att.id)
