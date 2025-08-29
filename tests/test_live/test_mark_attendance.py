import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.db.models import LiveSession, LiveSessionAttendance

BASE = "/api/v1/course/live/session"


# ---------- time helpers (naive UTC for stability) ----------
def _utcnow_aware() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)

def _to_aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0)


def _payload_minimal(now: datetime | None = None) -> dict:
    """
    Build the minimal valid body for LiveSessionAttendanceCreate,
    matching the schema's required fields.
    """
    now = (now or _utcnow_aware()).replace(microsecond=0)
    joined = now - timedelta(seconds=30)
    left = joined + timedelta(minutes=5)
    return {
        "joined_at": joined.isoformat(),
        "left_at": left.isoformat(),
        "attended_duration_minutes": int((left - joined).total_seconds() // 60),
    }


# ---------- fixtures / monkeypatch ----------
@pytest.fixture(autouse=True)
def patch_now_to_naive(monkeypatch):
    """
    Make the route's now_utc() return a fixed naive-UTC 'now' so tests are deterministic.
    """
    import app.api.v1.course.live.sessions as sessions_api
    fixed_now = _utcnow_aware()
    monkeypatch.setattr(sessions_api, "now_utc", lambda: fixed_now)


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
    capacity=None,
):
    # Default: session is currently live
    start = start or (_utcnow_aware() - timedelta(minutes=5))
    end = end or (start + timedelta(hours=1))
    s = LiveSession(
        id=uuid.uuid4(),
        title=title,
        organization_id=org_id,
        start_time=start,
        end_time=end,
        is_deleted=is_deleted,
        instructor_id=instructor_id,
        created_at=_utcnow_aware(),
        updated_at=_utcnow_aware(),
    )
    if capacity is not None and hasattr(LiveSession, "capacity"):
        setattr(s, "capacity", capacity)

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
    joined = joined or (_utcnow_aware() - timedelta(minutes=1))
    left = left or (joined + timedelta(minutes=5))
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
        created_at=_utcnow_aware(),
        updated_at=_utcnow_aware(),
    )
    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a


# =========================
#           TESTS
# =========================

@pytest.mark.anyio
async def test_mark_attendance__201_created_then_200_idempotent(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    First POST creates attendance (201). Second POST returns 200 with the same row (idempotent).
    """
    user, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=user.id)

    body = _payload_minimal()

    # Create
    r1 = await async_client.post(f"{BASE}/{s.id}/attendance", headers=headers, json=body)
    assert r1.status_code == 201, r1.text
    b1 = r1.json()
    assert b1["session_id"] == str(s.id)
    assert b1["user_id"] == str(user.id)

    # Idempotent repeat
    r2 = await async_client.post(f"{BASE}/{s.id}/attendance", headers=headers, json=body)
    assert r2.status_code == 200, r2.text
    b2 = r2.json()
    assert b2["id"] == b1["id"]


@pytest.mark.anyio
async def test_mark_attendance__403_not_started(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    future_start = _utcnow_aware() + timedelta(minutes=10)
    s = await _mk_session(
        db_session, org_id=org.id, instructor_id=user.id, start=future_start, end=future_start + timedelta(hours=1)
    )

    r = await async_client.post(f"{BASE}/{s.id}/attendance", headers=headers, json=_payload_minimal())
    assert r.status_code == 403
    assert "not started" in r.text.lower()


@pytest.mark.anyio
async def test_mark_attendance__403_ended(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    ended_end = _utcnow_aware() - timedelta(minutes=1)
    s = await _mk_session(
        db_session, org_id=org.id, instructor_id=user.id, start=ended_end - timedelta(hours=1), end=ended_end
    )

    r = await async_client.post(f"{BASE}/{s.id}/attendance", headers=headers, json=_payload_minimal())
    assert r.status_code == 403
    assert "ended" in r.text.lower()


@pytest.mark.anyio
async def test_mark_attendance__404_wrong_org_and_404_soft_deleted(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin1, headers1, org1 = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s1 = await _mk_session(db_session, org_id=org1.id, instructor_id=admin1.id)

    # Different org -> 404
    _, headers2, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r_404 = await async_client.post(f"{BASE}/{s1.id}/attendance", headers=headers2, json=_payload_minimal())
    assert r_404.status_code == 404

    # Soft-deleted in same org -> 404
    s_deleted = await _mk_session(db_session, org_id=org1.id, instructor_id=admin1.id, is_deleted=True)
    r_deleted = await async_client.post(f"{BASE}/{s_deleted.id}/attendance", headers=headers1, json=_payload_minimal())
    assert r_deleted.status_code == 404


@pytest.mark.anyio
async def test_mark_attendance__capacity_409_when_full(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    If capacity is reached, endpoint returns 409.

    This works even if LiveSession has no 'capacity' column by monkeypatching
    the route's session loader to attach capacity=1 and bypass org scoping
    (so we can use a different user without adding org membership plumbing).
    """
    # creator & live session (already started, not ended)
    admin, admin_headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    start = _utcnow_aware() - timedelta(minutes=5)
    end = _utcnow_aware() + timedelta(hours=1)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, start=start, end=end)

    # Monkeypatch loader used by the route:
    # - ignore org check (return our session regardless)
    # - attach capacity=1 dynamically so getattr(session, "capacity", None) works
    import app.api.v1.course.live.sessions as sessions_api
    from fastapi import HTTPException

    async def _patched_get_live_session_or_404(db, session_id, organization_id):
        if session_id != s.id:
            raise HTTPException(status_code=404, detail="Live session not found")
        setattr(s, "capacity", 1)
        return s

    monkeypatch.setattr(sessions_api, "get_live_session_or_404", _patched_get_live_session_or_404)

    # Fill capacity with one attendee (the admin)
    _ = await _mk_attendance(db_session, session_id=s.id, user_id=admin.id)

    # Another user tries to join -> 409 (capacity reached)
    other, other_headers, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    r = await async_client.post(f"{BASE}/{s.id}/attendance", headers=other_headers, json=_payload_minimal())

    assert r.status_code == 409, r.text
    assert "capacity" in r.text.lower()



@pytest.mark.anyio
async def test_mark_attendance__duplicate_path_existing_row_returns_200(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=user.id)

    # Pre-create attendance
    existing = await _mk_attendance(db_session, session_id=s.id, user_id=user.id)

    r = await async_client.post(f"{BASE}/{s.id}/attendance", headers=headers, json=_payload_minimal())
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == str(existing.id)
    assert body["session_id"] == str(s.id)
    assert body["user_id"] == str(user.id)


@pytest.mark.anyio
async def test_mark_attendance__ignores_client_supplied_ids(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Route must ignore client-supplied session_id/user_id and use path+auth.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=user.id)

    bogus_session = uuid.uuid4()
    bogus_user = uuid.uuid4()
    body = {
        **_payload_minimal(),
        "session_id": str(bogus_session),
        "user_id": str(bogus_user),
    }

    r = await async_client.post(f"{BASE}/{s.id}/attendance", headers=headers, json=body)
    assert r.status_code in (200, 201), r.text
    out = r.json()
    assert out["session_id"] == str(s.id)
    assert out["user_id"] == str(user.id)
