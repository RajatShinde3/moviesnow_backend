# tests/test_live/test_get_live_session_status.py
import uuid
import json
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import LiveSession
from app.schemas.enums import OrgRole

BASE = "/api/v1/course/live/session"  # same base used elsewhere

# ---------- helpers ----------
def _utcnow_naive() -> datetime:
    # Naïve UTC: what your DB columns store (TIMESTAMP WITHOUT TIME ZONE)
    return datetime.now(timezone.utc).replace(microsecond=0)

def _aware_utc(y=2025, mo=8, d=22, h=7, m=0, s=0) -> datetime:
    # Aware UTC: route compares on aware times, then writes naive to DB
    return datetime(y, mo, d, h, m, s, tzinfo=timezone.utc)

def _to_naive(dt: datetime | None) -> datetime | None:
    # Normalize any input (aware or naive) to NAÏVE UTC (seconds precision)
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
    return dt.replace(microsecond=0)

# ---------- freeze route's clock (aware UTC) ----------
@pytest.fixture(autouse=True)
def freeze_now(monkeypatch):
    """
    Freeze sessions_api.now_utc() to an AWARE UTC value so the route
    compares aware(now) vs aware(start/end), but writes NAÏVE UTC to DB.
    """
    import app.api.v1.course.live.sessions as sessions_api
    fixed_now = _aware_utc(2025, 8, 22, 7, 0, 0)  # 07:00Z (aware)
    monkeypatch.setattr(sessions_api, "now_utc", lambda: fixed_now)

# ---------- factory (forces ALL datetimes written to DB to NAÏVE UTC) ----------
async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
    title="Session",
    start: datetime | None = None,
    end: datetime | None = None,
    instructor_id=None,
    is_deleted: bool = False,
    actual_start_time: datetime | None = None,
    actual_end_time: datetime | None = None,
    capacity: int | None = None,
):
    # Defaults as NAÏVE UTC
    start = _to_naive(start) or (_utcnow_naive() + timedelta(minutes=10))
    end = _to_naive(end) or (start + timedelta(hours=1))
    actual_start_time = _to_naive(actual_start_time)
    actual_end_time = _to_naive(actual_end_time)

    s = LiveSession(
        id=uuid.uuid4(),
        title=title,
        organization_id=org_id,
        start_time=start,
        end_time=end,
        is_deleted=is_deleted,
        instructor_id=instructor_id,
    )
    # Optional columns on some schemas
    if hasattr(s, "actual_start_time"):
        s.actual_start_time = actual_start_time
    if hasattr(s, "actual_end_time"):
        s.actual_end_time = actual_end_time
    if capacity is not None and hasattr(s, "capacity"):
        s.capacity = capacity
    if hasattr(s, "created_at"):
        s.created_at = _utcnow_naive()
    if hasattr(s, "updated_at"):
        s.updated_at = _utcnow_naive()

    # HARD GUARD: coerce any datetime attributes back to NAÏVE UTC before commit.
    for attr in (
        "start_time",
        "end_time",
        "actual_start_time",
        "actual_end_time",
        "created_at",
        "updated_at",
    ):
        if hasattr(s, attr):
            val = getattr(s, attr)
            if isinstance(val, datetime):
                setattr(s, attr, _to_naive(val))

    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s

# =========================
#          TESTS
# =========================

@pytest.mark.anyio
async def test_status__upcoming_before_scheduled_no_actual(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # now = 07:00Z; schedule starts at 07:10Z
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    start = datetime(2025, 8, 22, 7, 10, 0)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, start=start, end=start + timedelta(hours=1))

    r = await async_client.get(f"{BASE}/{s.id}/status", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "upcoming"
    assert body["duration_minutes"] is None
    assert r.headers.get("ETag")

@pytest.mark.anyio
async def test_status__should_have_started_between_scheduled_and_not_started(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # now = 07:00Z; schedule 06:00-08:00Z; not actually started
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        start=datetime(2025, 8, 22, 6, 0, 0),
        end=datetime(2025, 8, 22, 8, 0, 0),
        actual_start_time=None,
    )

    r = await async_client.get(f"{BASE}/{s.id}/status", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "should_have_started"
    assert body["duration_minutes"] is None
    assert r.headers.get("ETag")

@pytest.mark.anyio
async def test_status__in_progress_started_not_ended_duration(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # now = 07:00Z; actual_start = 06:45Z → duration 15m
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        actual_start_time=datetime(2025, 8, 22, 6, 45, 0),
    )

    r = await async_client.get(f"{BASE}/{s.id}/status", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "in_progress"
    assert body["duration_minutes"] == 15
    assert r.headers.get("ETag")

@pytest.mark.anyio
async def test_status__defensive_upcoming_when_now_before_actual_start(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # now = 07:00Z; actual_start = 07:10Z → defensive "upcoming"
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    future = datetime(2025, 8, 22, 7, 10, 0)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        start=future,
        end=future + timedelta(hours=1),
        actual_start_time=future,
    )

    r = await async_client.get(f"{BASE}/{s.id}/status", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "upcoming"
    assert body["duration_minutes"] is None

@pytest.mark.anyio
async def test_status__ended_when_actual_end_set_and_duration_exact(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # ended: actual_start 06:30Z, actual_end 06:59Z → duration 29m
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        actual_start_time=datetime(2025, 8, 22, 6, 30, 0),
        actual_end_time=datetime(2025, 8, 22, 6, 59, 0),
    )

    r = await async_client.get(f"{BASE}/{s.id}/status", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ended"
    assert body["duration_minutes"] == 29
    assert r.headers.get("ETag")

@pytest.mark.anyio
async def test_status__expired_when_scheduled_end_passed_never_started(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # now = 07:00Z; schedule 05:00-06:00Z; never actually started → expired
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        start=datetime(2025, 8, 22, 5, 0, 0),
        end=datetime(2025, 8, 22, 6, 0, 0),
        actual_start_time=None,
    )

    r = await async_client.get(f"{BASE}/{s.id}/status", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "expired"
    assert body["duration_minutes"] is None

@pytest.mark.anyio
async def test_status__404_wrong_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Create in org1, call as org2 → 404 (org scoping)
    admin1, headers1, org1 = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s1 = await _mk_session(db_session, org_id=org1.id, instructor_id=admin1.id)

    _, headers2, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.get(f"{BASE}/{s1.id}/status", headers=headers2)
    assert r.status_code == 404

@pytest.mark.anyio
async def test_status__shape_and_etag_present(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        actual_start_time=datetime(2025, 8, 22, 6, 45, 0),
    )

    r = await async_client.get(f"{BASE}/{s.id}/status", headers=headers)
    assert r.status_code == 200
    body = r.json()

    # schema fields: align with LiveSessionStatusResponse
    for key in (
        "id",
        "title",
        "scheduled_start_time",
        "scheduled_end_time",
        "actual_start_time",
        "actual_end_time",
        "status",
        "duration_minutes",
    ):
        assert key in body, f"missing {key}"

    assert str(s.id) == body["id"]
    assert r.headers.get("ETag")
