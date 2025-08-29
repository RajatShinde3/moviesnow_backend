# tests/test_live/test_course_attendance_summary.py

import json
from uuid import uuid4, UUID
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo
import re
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

# Adjust imports if your project paths differ
from app.schemas.enums import OrgRole
from app.core.redis_client import redis_wrapper
from app.utils.audit import AuditEventType
from app.db.models import Course, LiveSession, LiveSessionAttendance

BASE = "/api/v1/course/live/analytics/course"


# ------------------------ helpers --------------------------------------------

def _simple_slug(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or "course"

async def _mk_course(db: AsyncSession, *, org_id, title="C", is_deleted=False, slug: str | None = None):
    # Build kwargs dynamically based on available columns
    kwargs = dict(title=title, organization_id=org_id)

    # Provide a non-null, unique slug if the model has it
    if hasattr(Course, "slug"):
        base = slug or _simple_slug(title)
        kwargs["slug"] = f"{base}-{uuid4().hex[:8]}"

    # Only include "is_deleted" if the model actually has it
    if hasattr(Course, "is_deleted"):
        kwargs["is_deleted"] = is_deleted

    c = Course(**kwargs)
    db.add(c)
    await db.commit()
    await db.refresh(c)
    return c


async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
    course_id,
    title="S",
    start=None,
    end=None,
    is_deleted=False,
):
    now = datetime.now(timezone.utc)
    kwargs = dict(
        title=title,
        description="",
        organization_id=org_id,
        course_id=course_id,
        start_time=start or now,
        end_time=end or (now + timedelta(hours=1)),
    )
    if hasattr(LiveSession, "is_deleted"):
        kwargs["is_deleted"] = is_deleted

    s = LiveSession(**kwargs)
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


async def _mk_attendance(
    db: AsyncSession,
    *,
    user_id,
    session_id,
    joined_at: datetime,
    minutes: int | None = 30,
):
    # Route stores/compares naive UTC; normalize if tz-aware
    if joined_at.tzinfo is not None:
        joined_at = joined_at.astimezone(timezone.utc).replace(tzinfo=None)

    a = LiveSessionAttendance(
        user_id=user_id,
        session_id=session_id,
        joined_at=joined_at,
        is_present=True,
        attended_duration_minutes=minutes,
    )
    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a


def _utc_start_of(d: date) -> datetime:
    return datetime(d.year, d.month, d.day)


def _to_utc_naive_local_day_start(d: date, tz: str) -> datetime:
    return (
        datetime.combine(d, datetime.min.time(), ZoneInfo(tz))
        .astimezone(ZoneInfo("UTC"))
        .replace(tzinfo=None)
    )


def _to_utc_naive_local_next_day_start(d: date, tz: str) -> datetime:
    return (
        datetime.combine(d + timedelta(days=1), datetime.min.time(), ZoneInfo(tz))
        .astimezone(ZoneInfo("UTC"))
        .replace(tzinfo=None)
    )


# ------------------------ tests ----------------------------------------------

@pytest.mark.anyio
async def test_course_summary__404_course_not_in_org(async_client: AsyncClient, org_user_with_token):
    _, headers, _org = await org_user_with_token(role=OrgRole.ADMIN)
    r = await async_client.get(f"{BASE}/{uuid4()}", headers=headers)
    assert r.status_code == 404, r.text
    assert "Course not found" in r.text


@pytest.mark.anyio
async def test_course_summary__includes_zero_attendance_sessions(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    course = await _mk_course(db_session, org_id=org.id)

    # Two sessions in the course; only one gets attendance.
    s1 = await _mk_session(db_session, org_id=org.id, course_id=course.id, title="S1")
    s2 = await _mk_session(db_session, org_id=org.id, course_id=course.id, title="S2")

    today = datetime.now(timezone.utc).date()
    await _mk_attendance(db_session, user_id=user.id, session_id=s1.id, joined_at=_utc_start_of(today))

    r = await async_client.get(f"{BASE}/{course.id}?tz=UTC", headers=headers)
    assert r.status_code == 200, r.text
    rows = r.json()

    # Expect both sessions; one with 1, the other with 0
    by_id = {UUID(x["session_id"]): x["attendee_count"] for x in rows}
    assert by_id[s1.id] == 1
    assert by_id[s2.id] == 0


@pytest.mark.anyio
async def test_course_summary__filters_on_join_preserve_left_join(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    course = await _mk_course(db_session, org_id=org.id)

    s_old = await _mk_session(db_session, org_id=org.id, course_id=course.id, title="old")
    s_new = await _mk_session(db_session, org_id=org.id, course_id=course.id, title="new")

    today = datetime.now(timezone.utc).date()
    yday = today - timedelta(days=1)

    # Put attendance only yesterday on s_old
    await _mk_attendance(db_session, user_id=user.id, session_id=s_old.id, joined_at=_utc_start_of(yday))

    # Filter for today only: both sessions should be present with 0
    r = await async_client.get(
        f"{BASE}/{course.id}?start_date={today}&end_date={today}&tz=UTC",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    rows = r.json()
    by_id = {UUID(x["session_id"]): x["attendee_count"] for x in rows}
    assert by_id[s_old.id] == 0
    assert by_id[s_new.id] == 0


@pytest.mark.anyio
async def test_course_summary__distinct_toggle_equals_raw_due_to_unique_constraint(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Schema enforces one attendance per (user, session), so distinct vs raw counts match.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    course = await _mk_course(db_session, org_id=org.id)
    s = await _mk_session(db_session, org_id=org.id, course_id=course.id, title="S")

    await _mk_attendance(db_session, user_id=user.id, session_id=s.id, joined_at=datetime.now(timezone.utc))

    r1 = await async_client.get(f"{BASE}/{course.id}?distinct_users=false&tz=UTC", headers=headers)
    r2 = await async_client.get(f"{BASE}/{course.id}?distinct_users=true&tz=UTC", headers=headers)

    assert r1.status_code == r2.status_code == 200
    assert r1.json() == r2.json()


@pytest.mark.anyio
async def test_course_summary__sort_by_time_title_id_and_pagination(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    course = await _mk_course(db_session, org_id=org.id)

    base = datetime.now(timezone.utc) - timedelta(days=1)
    sA = await _mk_session(db_session, org_id=org.id, course_id=course.id, title="Alpha", start=base + timedelta(hours=1))
    sB = await _mk_session(db_session, org_id=org.id, course_id=course.id, title="Beta",  start=base + timedelta(hours=2))
    sC = await _mk_session(db_session, org_id=org.id, course_id=course.id, title="Gamma", start=base + timedelta(hours=3))

    # Give some attendance so counts are non-zero
    for s in (sA, sB, sC):
        await _mk_attendance(db_session, user_id=user.id, session_id=s.id, joined_at=s.start_time)

    # sort_by=time asc (by start_time) => A, B, C
    r = await async_client.get(f"{BASE}/{course.id}?sort_by=time&sort_dir=asc&tz=UTC", headers=headers)
    assert [x["session_title"] for x in r.json()] == ["Alpha", "Beta", "Gamma"]

    # sort_by=time desc => C, B, A
    r = await async_client.get(f"{BASE}/{course.id}?sort_by=time&sort_dir=desc&tz=UTC", headers=headers)
    assert [x["session_title"] for x in r.json()] == ["Gamma", "Beta", "Alpha"]

    # sort_by=title asc => Alpha, Beta, Gamma
    r = await async_client.get(f"{BASE}/{course.id}?sort_by=title&sort_dir=asc&tz=UTC", headers=headers)
    assert [x["session_title"] for x in r.json()] == ["Alpha", "Beta", "Gamma"]

    # sort_by=id desc (order by UUID string), then limit/offset
    r = await async_client.get(f"{BASE}/{course.id}?sort_by=id&sort_dir=desc&tz=UTC", headers=headers)
    titles_desc_id = [x["session_title"] for x in r.json()]

    # Paginate: first 2 then next 1 using same sort
    r1 = await async_client.get(f"{BASE}/{course.id}?sort_by=id&sort_dir=desc&limit=2&offset=0&tz=UTC", headers=headers)
    r2 = await async_client.get(f"{BASE}/{course.id}?sort_by=id&sort_dir=desc&limit=2&offset=2&tz=UTC", headers=headers)
    assert [x["session_title"] for x in r1.json()] + [x["session_title"] for x in r2.json()] == titles_desc_id


@pytest.mark.anyio
async def test_course_summary__soft_deleted_sessions_excluded(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    course = await _mk_course(db_session, org_id=org.id)

    s_ok = await _mk_session(db_session, org_id=org.id, course_id=course.id, title="OK", is_deleted=False)
    s_deleted = await _mk_session(db_session, org_id=org.id, course_id=course.id, title="DELETED", is_deleted=True)

    await _mk_attendance(db_session, user_id=user.id, session_id=s_ok.id, joined_at=datetime.now(timezone.utc))

    r = await async_client.get(f"{BASE}/{course.id}?tz=UTC", headers=headers)
    assert r.status_code == 200
    titles = [x["session_title"] for x in r.json()]
    assert "OK" in titles
    assert "DELETED" not in titles


@pytest.mark.anyio
async def test_course_summary__end_only_inclusive_with_timezone(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    course = await _mk_course(db_session, org_id=org.id)
    s = await _mk_session(db_session, org_id=org.id, course_id=course.id, title="IST-edge")

    tz = "Asia/Kolkata"
    end_d = datetime.now(timezone.utc).date()

    # 21:30 IST on end_d => should be included when only end_date is given
    ist = ZoneInfo(tz)
    join_local = datetime(end_d.year, end_d.month, end_d.day, 21, 30, 0, tzinfo=ist)
    join_utc_naive = join_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

    await _mk_attendance(db_session, user_id=user.id, session_id=s.id, joined_at=join_utc_naive)

    r = await async_client.get(f"{BASE}/{course.id}?end_date={end_d}&tz={tz}", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert any(row["session_id"] == str(s.id) and row["attendee_count"] == 1 for row in body)


@pytest.mark.anyio
async def test_course_summary__validation_errors_422(async_client: AsyncClient, org_user_with_token, db_session):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    course = await _mk_course(db_session, org_id=org.id)

    # invalid sort_by
    r = await async_client.get(f"{BASE}/{course.id}?sort_by=bogus", headers=headers)
    assert r.status_code == 422

    # invalid sort_dir
    r = await async_client.get(f"{BASE}/{course.id}?sort_dir=sideways", headers=headers)
    assert r.status_code == 422

    # limit out of range
    r = await async_client.get(f"{BASE}/{course.id}?limit=0", headers=headers)
    assert r.status_code == 422


@pytest.mark.anyio
async def test_course_summary__cache_hit_short_circuit(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession, monkeypatch
):
    """
    Seed Redis with a deterministic key (explicit start/end), expect:
    - returned list equals cached payload
    - audit called with {"cache": "hit"}
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    course = await _mk_course(db_session, org_id=org.id)

    tz = "UTC"
    start_d = date(2020, 1, 1)
    end_d = date(2020, 1, 5)
    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)

    cache_key = (
        f"course:attendance:v2:org:{org.id}:course:{course.id}"
        f":tz:{tz}:start:{start_utc}:end:{end_utc_excl}"
        f":distinct:{0}:sort:time:asc:limit:None:offset:0"
    )

    cached = [
        {"session_id": str(uuid4()), "session_title": "Cached A", "attendee_count": 7},
        {"session_id": str(uuid4()), "session_title": "Cached B", "attendee_count": 9},
    ]
    await redis_wrapper.client.setex(cache_key, 60, json.dumps(cached, separators=(",", ":")))

    seen = {}
    async def _audit(**kwargs):
        seen["action"] = kwargs.get("action")
        seen["meta"] = kwargs.get("meta_data")

    monkeypatch.setattr(
        "app.api.v1.course.live.analytics.log_org_event", _audit, raising=True
    )

    r = await async_client.get(
        f"{BASE}/{course.id}?start_date={start_d}&end_date={end_d}&tz={tz}&distinct_users=false&sort_by=time&sort_dir=asc",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json() == cached
    assert seen.get("action") == AuditEventType.GET_COURSE_ATTENDACE_SUMMARY
    assert (seen.get("meta") or {}).get("cache") == "hit"
    assert (seen.get("meta") or {}).get("course_id") == str(course.id)


@pytest.mark.anyio
async def test_course_summary__use_cache_false_ignores_cache(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    course = await _mk_course(db_session, org_id=org.id)

    tz = "UTC"
    start_d = date(2020, 2, 1)
    end_d = date(2020, 2, 2)
    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)

    cache_key = (
        f"course:attendance:v2:org:{org.id}:course:{course.id}"
        f":tz:{tz}:start:{start_utc}:end:{end_utc_excl}"
        f":distinct:{0}:sort:time:asc:limit:None:offset:0"
    )
    cached = [{"session_id": str(uuid4()), "session_title": "X", "attendee_count": 99}]
    await redis_wrapper.client.setex(cache_key, 60, json.dumps(cached))

    r = await async_client.get(
        f"{BASE}/{course.id}?start_date={start_d}&end_date={end_d}&tz={tz}&use_cache=false",
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json() != cached  # ignored cache


@pytest.mark.anyio
async def test_course_summary__corrupt_cache_falls_back(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    course = await _mk_course(db_session, org_id=org.id)

    tz = "UTC"
    start_d = date(2020, 3, 1)
    end_d = date(2020, 3, 3)
    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)

    cache_key = (
        f"course:attendance:v2:org:{org.id}:course:{course.id}"
        f":tz:{tz}:start:{start_utc}:end:{end_utc_excl}"
        f":distinct:{0}:sort:time:asc:limit:None:offset:0"
    )
    await redis_wrapper.client.setex(cache_key, 60, "{not-json")

    r = await async_client.get(
        f"{BASE}/{course.id}?start_date={start_d}&end_date={end_d}&tz={tz}",
        headers=headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)
    assert all(set(x) == {"session_id", "session_title", "attendee_count"} for x in body)


@pytest.mark.anyio
async def test_course_summary__audit_called_on_success(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession, monkeypatch
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    course = await _mk_course(db_session, org_id=org.id)

    # Make at least one session exist
    await _mk_session(db_session, org_id=org.id, course_id=course.id, title="A")

    recorded = {}
    async def _audit(**kwargs):
        recorded["organization_id"] = kwargs.get("organization_id")
        recorded["action"] = kwargs.get("action")
        recorded["meta"] = kwargs.get("meta_data")

    monkeypatch.setattr(
        "app.api.v1.course.live.analytics.log_org_event", _audit, raising=True
    )

    r = await async_client.get(f"{BASE}/{course.id}?tz=UTC", headers=headers)
    assert r.status_code == 200
    assert recorded.get("organization_id") == org.id
    assert recorded.get("action") == AuditEventType.GET_COURSE_ATTENDACE_SUMMARY
    meta = recorded.get("meta") or {}
    assert meta.get("course_id") == str(course.id)
    assert meta.get("from_cache") is False
    assert "rows" in meta


@pytest.mark.anyio
async def test_course_summary__500_error_path_logs_audit(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession, monkeypatch
):
    """
    Force an error *inside the route* without breaking dependencies:
    patch the module's `and_` used in the outerjoin filter assembly.
    """
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    course = await _mk_course(db_session, org_id=org.id)

    def _boom(*a, **k):
        raise RuntimeError("and_ exploded")
    monkeypatch.setattr("app.api.v1.course.live.analytics.and_", _boom, raising=True)

    recorded = {}
    async def _audit(**kwargs):
        recorded["organization_id"] = kwargs.get("organization_id")
        recorded["action"] = kwargs.get("action")
        recorded["meta"] = kwargs.get("meta_data")

    monkeypatch.setattr(
        "app.api.v1.course.live.analytics.log_org_event", _audit, raising=True
    )

    r = await async_client.get(f"{BASE}/{course.id}?tz=UTC", headers=headers)
    assert r.status_code == 500, r.text
    assert recorded.get("organization_id") == org.id
    assert recorded.get("action") == AuditEventType.GET_COURSE_ATTENDACE_SUMMARY
    assert "error" in (recorded.get("meta") or {})
