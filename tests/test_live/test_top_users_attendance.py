# tests/test_live/test_top_users_attendance.py

import json
from uuid import uuid4
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.core.redis_client import redis_wrapper
from app.utils.audit import AuditEventType
from app.db.models import LiveSession, LiveSessionAttendance

BASE = "/api/v1/course/live/analytics/top-users"


# ------------------------ helpers --------------------------------------------

async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
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
    # Route compares naive-UTC
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
async def test_top_users__200_empty_list_when_no_attendance(async_client: AsyncClient, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN)
    r = await async_client.get(f"{BASE}?tz=UTC", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json() == []


@pytest.mark.anyio
async def test_top_users__aggregates_and_order_desc_total_minutes(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    One user with 3 sessions -> total minutes = sum; sessions_attended matches distinct toggle
    due to unique (user, session).
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    base = datetime.now(timezone.utc) - timedelta(days=1)
    s1 = await _mk_session(db_session, org_id=org.id, title="A", start=base + timedelta(hours=1))
    s2 = await _mk_session(db_session, org_id=org.id, title="B", start=base + timedelta(hours=2))
    s3 = await _mk_session(db_session, org_id=org.id, title="C", start=base + timedelta(hours=3))

    await _mk_attendance(db_session, user_id=user.id, session_id=s1.id, joined_at=s1.start_time, minutes=10)
    await _mk_attendance(db_session, user_id=user.id, session_id=s2.id, joined_at=s2.start_time, minutes=30)
    await _mk_attendance(db_session, user_id=user.id, session_id=s3.id, joined_at=s3.start_time, minutes=20)

    r1 = await async_client.get(f"{BASE}?limit=5&distinct_sessions=false&tz=UTC", headers=headers)
    r2 = await async_client.get(f"{BASE}?limit=5&distinct_sessions=true&tz=UTC", headers=headers)
    assert r1.status_code == r2.status_code == 200
    body = r1.json()
    assert len(body) == 1
    assert body[0]["user_id"] == str(user.id)
    assert body[0]["total_minutes"] == 60
    assert body[0]["sessions_attended"] == 3
    # With unique (user, session), distinct toggle yields same result
    assert r1.json() == r2.json()


@pytest.mark.anyio
async def test_top_users__date_window_filters(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    With yday & today rows, querying [today, today] should include only today's minutes.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s_y = await _mk_session(db_session, org_id=org.id, title="Y")
    s_t = await _mk_session(db_session, org_id=org.id, title="T")

    today = datetime.now(timezone.utc).date()
    yday = today - timedelta(days=1)

    await _mk_attendance(db_session, user_id=user.id, session_id=s_y.id, joined_at=_utc_start_of(yday), minutes=15)
    await _mk_attendance(db_session, user_id=user.id, session_id=s_t.id, joined_at=_utc_start_of(today), minutes=25)

    r = await async_client.get(
        f"{BASE}?start_date={today}&end_date={today}&tz=UTC",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 1
    assert body[0]["user_id"] == str(user.id)
    assert body[0]["total_minutes"] == 25
    assert body[0]["sessions_attended"] == 1


@pytest.mark.anyio
async def test_top_users__end_only_inclusive_with_timezone(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    end_date is inclusive in the given tz (implemented via next-day exclusive).
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id, title="IST-edge")

    tz = "Asia/Kolkata"
    end_d = datetime.now(timezone.utc).date()

    ist = ZoneInfo(tz)
    join_local = datetime(end_d.year, end_d.month, end_d.day, 21, 30, 0, tzinfo=ist)  # 21:30 IST on end_d
    join_utc_naive = join_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
    await _mk_attendance(db_session, user_id=user.id, session_id=s.id, joined_at=join_utc_naive, minutes=50)

    r = await async_client.get(f"{BASE}?end_date={end_d}&tz={tz}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 1
    assert body[0]["user_id"] == str(user.id)
    assert body[0]["total_minutes"] == 50
    assert body[0]["sessions_attended"] == 1


@pytest.mark.anyio
async def test_top_users__forgiving_inverted_dates(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    start >= end -> route widens to [end-1day, end) (end exclusive).
    Ensure our row is strictly < end (today 00:00) so it is included.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id, title="Swap")

    today = datetime.now(timezone.utc).date()
    # Put the join at 23:59:59 yesterday (strictly inside the widened window)
    join_time = _utc_start_of(today) - timedelta(seconds=1)
    await _mk_attendance(db_session, user_id=user.id, session_id=s.id, joined_at=join_time, minutes=10)

    r = await async_client.get(
        f"{BASE}?start_date={today}&end_date={today - timedelta(days=1)}&tz=UTC",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) >= 1
    assert body[0]["user_id"] == str(user.id)
    assert body[0]["total_minutes"] >= 10



@pytest.mark.anyio
async def test_top_users__limit_validation_422(async_client: AsyncClient, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN)

    r = await async_client.get(f"{BASE}?limit=0", headers=headers)   # below min
    assert r.status_code == 422
    r = await async_client.get(f"{BASE}?limit=101", headers=headers)  # above max
    assert r.status_code == 422


@pytest.mark.anyio
async def test_top_users__cache_hit_short_circuit(
    async_client: AsyncClient, org_user_with_token, monkeypatch
):
    """
    Seed Redis with a deterministic key (explicit start/end), expect:
    - response equals cached payload
    - audit called with {"cache": "hit"}
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    tz = "UTC"
    start_d = date(2020, 1, 1)
    end_d = date(2020, 1, 31)
    limit = 5
    distinct = False

    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)

    cache_key = (
        f"topusers:v2:org:{org.id}:tz:{tz}"
        f":start:{start_utc}:end:{end_utc_excl}"
        f":distinct:{int(distinct)}:limit:{limit}"
    )
    cached = [
        {"user_id": str(user.id), "sessions_attended": 3, "total_minutes": 60},
        {"user_id": str(uuid4()), "sessions_attended": 2, "total_minutes": 40},
    ]
    await redis_wrapper.client.setex(cache_key, 60, json.dumps(cached, separators=(",", ":")))

    seen = {}
    async def _audit(**kwargs):
        seen["action"] = kwargs.get("action")
        seen["meta"] = kwargs.get("meta_data")

    # Patch where the route imports it
    monkeypatch.setattr("app.api.v1.course.live.analytics.log_org_event", _audit, raising=True)

    r = await async_client.get(
        f"{BASE}?start_date={start_d}&end_date={end_d}&tz={tz}&limit={limit}&distinct_sessions={'true' if distinct else 'false'}",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json() == cached
    assert seen.get("action") == AuditEventType.GET_TOP_ATTENDEES
    assert (seen.get("meta") or {}).get("cache") == "hit"
    assert (seen.get("meta") or {}).get("limit") == limit


@pytest.mark.anyio
async def test_top_users__use_cache_false_ignores_cache(
    async_client: AsyncClient, org_user_with_token
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    tz = "UTC"
    start_d = date(2020, 2, 1)
    end_d = date(2020, 2, 2)
    limit = 3
    distinct = True

    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)
    cache_key = (
        f"topusers:v2:org:{org.id}:tz:{tz}"
        f":start:{start_utc}:end:{end_utc_excl}"
        f":distinct:{int(distinct)}:limit:{limit}"
    )
    cached = [{"user_id": str(uuid4()), "sessions_attended": 9, "total_minutes": 999}]
    await redis_wrapper.client.setex(cache_key, 60, json.dumps(cached))

    r = await async_client.get(
        f"{BASE}?start_date={start_d}&end_date={end_d}&tz={tz}&use_cache=false&limit={limit}&distinct_sessions=true",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json() != cached  # cache ignored


@pytest.mark.anyio
async def test_top_users__corrupt_cache_falls_back(
    async_client: AsyncClient, org_user_with_token
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    tz = "UTC"
    start_d = date(2020, 3, 1)
    end_d = date(2020, 3, 3)
    limit = 5
    distinct = False

    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)
    cache_key = (
        f"topusers:v2:org:{org.id}:tz:{tz}"
        f":start:{start_utc}:end:{end_utc_excl}"
        f":distinct:{int(distinct)}:limit:{limit}"
    )
    await redis_wrapper.client.setex(cache_key, 60, "{not-json")

    r = await async_client.get(
        f"{BASE}?start_date={start_d}&end_date={end_d}&tz={tz}&limit={limit}&distinct_sessions=false",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    # Fallback response shape: list of {user_id, sessions_attended, total_minutes}
    assert isinstance(body, list)
    for row in body:
        assert set(row) == {"user_id", "sessions_attended", "total_minutes"}


@pytest.mark.anyio
async def test_top_users__audit_called_on_success(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id, title="Audit")
    await _mk_attendance(db_session, user_id=user.id, session_id=s.id, joined_at=datetime.now(timezone.utc), minutes=12)

    recorded = {}
    async def _audit(**kwargs):
        recorded["organization_id"] = kwargs.get("organization_id")
        recorded["action"] = kwargs.get("action")
        recorded["meta"] = kwargs.get("meta_data")

    monkeypatch.setattr("app.api.v1.course.live.analytics.log_org_event", _audit, raising=True)

    r = await async_client.get(f"{BASE}?limit=5&tz=UTC", headers=headers)
    assert r.status_code == 200, r.text
    assert recorded.get("organization_id") == org.id
    assert recorded.get("action") == AuditEventType.GET_TOP_ATTENDEES
    meta = recorded.get("meta") or {}
    assert meta.get("from_cache") is False
    assert meta.get("rows") >= 1
    assert meta.get("limit") == 5


@pytest.mark.anyio
async def test_top_users__500_error_path_logs_audit(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession, monkeypatch
):
    """
    Force an error inside the route without breaking dependencies:
    patch the module's `and_` used to compose filters in the WHERE clause.
    """
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    # Ensure there is at least one session so normal path would have worked
    await _mk_session(db_session, org_id=org.id, title="boom-prep")

    def _boom(*a, **k):
        raise RuntimeError("and_ exploded")
    monkeypatch.setattr("app.api.v1.course.live.analytics.and_", _boom, raising=True)

    recorded = {}
    async def _audit(**kwargs):
        recorded["organization_id"] = kwargs.get("organization_id")
        recorded["action"] = kwargs.get("action")
        recorded["meta"] = kwargs.get("meta_data")

    monkeypatch.setattr("app.api.v1.course.live.analytics.log_org_event", _audit, raising=True)

    r = await async_client.get(f"{BASE}?limit=5&tz=UTC", headers=headers)
    assert r.status_code == 500, r.text
    assert recorded.get("organization_id") == org.id
    assert recorded.get("action") == AuditEventType.GET_TOP_ATTENDEES
    assert "error" in (recorded.get("meta") or {})
