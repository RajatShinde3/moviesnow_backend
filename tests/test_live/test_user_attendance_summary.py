# tests/test_live/test_user_attendance_summary.py

import json
from uuid import uuid4
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

# Project-level imports – adjust if your paths differ
from app.schemas.enums import OrgRole
from app.core.redis_client import redis_wrapper
from app.utils.audit import AuditEventType
from app.db.models import LiveSession, LiveSessionAttendance

BASE = "/api/v1/course/live/analytics/user"


# ------------------------ helpers --------------------------------------------

async def _mk_session(db: AsyncSession, *, org_id, title="S", start=None, end=None, is_deleted=False):
    now = datetime.now(timezone.utc)
    s = LiveSession(
        title=title,
        description="",
        organization_id=org_id,
        start_time=start or now,
        end_time=end or (now + timedelta(hours=1)),
        is_deleted=is_deleted,
    )
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
    # Route stores/compares naive UTC; normalize to naive UTC if tz-aware
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
    """Matches the route’s: datetime.combine(d, 00:00, tz).astimezone(UTC).replace(tzinfo=None)"""
    return (
        datetime.combine(d, datetime.min.time(), ZoneInfo(tz))
        .astimezone(ZoneInfo("UTC"))
        .replace(tzinfo=None)
    )


def _to_utc_naive_local_next_day_start(d: date, tz: str) -> datetime:
    """Inclusive end-of-day -> exclusive next-day midnight (local), then to naive UTC"""
    return (
        datetime.combine(d + timedelta(days=1), datetime.min.time(), ZoneInfo(tz))
        .astimezone(ZoneInfo("UTC"))
        .replace(tzinfo=None)
    )


# ------------------------ tests ----------------------------------------------

@pytest.mark.anyio
async def test_user_summary__404_when_user_not_in_org(async_client: AsyncClient, org_user_with_token):
    _, headers, _org = await org_user_with_token(role=OrgRole.ADMIN)
    not_in_org_id = uuid4()

    r = await async_client.get(f"{BASE}/{not_in_org_id}", headers=headers)
    assert r.status_code == 404, r.text
    assert r.json()["detail"].lower().startswith("user not found")


@pytest.mark.anyio
async def test_user_summary__200_zero_default(async_client: AsyncClient, org_user_with_token):
    user, headers, _org = await org_user_with_token(role=OrgRole.ADMIN)

    r = await async_client.get(f"{BASE}/{user.id}?tz=UTC", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user_id"] == str(user.id)
    assert body["sessions_attended"] == 0
    assert body["total_minutes"] == 0


@pytest.mark.anyio
async def test_user_summary__counts_and_minutes(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s1 = await _mk_session(db_session, org_id=org.id, title="A")
    s2 = await _mk_session(db_session, org_id=org.id, title="B")

    today = datetime.now(timezone.utc).date()
    await _mk_attendance(db_session, user_id=user.id, session_id=s1.id, joined_at=_utc_start_of(today), minutes=25)
    await _mk_attendance(db_session, user_id=user.id, session_id=s2.id, joined_at=_utc_start_of(today), minutes=35)

    r = await async_client.get(f"{BASE}/{user.id}?tz=UTC", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sessions_attended"] == 2
    assert body["total_minutes"] == 60


@pytest.mark.anyio
async def test_user_summary__null_safe_sum_and_soft_deleted_excluded(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    s_ok = await _mk_session(db_session, org_id=org.id, title="OK")
    s_deleted = await _mk_session(db_session, org_id=org.id, title="DELETED", is_deleted=True)

    today = datetime.now(timezone.utc).date()
    # minutes None should be ignored by SUM (NULL-safe via COALESCE on the SUM)
    await _mk_attendance(db_session, user_id=user.id, session_id=s_ok.id, joined_at=_utc_start_of(today), minutes=None)
    # soft-deleted session should not be counted at all
    await _mk_attendance(db_session, user_id=user.id, session_id=s_deleted.id, joined_at=_utc_start_of(today), minutes=999)

    r = await async_client.get(f"{BASE}/{user.id}?tz=UTC", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sessions_attended"] == 1
    assert body["total_minutes"] == 0


@pytest.mark.anyio
async def test_user_summary__date_window_start_and_end_in_utc(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    tz = "UTC"
    today = datetime.now(timezone.utc).date()
    yday = today - timedelta(days=1)
    tmrw = today + timedelta(days=1)

    # Use different sessions for each attendance to avoid (user, session) duplicates
    s_y = await _mk_session(db_session, org_id=org.id, title="Y")   # yesterday
    s_t = await _mk_session(db_session, org_id=org.id, title="T")   # today
    s_n = await _mk_session(db_session, org_id=org.id, title="N")   # tomorrow

    await _mk_attendance(db_session, user_id=user.id, session_id=s_y.id, joined_at=_utc_start_of(yday), minutes=10)
    await _mk_attendance(db_session, user_id=user.id, session_id=s_t.id, joined_at=_utc_start_of(today), minutes=20)
    await _mk_attendance(db_session, user_id=user.id, session_id=s_n.id, joined_at=_utc_start_of(tmrw), minutes=30)

    # Range [yday, today] inclusive -> next-day exclusive
    r = await async_client.get(f"{BASE}/{user.id}?start_date={yday}&end_date={today}&tz={tz}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sessions_attended"] == 2
    assert body["total_minutes"] == 30



@pytest.mark.anyio
async def test_user_summary__start_only_caps_end_to_now(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    today = datetime.now(timezone.utc).date()
    yday = today - timedelta(days=1)
    two_days_ago = today - timedelta(days=2)

    # Different sessions for each attendance
    s_2d = await _mk_session(db_session, org_id=org.id, title="2D")
    s_yd = await _mk_session(db_session, org_id=org.id, title="YD")
    s_td = await _mk_session(db_session, org_id=org.id, title="TD")

    await _mk_attendance(db_session, user_id=user.id, session_id=s_2d.id, joined_at=_utc_start_of(two_days_ago), minutes=5)
    await _mk_attendance(db_session, user_id=user.id, session_id=s_yd.id, joined_at=_utc_start_of(yday), minutes=15)
    await _mk_attendance(db_session, user_id=user.id, session_id=s_td.id, joined_at=_utc_start_of(today), minutes=25)

    # start only at yday -> should count yday + today
    r = await async_client.get(f"{BASE}/{user.id}?start_date={yday}&tz=UTC", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sessions_attended"] == 2
    assert body["total_minutes"] == 40


@pytest.mark.anyio
async def test_user_summary__end_only_is_inclusive_local_day(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    tz = "Asia/Kolkata"  # test end-of-day logic with tz
    end_d = datetime.now(timezone.utc).date()

    # Place an attendance at 21:30 IST on end_d (which is 16:00 UTC)
    ist = ZoneInfo(tz)
    join_local = datetime(end_d.year, end_d.month, end_d.day, 21, 30, 0, tzinfo=ist)
    join_utc_naive = join_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

    await _mk_attendance(db_session, user_id=user.id, session_id=s.id, joined_at=join_utc_naive, minutes=50)

    # Provide only end_date=end_d -> should include the row (end is inclusive by converting to next-day midnight exclusive)
    r = await async_client.get(f"{BASE}/{user.id}?end_date={end_d}&tz={tz}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sessions_attended"] == 1
    assert body["total_minutes"] == 50


@pytest.mark.anyio
async def test_user_summary__inverted_dates_are_forgiven(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    today = datetime.now(timezone.utc).date()
    yday = today - timedelta(days=1)

    await _mk_attendance(db_session, user_id=user.id, session_id=s.id, joined_at=_utc_start_of(yday), minutes=10)

    # Pass start_date AFTER end_date; route swaps internally
    r = await async_client.get(f"{BASE}/{user.id}?start_date={today}&end_date={yday}&tz=UTC", headers=headers)
    assert r.status_code == 200, r.text
    # With the forgiving swap to (end-1day, end), we still should get >=1 when data exists
    assert r.json()["sessions_attended"] >= 1


@pytest.mark.anyio
async def test_user_summary__cache_hit_short_circuit(
    async_client: AsyncClient, org_user_with_token, monkeypatch
):
    """
    Seed Redis with a deterministic key (both start and end provided), expect:
    - response equals cached payload
    - audit called with {"cache":"hit"}
    NOTE: do not patch db_session.execute to avoid breaking dependencies.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    tz = "UTC"
    start_d = date(2020, 1, 1)
    end_d = date(2020, 1, 31)

    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)

    cache_key = (
        f"user:attendance:v2:org:{org.id}:user:{user.id}:tz:{tz}:"
        f"start:{start_utc}:end:{end_utc_excl}"
    )
    cached = {"user_id": str(user.id), "sessions_attended": 42, "total_minutes": 9001}
    await redis_wrapper.client.setex(cache_key, 60, json.dumps(cached, separators=(",", ":")))

    seen = {}
    async def _audit(**kwargs):
        seen["meta"] = kwargs.get("meta_data")
        seen["action"] = kwargs.get("action")

    monkeypatch.setattr(
        "app.api.v1.course.live.analytics.log_org_event", _audit, raising=True
    )

    r = await async_client.get(
        f"{BASE}/{user.id}?start_date={start_d}&end_date={end_d}&tz={tz}",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json() == cached
    assert seen.get("action") == AuditEventType.GET_USER_ATTENDENCE_SUMMARY
    assert (seen.get("meta") or {}).get("cache") == "hit"


@pytest.mark.anyio
async def test_user_summary__use_cache_false_ignores_cache(
    async_client: AsyncClient, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    tz = "UTC"
    start_d = date(2020, 2, 1)
    end_d = date(2020, 2, 2)

    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)
    cache_key = (
        f"user:attendance:v2:org:{org.id}:user:{user.id}:tz:{tz}:"
        f"start:{start_utc}:end:{end_utc_excl}"
    )
    cached = {"user_id": str(user.id), "sessions_attended": 99, "total_minutes": 1234}
    await redis_wrapper.client.setex(cache_key, 60, json.dumps(cached))

    r = await async_client.get(
        f"{BASE}/{user.id}?start_date={start_d}&end_date={end_d}&tz={tz}&use_cache=false",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json() != cached  # ignored


@pytest.mark.anyio
async def test_user_summary__corrupt_cache_falls_back(
    async_client: AsyncClient, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    tz = "UTC"
    start_d = date(2020, 3, 1)
    end_d = date(2020, 3, 1)

    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)
    cache_key = (
        f"user:attendance:v2:org:{org.id}:user:{user.id}:tz:{tz}:"
        f"start:{start_utc}:end:{end_utc_excl}"
    )
    await redis_wrapper.client.setex(cache_key, 60, "{not-json")

    r = await async_client.get(
        f"{BASE}/{user.id}?start_date={start_d}&end_date={end_d}&tz={tz}",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"user_id", "sessions_attended", "total_minutes"}


@pytest.mark.anyio
async def test_user_summary__audit_called_on_success(
    async_client: AsyncClient, org_user_with_token, monkeypatch
):
    user, headers, _org = await org_user_with_token(role=OrgRole.ADMIN)

    recorded = {}
    async def _audit(**kwargs):
        recorded["actor_id"] = kwargs.get("actor_id")
        recorded["organization_id"] = kwargs.get("organization_id")
        recorded["action"] = kwargs.get("action")
        recorded["meta"] = kwargs.get("meta_data")

    monkeypatch.setattr(
        "app.api.v1.course.live.analytics.log_org_event", _audit, raising=True
    )

    r = await async_client.get(f"{BASE}/{user.id}?tz=UTC", headers=headers)
    assert r.status_code == 200, r.text
    assert recorded.get("actor_id") == user.id
    assert recorded.get("action") == AuditEventType.GET_USER_ATTENDENCE_SUMMARY
    meta = recorded.get("meta") or {}
    assert meta.get("from_cache") is False
    assert meta.get("target_user_id") == str(user.id)
    assert "sessions_attended" in meta and "total_minutes" in meta


@pytest.mark.anyio
async def test_user_summary__500_error_path_logs_audit(
    async_client: AsyncClient, org_user_with_token, monkeypatch
):
    """
    Force an error *inside the route* without breaking dependencies:
    patch the module's `and_` used only in the aggregate query (membership check doesn't use it).
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    def _boom(*a, **k):
        raise RuntimeError("and_ boom")
    monkeypatch.setattr("app.api.v1.course.live.analytics.and_", _boom, raising=True)

    recorded = {}
    async def _audit(**kwargs):
        recorded["organization_id"] = kwargs.get("organization_id")
        recorded["action"] = kwargs.get("action")
        recorded["meta"] = kwargs.get("meta_data")

    monkeypatch.setattr(
        "app.api.v1.course.live.analytics.log_org_event", _audit, raising=True
    )

    r = await async_client.get(f"{BASE}/{user.id}?tz=UTC", headers=headers)
    assert r.status_code == 500, r.text
    assert recorded.get("organization_id") == org.id
    assert recorded.get("action") == AuditEventType.GET_USER_ATTENDENCE_SUMMARY
    assert "error" in (recorded.get("meta") or {})
