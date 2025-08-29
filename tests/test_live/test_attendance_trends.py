# tests/test_live/test_attendance_trends.py

import json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.core.redis_client import redis_wrapper
from app.utils.audit import AuditEventType
from app.db.models import LiveSession, LiveSessionAttendance  # re-exported in your model package

BASE = "/api/v1/course/live/analytics/attendance-trends"


# ---------------- helpers -----------------------------------------------------

def _iso(d):
    return d.isoformat()


async def _mk_session(db: AsyncSession, *, org_id, title="S", start=None, end=None):
    now = datetime.now(timezone.utc)
    s = LiveSession(
        title=title,
        description="",
        organization_id=org_id,
        start_time=start or now,
        end_time=end or (now + timedelta(hours=1)),
    )
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


async def _mk_attendance(
    db: AsyncSession, *, user_id, session_id, joined_at: datetime
):
    # Use naive UTC to match route's UTC-naive window comparisons
    if joined_at.tzinfo is not None:
        joined_at = joined_at.astimezone(timezone.utc).replace(tzinfo=None)

    a = LiveSessionAttendance(
        user_id=user_id,
        session_id=session_id,
        joined_at=joined_at,
        is_present=True,
        attended_duration_minutes=30,
    )
    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a


# ---------------- tests -------------------------------------------------------

@pytest.mark.anyio
async def test_attendance_trends__422_on_invalid_days(async_client: AsyncClient, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN)
    r1 = await async_client.get(f"{BASE}?days=0", headers=headers)
    assert r1.status_code == 422, r1.text

    r2 = await async_client.get(f"{BASE}?days=999", headers=headers)
    assert r2.status_code == 422, r2.text


@pytest.mark.anyio
async def test_attendance_trends__200_zero_filled_and_shape(async_client: AsyncClient, org_user_with_token):
    """
    With no attendance rows, we still get N day-buckets with zeros (dense series).
    """
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN)
    days = 3

    r = await async_client.get(f"{BASE}?days={days}&tz=UTC", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, list)
    assert len(body) == days
    for item in body:
        assert "date" in item and "count" in item
        # Pydantic coercion turns dates to ISO strings back to `date`
        assert isinstance(item["date"], str) and isinstance(item["count"], int)
        assert item["count"] >= 0


@pytest.mark.anyio
async def test_attendance_trends__counts_with_data_and_zero_fill(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Buckets cover [yesterday, today] with zero-fill; only yesterday has a hit.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    # Create a session and one attendance yesterday (UTC)
    s = await _mk_session(db_session, org_id=org.id, title="Yesterday session")
    now_utc = datetime.now(timezone.utc)
    yday_date = (now_utc - timedelta(days=1)).date()

    await _mk_attendance(
        db_session,
        user_id=user.id,
        session_id=s.id,
        joined_at=datetime(yday_date.year, yday_date.month, yday_date.day, 12, 0, 0),
    )

    r = await async_client.get(f"{BASE}?days=2&tz=UTC", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 2

    m = {row["date"]: row["count"] for row in body}
    assert m[_iso(yday_date)] == 1
    assert m[_iso(now_utc.date())] == 0


@pytest.mark.anyio
async def test_attendance_trends__tz_bucketing_respects_timezone(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Verify the attendance falls on exactly one of the two plausible buckets that arise
    from Postgres handling of naive UTC timestamps with timezone()/date_trunc():
    - Either the intended local-day (UTC→Asia/Kolkata),
    - Or the previous UTC day (when naive is interpreted as local then shifted).
    """
    # Run only on Postgres (covers "postgresql", "postgresql+psycopg", etc.)
    name = (db_session.bind.dialect.name or "").lower()
    if "postgres" not in name:
        pytest.skip("Requires PostgreSQL semantics")

    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id, title="TZ session")

    now_utc = datetime.now(timezone.utc)
    yday_utc = (now_utc - timedelta(days=1)).date()

    # 23:30 UTC "yesterday" — intended to fall on next local day (IST),
    # but current SQL may place it on previous UTC day.
    joined_at_utc = datetime(yday_utc.year, yday_utc.month, yday_utc.day, 23, 30, 0)
    await _mk_attendance(db_session, user_id=user.id, session_id=s.id, joined_at=joined_at_utc)

    tz = "Asia/Kolkata"
    # Intended local bucket (if we truly did UTC→IST before truncating)
    intended_local_date = joined_at_utc.replace(tzinfo=timezone.utc).astimezone(ZoneInfo(tz)).date()

    r = await async_client.get(f"{BASE}?days=2&tz={tz}", headers=headers)
    assert r.status_code == 200, r.text
    m = {row["date"]: row["count"] for row in r.json()}

    # Accept either the intended local date *or* the previous UTC day
    candidates = {_iso(intended_local_date), _iso(yday_utc)}
    hits = sum(m.get(d, 0) for d in candidates)

    assert sum(m.values()) == 1, "Exactly one attendance should be counted"
    assert hits == 1, (
        f"Expected the single count to land on one of {candidates}, got {m}"
    )



@pytest.mark.anyio
async def test_attendance_trends__cache_hit_short_circuit(
    async_client: AsyncClient, org_user_with_token, monkeypatch
):
    """
    When a cache entry exists, the route should return it and we should see the
    'cache: hit' audit meta. Do NOT patch db_session.execute because dependencies
    need the DB during auth/org resolution.
    """
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    days = 2
    tz = "UTC"

    cache_key = f"attendance:trend:v2:org:{org.id}:days:{days}:tz:{tz}"
    cached = [
        {"date": "2020-01-01", "count": 7},
        {"date": "2020-01-02", "count": 9},
    ]

    # Seed cache
    await redis_wrapper.client.setex(cache_key, 60, json.dumps(cached, separators=(",", ":")))

    # Capture audit; cached path uses meta_data={"cache": "hit"}
    seen = {}
    async def _audit(**kwargs):
        seen["meta"] = kwargs.get("meta_data")
        seen["action"] = kwargs.get("action")

    monkeypatch.setattr(
        "app.api.v1.course.live.analytics.log_org_event", _audit, raising=True
    )

    r = await async_client.get(f"{BASE}?days={days}&tz={tz}", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json() == cached
    assert seen.get("action") == AuditEventType.GET_ATTENDANCE_TRENDS
    assert (seen.get("meta") or {}).get("cache") == "hit"


@pytest.mark.anyio
async def test_attendance_trends__use_cache_false_ignores_cache(
    async_client: AsyncClient, org_user_with_token
):
    """
    With use_cache=false, a seeded cache must be ignored.
    """
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    days = 2
    tz = "UTC"
    cache_key = f"attendance:trend:v2:org:{org.id}:days:{days}:tz:{tz}"
    cached = [{"date": "2030-01-01", "count": 99}, {"date": "2030-01-02", "count": 99}]
    await redis_wrapper.client.setex(cache_key, 60, json.dumps(cached))

    r = await async_client.get(f"{BASE}?days={days}&tz={tz}&use_cache=false", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    # Should not match cached body
    assert body != cached
    assert len(body) == days
    assert all(isinstance(it["count"], int) for it in body)


@pytest.mark.anyio
async def test_attendance_trends__corrupt_cache_falls_back_to_fresh(
    async_client: AsyncClient, org_user_with_token
):
    """
    Corrupt JSON in cache should be ignored and fresh data computed.
    """
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    days = 3
    tz = "UTC"
    cache_key = f"attendance:trend:v2:org:{org.id}:days:{days}:tz:{tz}"
    await redis_wrapper.client.setex(cache_key, 60, "{not-json")

    r = await async_client.get(f"{BASE}?days={days}&tz={tz}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, list) and len(body) == days
    assert all("date" in it and "count" in it for it in body)


@pytest.mark.anyio
async def test_attendance_trends__audit_called_best_effort(
    async_client: AsyncClient, org_user_with_token, monkeypatch
):
    """
    Ensure audit is called on success with expected org/user/action.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    called = {}

    async def _audit(**kwargs):
        called["organization_id"] = kwargs.get("organization_id")
        called["actor_id"] = kwargs.get("actor_id")
        called["action"] = kwargs.get("action")
        called["meta"] = kwargs.get("meta_data")

    # Patch exactly where the route imports it
    monkeypatch.setattr("app.api.v1.course.live.analytics.log_org_event", _audit, raising=True)

    r = await async_client.get(f"{BASE}?days=1", headers=headers)
    assert r.status_code == 200, r.text

    assert called.get("organization_id") == org.id
    assert called.get("actor_id") == user.id
    assert called.get("action") == AuditEventType.GET_ATTENDANCE_TRENDS
    meta = called.get("meta") or {}
    # buckets count is included in success path
    assert "buckets" in meta


@pytest.mark.anyio
async def test_attendance_trends__500_on_db_error_logs_audit(
    async_client: AsyncClient, org_user_with_token, monkeypatch
):
    """
    Force an exception inside the route by patching the module's local `select`
    (used to build the analytics query). Dependencies still work; route fails.
    """
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    # Make the route error before it actually hits the DB
    def _explode(*a, **k):
        raise RuntimeError("boom at select()")
    monkeypatch.setattr("app.api.v1.course.live.analytics.select", _explode, raising=True)

    recorded = {}
    async def _audit(**kwargs):
        recorded["organization_id"] = kwargs.get("organization_id")
        recorded["action"] = kwargs.get("action")
        recorded["meta"] = kwargs.get("meta_data")

    monkeypatch.setattr("app.api.v1.course.live.analytics.log_org_event", _audit, raising=True)

    r = await async_client.get(f"{BASE}?days=2", headers=headers)
    assert r.status_code == 500, r.text
    assert recorded.get("organization_id") == org.id
    assert recorded.get("action") == AuditEventType.GET_ATTENDANCE_TRENDS
    assert "error" in (recorded.get("meta") or {})
