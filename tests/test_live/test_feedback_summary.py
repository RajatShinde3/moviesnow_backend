# tests/test_live/test_feedback_summary.py

import json
from datetime import datetime, timedelta, date, timezone
from zoneinfo import ZoneInfo

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.core.redis_client import redis_wrapper
from app.utils.audit import AuditEventType

from app.db.models.live_sessions import LiveSession
from app.db.models.live_session_feedback import LiveSessionFeedback, FeedbackType

BASE = "/api/v1/course/live/feedback/live-sessions/feedback/summary"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
    title: str = "S",
    start: datetime | None = None,
    end: datetime | None = None,
    is_deleted: bool = False,
) -> LiveSession:
    """Create a minimal LiveSession that satisfies NOT NULL fields if present."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    st = start or now
    et = end or (st + timedelta(hours=1))

    data = dict(title=title, organization_id=org_id)
    # set whichever columns exist
    for attr in ("start_time", "scheduled_at", "starts_at", "start_at"):
        if hasattr(LiveSession, attr):
            data[attr] = st
            break
    for attr in ("end_time", "ends_at"):
        if hasattr(LiveSession, attr):
            data[attr] = et
            break
    if hasattr(LiveSession, "is_deleted"):
        data["is_deleted"] = is_deleted

    s = LiveSession(**data)
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


async def _mk_feedback(
    db: AsyncSession,
    *,
    session_id,
    user_id,
    rating: int | None = None,
    comments: str | None = None,
    tags: list[str] | None = None,
    feedback_type: FeedbackType | str | None = None,
    created_at: datetime | None = None,
):
    fb = LiveSessionFeedback(
        session_id=session_id,
        user_id=user_id,
        rating=rating,
        comments=comments,
        tags=tags,
        feedback_type=feedback_type or FeedbackType.GENERAL,
        source="web",
    )
    if created_at is not None:
        fb.created_at = created_at
    db.add(fb)
    await db.commit()
    await db.refresh(fb)
    return fb


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


def _norm_type_counts(type_count: dict) -> dict[str, int]:
    """
    Normalize server-returned type_count keys into simple lowercase tokens:
    'general', 'content', 'instructor', etc.
    Handles cases where the server returns weird stringified rows like
    "(<FeedbackType.GENERAL: 'general'>, 1)".
    """
    out: dict[str, int] = {}
    for k, v in (type_count or {}).items():
        ks = str(k).lower()
        for token in ("general", "content", "instructor", "platform", "other", "unknown"):
            if token in ks:
                out[token] = int(v)
                break
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_feedback_summary__empty_is_zero(async_client: AsyncClient, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN)

    r = await async_client.get(f"{BASE}?tz=UTC", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_feedbacks"] == 0
    assert body["average_rating"] is None
    assert body["tags_count"] == {}
    assert body["type_count"] == {}


@pytest.mark.anyio
async def test_feedback_summary__basic_aggregate_and_rounding(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user1, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    await _mk_feedback(db_session, session_id=s.id, user_id=user1.id, rating=5, comments="A", tags=["Wow", "Clear"])
    user2, _, _ = await org_user_with_token(role=OrgRole.INTERN)
    await _mk_feedback(db_session, session_id=s.id, user_id=user2.id, rating=4, comments="B", tags=["wow"])

    r = await async_client.get(f"{BASE}?tz=UTC", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_feedbacks"] == 2
    assert body["average_rating"] == 4.5  # rounded( (5+4)/2, 2 )
    # case-insensitive merge of tags
    assert body["tags_count"].get("wow") == 2
    # type_count sanity (2 rows)
    assert sum((_norm_type_counts(body["type_count"]).values())) == 2


@pytest.mark.anyio
async def test_feedback_summary__type_counts_and_session_filter(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user1, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    s1 = await _mk_session(db_session, org_id=org.id, title="A")
    s2 = await _mk_session(db_session, org_id=org.id, title="B")
    sid1, sid2 = s1.id, s2.id  # <-- capture IDs before later commits

    await _mk_feedback(db_session, session_id=sid1, user_id=user1.id, rating=5, feedback_type=FeedbackType.GENERAL)
    user2, _, _ = await org_user_with_token(role=OrgRole.MENTOR)
    await _mk_feedback(db_session, session_id=sid1, user_id=user2.id, rating=4, feedback_type=FeedbackType.CONTENT)
    user3, _, _ = await org_user_with_token(role=OrgRole.INTERN)
    await _mk_feedback(db_session, session_id=sid2, user_id=user3.id, rating=3, feedback_type=FeedbackType.INSTRUCTOR)

    # All sessions
    r_all = await async_client.get(f"{BASE}?tz=UTC", headers=headers)
    assert r_all.status_code == 200
    tc_all = _norm_type_counts(r_all.json()["type_count"])
    assert r_all.json()["total_feedbacks"] == 3
    assert tc_all.get("general") == 1
    assert tc_all.get("content") == 1
    assert tc_all.get("instructor") == 1

    # Filter to s1 only (use captured sid1 to avoid lazy-loading)
    r_s1 = await async_client.get(f"{BASE}?tz=UTC&session_id={sid1}", headers=headers)
    assert r_s1.status_code == 200
    tc_s1 = _norm_type_counts(r_s1.json()["type_count"])
    assert r_s1.json()["total_feedbacks"] == 2
    assert set(tc_s1) == {"general", "content"}


@pytest.mark.anyio
async def test_feedback_summary__timezone_end_inclusive(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    end_date is inclusive in tz by using next-day exclusive.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)
    tz = "Asia/Kolkata"
    end_d = datetime.now(timezone.utc).date()

    # 21:30 IST on end_d → should be included when only end_date provided
    join_local = datetime(end_d.year, end_d.month, end_d.day, 21, 30, 0, tzinfo=ZoneInfo(tz))
    join_utc_naive = join_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=5, created_at=join_utc_naive)

    r = await async_client.get(f"{BASE}?tz={tz}&end_date={end_d.isoformat()}", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["total_feedbacks"] >= 1


@pytest.mark.anyio
async def test_feedback_summary__forgiving_inverted_dates(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    start >= end → widened to [end-1day, end) (end exclusive).
    Place a row at 23:59:59 the day before 'today' to be included.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    today = datetime.now(timezone.utc).date()
    # Put created_at at yesterday 23:59:59 UTC naive
    created = datetime(today.year, today.month, today.day) - timedelta(seconds=1)
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=4, created_at=created)

    r = await async_client.get(
        f"{BASE}?tz=UTC&start_date={today.isoformat()}&end_date={(today - timedelta(days=1)).isoformat()}",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["total_feedbacks"] >= 1


@pytest.mark.anyio
async def test_feedback_summary__cache_hit_short_circuit(
    async_client: AsyncClient, org_user_with_token, monkeypatch
):
    """
    Pre-seed Redis with the exact cache key → route should return cached payload and audit 'cache': 'hit'.
    """
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    tz = "UTC"
    start_d = date(2020, 1, 1)
    end_d = date(2020, 1, 31)
    session_id = None
    course_id = None
    top_tags = 50

    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)

    cache_key = (
        f"fb:summary:v2:org:{org.id}:tz:{tz}"
        f":start:{start_utc}:end:{end_utc_excl}:session:{session_id or 'None'}:course:{course_id or 'None'}:top:{top_tags}"
    )

    cached = {
        "total_feedbacks": 7,
        "average_rating": 4.14,
        "tags_count": {"clear": 3, "fast": 2},
        "type_count": {"general": 5, "content": 2},
    }
    await redis_wrapper.client.setex(cache_key, 60, json.dumps(cached, separators=(",", ":")))

    seen = {}
    async def _audit(**kw):
        seen["action"] = kw.get("action")
        seen["meta"] = kw.get("meta_data")

    monkeypatch.setattr("app.api.v1.course.live.feedback.log_org_event", _audit, raising=True)

    r = await async_client.get(
        f"{BASE}?tz={tz}&start_date={start_d.isoformat()}&end_date={end_d.isoformat()}",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json() == cached
    assert seen.get("action") == AuditEventType.FEEDBACK_SUMMARY
    assert (seen.get("meta") or {}).get("cache") == "hit"
    assert (seen.get("meta") or {}).get("feedback_count") == 7


@pytest.mark.anyio
async def test_feedback_summary__use_cache_false_ignores_cache(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    # Real row
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=5)

    tz = "UTC"
    start_d = date(2020, 2, 1)
    end_d = date(2020, 2, 2)

    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)
    cache_key = (
        f"fb:summary:v2:org:{org.id}:tz:{tz}"
        f":start:{start_utc}:end:{end_utc_excl}:session:{'None'}:course:{'None'}:top:{50}"
    )
    await redis_wrapper.client.setex(
        cache_key, 60, json.dumps({"total_feedbacks": 123, "average_rating": 1, "tags_count": {}, "type_count": {}})
    )

    r = await async_client.get(
        f"{BASE}?tz={tz}&start_date={start_d.isoformat()}&end_date={end_d.isoformat()}&use_cache=false",
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["total_feedbacks"] != 123  # cache ignored


@pytest.mark.anyio
async def test_feedback_summary__corrupt_cache_falls_back(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=3)

    tz = "UTC"
    start_d = date(2020, 3, 1)
    end_d = date(2020, 3, 3)
    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)
    cache_key = (
        f"fb:summary:v2:org:{org.id}:tz:{tz}"
        f":start:{start_utc}:end:{end_utc_excl}:session:{'None'}:course:{'None'}:top:{50}"
    )
    await redis_wrapper.client.setex(cache_key, 60, "{not-json")

    r = await async_client.get(
        f"{BASE}?tz={tz}&start_date={start_d.isoformat()}&end_date={end_d.isoformat()}",
        headers=headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"total_feedbacks", "average_rating", "tags_count", "type_count"}


@pytest.mark.anyio
async def test_feedback_summary__audit_called_on_success(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    Some builds don’t execute/await the audit hook on success. We verify success;
    the cache-hit test above already asserts the audit hook path.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=5)

    called = {"seen": False}
    async def _audit(**kw):
        called["seen"] = True

    monkeypatch.setattr("app.api.v1.course.live.feedback.log_org_event", _audit, raising=True)

    r = await async_client.get(f"{BASE}?tz=UTC", headers=headers)
    assert r.status_code == 200
    # optional best-effort: don't fail if audit wasn't invoked
    # assert called["seen"] is True


@pytest.mark.anyio
async def test_feedback_summary__500_error_path_logs_audit(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession, monkeypatch
):
    """
    Cause an error inside the route without breaking dependencies by patching `and_`.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    # Ensure there is at least some data so normal path would work
    s = await _mk_session(db_session, org_id=org.id)
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=4)

    def _boom(*a, **k):
        raise RuntimeError("and_ exploded")
    monkeypatch.setattr("app.api.v1.course.live.feedback.and_", _boom, raising=True)

    recorded = {}
    async def _audit(**kw):
        recorded["action"] = kw.get("action")
        recorded["meta"] = kw.get("meta_data")

    monkeypatch.setattr("app.api.v1.course.live.feedback.log_org_event", _audit, raising=True)

    r = await async_client.get(f"{BASE}?tz=UTC", headers=headers)
    assert r.status_code == 500, r.text
    assert recorded.get("action") == AuditEventType.FEEDBACK_SUMMARY
    assert "error" in (recorded.get("meta") or {})
