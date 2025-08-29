# tests/test_live/test_list_all_feedbacks.py

import json
from uuid import uuid4, UUID
from datetime import datetime, timedelta, date, timezone
from zoneinfo import ZoneInfo
from typing import Optional

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.core.redis_client import redis_wrapper
from app.utils.audit import AuditEventType

from app.db.models.live_sessions import LiveSession
from app.db.models.live_session_feedback import LiveSessionFeedback, FeedbackType

# Try to import Course for the course_id filter test; skip if not present
try:
    from app.db.models.course import Course  # type: ignore
except Exception:  # pragma: no cover
    Course = None  # type: ignore

BASE = "/api/v1/course/live/feedback/live-sessions"  # full path = {BASE}/all


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
    course_id: Optional[UUID] = None,
) -> LiveSession:
    """Create a minimal LiveSession that satisfies NOT NULL fields if present."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    st = start or now
    et = end or (st + timedelta(hours=1))

    data = dict(title=title, organization_id=org_id)
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
    if course_id is not None and hasattr(LiveSession, "course_id"):
        data["course_id"] = course_id

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


def _cache_key(
    *,
    org_id,
    tz: str,
    start_utc: datetime | None,
    end_utc_excl: datetime | None,
    min_rating: int | None = None,
    max_rating: int | None = None,
    search: str | None = None,
    feedback_type: str | None = None,
    user_id: UUID | None = None,
    session_id: UUID | None = None,
    course_id: UUID | None = None,
    tags_any: list[str] | None = None,
    tags_all: list[str] | None = None,
    sort_by: str = "newest",
    limit: int = 50,
    offset: int = 0,
) -> str:
    # must mirror app route
    return (
        f"fb:all:v2:org:{org_id}:tz:{tz}"
        f":start:{start_utc or 'None'}:end:{end_utc_excl or 'None'}"
        f":min:{min_rating}:max:{max_rating}"
        f":search:{(search or '').strip().lower()[:40]}"
        f":ftype:{(feedback_type or '').lower()}"
        f":user:{user_id or 'None'}:session:{session_id or 'None'}:course:{course_id or 'None'}"
        f":any:{','.join((t or '').lower() for t in (tags_any or [])[:6])}"
        f":all:{','.join((t or '').lower() for t in (tags_all or [])[:6])}"
        f":sort:{sort_by}:limit:{limit}:offset:{offset}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_admin_list_all__403_for_non_admin(async_client: AsyncClient, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.MENTOR)
    r = await async_client.get(f"{BASE}/all?tz=UTC", headers=headers)
    assert r.status_code == 403, r.text


@pytest.mark.anyio
async def test_admin_list_all__empty_ok(async_client: AsyncClient, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN)
    r = await async_client.get(f"{BASE}/all?tz=UTC", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json() == []


@pytest.mark.anyio
async def test_admin_list_all__basic_filters_and_sorting(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s1 = await _mk_session(db_session, org_id=org.id, title="A")
    s2 = await _mk_session(db_session, org_id=org.id, title="B")

    # Keep these in the past so implicit end<now window includes them
    t0 = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=30)
    await _mk_feedback(db_session, session_id=s1.id, user_id=admin.id, rating=2, comments="old", created_at=t0)
    await _mk_feedback(db_session, session_id=s1.id, user_id=admin.id, rating=5, comments="new", created_at=t0 + timedelta(seconds=10))
    await _mk_feedback(db_session, session_id=s2.id, user_id=admin.id, rating=3, comments="mid", created_at=t0 + timedelta(seconds=5))

    # newest
    r_new = await async_client.get(f"{BASE}/all?sort_by=newest&tz=UTC", headers=headers)
    assert r_new.status_code == 200, r_new.text
    comments_new = [row["comments"] for row in r_new.json()]
    assert "new" in comments_new and comments_new.index("new") < comments_new.index("old")

    # oldest
    r_old = await async_client.get(f"{BASE}/all?sort_by=oldest&tz=UTC", headers=headers)
    assert r_old.status_code == 200
    assert [row["comments"] for row in r_old.json()][0] == "old"

    # highest_rating
    r_hi = await async_client.get(f"{BASE}/all?sort_by=highest_rating&tz=UTC", headers=headers)
    assert r_hi.status_code == 200
    assert r_hi.json()[0]["rating"] == 5

    # lowest_rating
    r_lo = await async_client.get(f"{BASE}/all?sort_by=lowest_rating&tz=UTC", headers=headers)
    assert r_lo.status_code == 200
    assert r_lo.json()[0]["rating"] == 2

    # rating range filter
    r_range = await async_client.get(f"{BASE}/all?min_rating=3&max_rating=5&tz=UTC", headers=headers)
    assert r_range.status_code == 200
    got = [row["comments"] for row in r_range.json()]
    assert set(got) == {"mid", "new"}


@pytest.mark.anyio
async def test_admin_list_all__search_keyword_ilike(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)
    await _mk_feedback(db_session, session_id=s.id, user_id=admin.id, rating=4, comments="Great session indeed")

    r = await async_client.get(f"{BASE}/all?tz=UTC&search=great", headers=headers)
    assert r.status_code == 200
    assert any("Great" in row["comments"] for row in r.json())


@pytest.mark.anyio
async def test_admin_list_all__tags_any_all_python_fallback(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    await _mk_feedback(db_session, session_id=s.id, user_id=admin.id, rating=5, comments="A", tags=["Wow", "Clear"])
    await _mk_feedback(db_session, session_id=s.id, user_id=admin.id, rating=4, comments="B", tags=["clear"])

    # ANY=wow -> A included
    r_any = await async_client.get(f"{BASE}/all?tz=UTC&tags_any=wow", headers=headers)
    assert r_any.status_code == 200
    assert any(row["comments"] == "A" for row in r_any.json())

    # ALL=wow,clear -> only A
    r_all = await async_client.get(f"{BASE}/all?tz=UTC&tags_all=wow&tags_all=clear", headers=headers)
    assert r_all.status_code == 200
    comments = [row["comments"] for row in r_all.json()]
    assert comments == ["A"]


@pytest.mark.anyio
async def test_admin_list_all__timezone_window_inclusive(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)
    tz = "Asia/Kolkata"
    end_d = datetime.now(timezone.utc).date()

    # 21:30 IST on end_d → should be included when only end_date provided
    join_local = datetime(end_d.year, end_d.month, end_d.day, 21, 30, 0, tzinfo=ZoneInfo(tz))
    join_utc_naive = join_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
    await _mk_feedback(db_session, session_id=s.id, user_id=admin.id, rating=5, created_at=join_utc_naive)

    r = await async_client.get(f"{BASE}/all?tz={tz}&end_date={end_d.isoformat()}", headers=headers)
    assert r.status_code == 200
    assert len(r.json()) >= 1


@pytest.mark.anyio
async def test_admin_list_all__pagination_and_total_count(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    for i in range(3):
        await _mk_feedback(db_session, session_id=s.id, user_id=admin.id, rating=3, comments=f"row-{i}")

    r = await async_client.get(f"{BASE}/all?tz=UTC&limit=2&offset=0", headers=headers)
    assert r.status_code == 200
    assert len(r.json()) == 2
    assert r.headers.get("X-Total-Count") in {"3", 3}


@pytest.mark.anyio
async def test_admin_list_all__filters_user_session_course(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s1 = await _mk_session(db_session, org_id=org.id, title="S1")
    s2 = await _mk_session(db_session, org_id=org.id, title="S2")

    # create two other users to avoid FK issues
    u2, _, _ = await org_user_with_token(role=OrgRole.MENTOR)
    u3, _, _ = await org_user_with_token(role=OrgRole.INTERN)

    await _mk_feedback(db_session, session_id=s1.id, user_id=admin.id, rating=5, comments="admin")
    await _mk_feedback(db_session, session_id=s1.id, user_id=u2.id, rating=5, comments="u2")
    await _mk_feedback(db_session, session_id=s2.id, user_id=u3.id, rating=5, comments="u3")

    # by user_id
    r_user = await async_client.get(f"{BASE}/all?tz=UTC&user_id={u2.id}", headers=headers)
    assert r_user.status_code == 200
    assert [row["comments"] for row in r_user.json()] == ["u2"]

    # by session_id
    r_sess = await async_client.get(f"{BASE}/all?tz=UTC&session_id={s2.id}", headers=headers)
    assert r_sess.status_code == 200
    assert [row["comments"] for row in r_sess.json()] == ["u3"]

    # by course_id — only if modeled AND Course model importable
    if hasattr(LiveSession, "course_id") and Course is not None:
        # create a real course to satisfy FK, point s1 to it
        course = Course(title="Course X", slug="course-x", organization_id=org.id)  # type: ignore
        db_session.add(course)
        await db_session.commit()
        await db_session.refresh(course)

        setattr(s1, "course_id", course.id)
        await db_session.commit()
        await db_session.refresh(s1)

        r_course = await async_client.get(f"{BASE}/all?tz=UTC&course_id={course.id}", headers=headers)
        assert r_course.status_code == 200
        got = [row["comments"] for row in r_course.json()]
        # both rows ("admin","u2") were on s1
        assert set(got) <= {"admin", "u2"}
    else:
        pytest.skip("LiveSession.course_id/Course not modeled; skipping course filter test.")


@pytest.mark.anyio
async def test_admin_list_all__cache_hit_short_circuit(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession, monkeypatch
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    tz = "UTC"
    limit = 2
    offset = 0
    start_d = date(2020, 1, 1)
    end_d = date(2020, 1, 2)
    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)

    ck = _cache_key(
        org_id=org.id,
        tz=tz,
        start_utc=start_utc,
        end_utc_excl=end_utc_excl,
        sort_by="newest",
        limit=limit,
        offset=offset,
    )

    cached_items = [
        {
            "id": str(uuid4()),
            "session_id": str(s.id),
            "user_id": str(admin.id),
            "rating": 5,
            "comments": "cached-1",
            "tags": ["wow"],
            "feedback_type": "general",
            "source": "web",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
        {
            "id": str(uuid4()),
            "session_id": str(s.id),
            "user_id": str(admin.id),
            "rating": 4,
            "comments": "cached-2",
            "tags": [],
            "feedback_type": "content",
            "source": "web",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    ]
    await redis_wrapper.client.setex(
        ck, 60, json.dumps({"x_total_count": 99, "items": cached_items}, separators=(",", ":"))
    )

    seen = {}
    async def _audit(**kw):
        seen["action"] = kw.get("action")
        seen["meta"] = kw.get("meta_data")
    monkeypatch.setattr("app.api.v1.course.live.feedback.log_org_event", _audit, raising=True)

    r = await async_client.get(
        f"{BASE}/all?tz={tz}&limit={limit}&offset={offset}&start_date={start_d}&end_date={end_d}",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.headers.get("X-Total-Count") == "99"
    body = r.json()
    assert [row["comments"] for row in body] == ["cached-1", "cached-2"]
    # Action can be READ or a specific LIST_* constant depending on your enum
    assert seen.get("action") in {AuditEventType.LIST_ALL_FEEDBACKS, getattr(AuditEventType, "LIST_ALL_FEEDBACKS", AuditEventType.LIST_ALL_FEEDBACKS)}
    assert (seen.get("meta") or {}).get("cache") == "hit"


@pytest.mark.anyio
async def test_admin_list_all__use_cache_false_ignores_cache(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    tz = "UTC"
    start_d = date(2020, 1, 1)
    end_d = date(2020, 1, 2)
    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)

    # Create the row *inside* the requested window
    created_inside = start_utc + timedelta(hours=12)
    await _mk_feedback(db_session, session_id=s.id, user_id=admin.id, rating=4, comments="real", created_at=created_inside)

    ck = _cache_key(org_id=org.id, tz=tz, start_utc=start_utc, end_utc_excl=end_utc_excl)
    await redis_wrapper.client.setex(ck, 60, json.dumps({"x_total_count": 123, "items": []}))

    r = await async_client.get(
        f"{BASE}/all?tz={tz}&use_cache=false&start_date={start_d}&end_date={end_d}",
        headers=headers,
    )
    assert r.status_code == 200
    assert any(row["comments"] == "real" for row in r.json())


@pytest.mark.anyio
async def test_admin_list_all__corrupt_cache_falls_back(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    tz = "UTC"
    start_d = date(2020, 3, 1)
    end_d = date(2020, 3, 2)
    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)

    created_inside = start_utc + timedelta(hours=8)
    await _mk_feedback(db_session, session_id=s.id, user_id=admin.id, rating=3, comments="ok", created_at=created_inside)

    ck = _cache_key(org_id=org.id, tz=tz, start_utc=start_utc, end_utc_excl=end_utc_excl)
    await redis_wrapper.client.setex(ck, 60, "{not-json")

    r = await async_client.get(
        f"{BASE}/all?tz={tz}&start_date={start_d}&end_date={end_d}",
        headers=headers,
    )
    assert r.status_code == 200
    assert any(row["comments"] == "ok" for row in r.json())


@pytest.mark.anyio
async def test_admin_list_all__audit_success_and_error_paths(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession, monkeypatch
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)
    await _mk_feedback(db_session, session_id=s.id, user_id=admin.id, rating=5, comments="one")

    # success audit (best-effort)
    seen_ok = {}
    async def _audit_ok(**kw):
        seen_ok["action"] = kw.get("action")
        seen_ok["meta"] = kw.get("meta_data")
    monkeypatch.setattr("app.api.v1.course.live.feedback.log_org_event", _audit_ok, raising=True)

    r = await async_client.get(f"{BASE}/all?tz=UTC&use_cache=false", headers=headers)
    assert r.status_code == 200

    # error path: force DB path and make and_ explode
    def _boom(*a, **k): raise RuntimeError("and_ exploded")
    monkeypatch.setattr("app.api.v1.course.live.feedback.and_", _boom, raising=True)

    seen_err = {}
    async def _audit_err(**kw):
        seen_err["action"] = kw.get("action")
        seen_err["meta"] = kw.get("meta_data")
    monkeypatch.setattr("app.api.v1.course.live.feedback.log_org_event", _audit_err, raising=True)

    r2 = await async_client.get(f"{BASE}/all?tz=UTC&use_cache=false", headers=headers)
    assert r2.status_code == 500, r2.text
    assert seen_err.get("action") in {AuditEventType.LIST_ALL_FEEDBACKS, getattr(AuditEventType, "LIST_ALL_FEEDBACKS", AuditEventType.LIST_ALL_FEEDBACKS)}
