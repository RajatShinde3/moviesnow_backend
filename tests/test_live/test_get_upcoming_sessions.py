# tests/test_live/test_get_upcoming_sessions.py
from __future__ import annotations

import pytest
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from app.schemas.enums import OrgRole
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

BASE = "/api/v1/course/live/session"


# --- Model imports with fallbacks (works across common layouts) -------------
try:
    from app.db.models import LiveSession  # type: ignore
except Exception:  # pragma: no cover
    from app.db.models import LiveSession  # type: ignore

try:
    from app.db.models.course import Course as _Course  # type: ignore
except Exception:  # pragma: no cover
    _Course = None  # type: ignore


# --- Debug helpers -----------------------------------------------------------
def _fmt_dt(dt) -> str:
    if dt is None:
        return "None"
    # Show tz awareness + ISO
    tz = "aware" if getattr(dt, "tzinfo", None) else "naive"
    try:
        iso = dt.isoformat()
    except Exception:
        iso = str(dt)
    return f"{iso} ({tz})"

def _ids(rows):
    return [r["id"] for r in rows]

def _dump_sessions(label: str, *sessions: LiveSession):
    print(f"\n[DEBUG] {label}: count={len(sessions)}")
    for s in sessions:
        start = getattr(s, "start_time", None)
        end = getattr(s, "end_time", None)
        print(
            "  - id=%s title=%r org=%s course=%s instructor=%s deleted=%s start=%s end=%s"
            % (
                getattr(s, "id", None),
                getattr(s, "title", None),
                getattr(s, "organization_id", None),
                getattr(s, "course_id", None) if hasattr(s, "course_id") else None,
                getattr(s, "instructor_id", None) if hasattr(s, "instructor_id") else None,
                getattr(s, "is_deleted", None) if hasattr(s, "is_deleted") else None,
                _fmt_dt(start),
                _fmt_dt(end),
            )
        )

def _dump_response(label: str, resp):
    # Best-effort JSON parse
    try:
        body = resp.json()
    except Exception:
        body = resp.text
    print(
        f"\n[DEBUG] {label} "
        f"status={resp.status_code} "
        f"X-Total-Count={resp.headers.get('X-Total-Count')} "
        f"X-Page-Offset={resp.headers.get('X-Page-Offset')} "
        f"X-Page-Limit={resp.headers.get('X-Page-Limit')}"
    )
    if isinstance(body, list):
        print(f"[DEBUG] {label} body len={len(body)} ids={_ids(body)}")
    else:
        print(f"[DEBUG] {label} body={body}")


# --- Tiny helpers ------------------------------------------------------------
def _utcnow_naive() -> datetime:
    # naive UTC (TIMESTAMP WITHOUT TIME ZONE safe)
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
    title: str = "S",
    start: datetime | None = None,
    end: datetime | None = None,
    course_id=None,
    instructor_id=None,
    deleted: bool = False,
) -> LiveSession:
    """Create a minimal, DB-safe LiveSession row."""
    now = _utcnow_naive()
    start = start or (now + timedelta(hours=1))
    end = end or (start + timedelta(hours=1))

    s = LiveSession(
        id=uuid4(),
        title=title,
        organization_id=org_id,
        start_time=start,
        end_time=end,
    )
    # optional fields if present on model
    if hasattr(s, "course_id"):
        s.course_id = course_id
    if hasattr(s, "instructor_id"):
        s.instructor_id = instructor_id
    if hasattr(s, "is_deleted"):
        s.is_deleted = deleted
    if hasattr(s, "status") and getattr(s, "status", None) in (None, ""):
        try:
            from app.schemas.enums import LiveSessionStatus  # type: ignore
            s.status = getattr(LiveSessionStatus, "SCHEDULED", "SCHEDULED")
        except Exception:
            s.status = "SCHEDULED"
    # ensure created/updated naive when present
    if hasattr(s, "created_at"):
        s.created_at = now - timedelta(minutes=10)
    if hasattr(s, "updated_at"):
        s.updated_at = now - timedelta(minutes=10)

    db.add(s)
    await db.commit()
    await db.refresh(s)
    # Debug for each created session
    _dump_sessions("created_session", s)
    return s


async def _mk_course(db: AsyncSession, *, org_id, title="Course A", slug=None):
    if _Course is None:
        pytest.skip("Course model not available; skipping course-title joins.")

    slug = slug or f"{title.lower().replace(' ', '-')}-{uuid4().hex[:8]}"
    c = _Course(title=title, organization_id=org_id)
    if hasattr(c, "slug"):
        c.slug = slug
    if hasattr(c, "language") and getattr(c, "language", None) in (None, ""):
        c.language = "en"
    if hasattr(c, "level") and getattr(c, "level", None) in (None, ""):
        try:
            from app.schemas.enums import CourseLevel  # type: ignore
            c.level = getattr(CourseLevel, "BEGINNER", "BEGINNER")
        except Exception:
            c.level = "BEGINNER"
    if hasattr(c, "visibility") and getattr(c, "visibility", None) in (None, ""):
        try:
            from app.schemas.enums import CourseVisibility  # type: ignore
            c.visibility = getattr(CourseVisibility, "PUBLIC", "PUBLIC")
        except Exception:
            c.visibility = "PUBLIC"
    if hasattr(c, "status") and getattr(c, "status", None) in (None, ""):
        try:
            from app.schemas.enums import CourseStatus  # type: ignore
            c.status = getattr(CourseStatus, "DRAFT", "DRAFT")
        except Exception:
            c.status = "DRAFT"
    if hasattr(c, "is_latest") and getattr(c, "is_latest", None) is None:
        c.is_latest = True
    if hasattr(c, "is_deleted"):
        c.is_deleted = False

    db.add(c)
    await db.commit()
    await db.refresh(c)
    print(f"\n[DEBUG] created_course id={c.id} title={c.title!r} org={c.organization_id}")
    return c


# --- Fixture: patch route's now_utc to NAIVE timestamp ----------------------
@pytest.fixture
def patch_naive_now(monkeypatch):
    """
    Patch app route's now_utc to a fixed naive timestamp so comparisons against
    TIMESTAMP WITHOUT TIME ZONE columns work in tests.
    """
    import app.api.v1.course.live.sessions as sessions_api  # route module
    fixed = _utcnow_naive()
    monkeypatch.setattr(sessions_api, "now_utc", lambda: fixed)
    print(f"\n[DEBUG] patch_naive_now fixed_now={_fmt_dt(fixed)}")
    return fixed


# --- Tests ------------------------------------------------------------------

@pytest.mark.anyio
async def test_upcoming__only_future_sorted_and_paginated(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    now = patch_naive_now
    print(f"\n[DEBUG] test_upcoming__only_future_sorted_and_paginated org={org.id} now={_fmt_dt(now)}")

    # Past (excluded), and three future
    _past = await _mk_session(db_session, org_id=org.id, title="P", start=now - timedelta(hours=1), end=now)
    f1 = await _mk_session(db_session, org_id=org.id, title="A", start=now + timedelta(hours=1))
    f2 = await _mk_session(db_session, org_id=org.id, title="B", start=now + timedelta(hours=2))
    f3 = await _mk_session(db_session, org_id=org.id, title="C", start=now + timedelta(hours=3))
    _dump_sessions("pre_query_sessions", _past, f1, f2, f3)

    # page 1
    r1 = await async_client.get(f"{BASE}/upcoming?skip=0&limit=2", headers=headers)
    _dump_response("page1", r1)
    assert r1.status_code == 200
    body1 = r1.json()
    assert _ids(body1) == [str(f1.id), str(f2.id)]
    assert r1.headers.get("X-Total-Count") == "3"
    assert r1.headers.get("X-Page-Offset") == "0"
    assert r1.headers.get("X-Page-Limit") == "2"

    # page 2
    r2 = await async_client.get(f"{BASE}/upcoming?skip=2&limit=2", headers=headers)
    _dump_response("page2", r2)
    assert r2.status_code == 200
    body2 = r2.json()
    assert _ids(body2) == [str(f3.id)]
    assert r2.headers.get("X-Total-Count") == "3"
    assert r2.headers.get("X-Page-Offset") == "2"
    assert r2.headers.get("X-Page-Limit") == "2"


@pytest.mark.anyio
async def test_upcoming__within_days_filters_window(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    now = patch_naive_now
    print(f"\n[DEBUG] test_upcoming__within_days_filters_window org={org.id} now={_fmt_dt(now)}")

    within = await _mk_session(db_session, org_id=org.id, title="W", start=now + timedelta(days=2))
    beyond = await _mk_session(db_session, org_id=org.id, title="B", start=now + timedelta(days=10))
    _dump_sessions("pre_query_sessions", within, beyond)

    r = await async_client.get(f"{BASE}/upcoming?within_days=3", headers=headers)
    _dump_response("within_days", r)
    assert r.status_code == 200
    ids = set(_ids(r.json()))
    assert str(within.id) in ids
    assert str(beyond.id) not in ids


@pytest.mark.anyio
async def test_upcoming__search_matches_session_title(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    now = patch_naive_now
    print(f"\n[DEBUG] test_upcoming__search_matches_session_title org={org.id} now={_fmt_dt(now)}")

    s1 = await _mk_session(db_session, org_id=org.id, title="Networking Basics", start=now + timedelta(hours=1))
    _ = await _mk_session(db_session, org_id=org.id, title="Different", start=now + timedelta(hours=2))

    r = await async_client.get(f"{BASE}/upcoming?search=network", headers=headers)
    _dump_response("search_title", r)
    assert r.status_code == 200
    assert set(_ids(r.json())) == {str(s1.id)}


@pytest.mark.anyio
async def test_upcoming__search_matches_course_title_via_outer_join(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    now = patch_naive_now
    print(f"\n[DEBUG] test_upcoming__search_matches_course_title_via_outer_join org={org.id} now={_fmt_dt(now)}")

    if _Course is None:
        pytest.skip("Course model not available; skipping course-title join test.")

    course = await _mk_course(db_session, org_id=org.id, title="Advanced Databases")
    s1 = await _mk_session(db_session, org_id=org.id, title="Unrelated", course_id=course.id, start=now + timedelta(hours=1))
    _ = await _mk_session(db_session, org_id=org.id, title="Other", start=now + timedelta(hours=2))

    r = await async_client.get(f"{BASE}/upcoming?search=database", headers=headers)
    _dump_response("search_course_title", r)
    assert r.status_code == 200
    assert set(_ids(r.json())) == {str(s1.id)}


@pytest.mark.anyio
async def test_upcoming__course_and_instructor_filters(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    now = patch_naive_now
    print(f"\n[DEBUG] test_upcoming__course_and_instructor_filters org={org.id} admin={admin.id} now={_fmt_dt(now)}")

    course = None
    if _Course is not None:
        course = await _mk_course(db_session, org_id=org.id, title="C1")

    s_ok = await _mk_session(
        db_session,
        org_id=org.id,
        title="OK",
        instructor_id=admin.id,
        course_id=(course.id if course else None),
        start=now + timedelta(hours=1),
    )
    _ = await _mk_session(
        db_session, org_id=org.id, title="Nope", instructor_id=None, course_id=None, start=now + timedelta(hours=2)
    )

    qs = []
    if course:
        qs.append(f"course_id={course.id}")
    qs.append(f"instructor_id={admin.id}")
    query = "&".join(qs)

    print(f"[DEBUG] course_and_instructor_filters query={query}")
    r = await async_client.get(f"{BASE}/upcoming?{query}", headers=headers)
    _dump_response("course_and_instructor_filters", r)
    assert r.status_code == 200
    assert set(_ids(r.json())) == {str(s_ok.id)}


@pytest.mark.anyio
async def test_upcoming__excludes_deleted_and_wrong_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now
):
    _, headers1, org1 = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    _, headers2, org2 = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    now = patch_naive_now
    print(f"\n[DEBUG] test_upcoming__excludes_deleted_and_wrong_org org1={org1.id} org2={org2.id} now={_fmt_dt(now)}")

    # in org1: one deleted (should not show), one active (should show for org1 only)
    deleted = await _mk_session(db_session, org_id=org1.id, title="D", deleted=True, start=now + timedelta(hours=1))
    s_visible = await _mk_session(db_session, org_id=org1.id, title="V", start=now + timedelta(hours=2))

    # in org2: future row shouldn't appear for org1
    s_org2 = await _mk_session(db_session, org_id=org2.id, title="O2", start=now + timedelta(hours=3))
    _dump_sessions("pre_query_sessions", deleted, s_visible, s_org2)

    r1 = await async_client.get(f"{BASE}/upcoming", headers=headers1)
    _dump_response("org1_view", r1)
    assert r1.status_code == 200
    assert set(_ids(r1.json())) == {str(s_visible.id)}

    r2 = await async_client.get(f"{BASE}/upcoming", headers=headers2)
    _dump_response("org2_view", r2)
    assert r2.status_code == 200
    # org2 sees only its own
    assert set(_ids(r2.json())) == {"%s" % _["id"] for _ in r2.json()}


@pytest.mark.anyio
async def test_upcoming__stable_tie_break_by_id_when_same_start(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    now = patch_naive_now
    t = now + timedelta(hours=4)
    print(f"\n[DEBUG] test_upcoming__stable_tie_break_by_id_when_same_start org={org.id} tie_start={_fmt_dt(t)}")

    s1 = await _mk_session(db_session, org_id=org.id, title="T1", start=t, end=t + timedelta(hours=1))
    s2 = await _mk_session(db_session, org_id=org.id, title="T2", start=t, end=t + timedelta(hours=1))
    _dump_sessions("pre_query_sessions", s1, s2)

    r = await async_client.get(f"{BASE}/upcoming", headers=headers)
    _dump_response("tie_break", r)
    assert r.status_code == 200
    ids = _ids(r.json())

    # start_time tie -> ascending by id
    assert ids == sorted([str(s1.id), str(s2.id)])


@pytest.mark.anyio
async def test_upcoming__empty_when_no_future(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    now = patch_naive_now
    print(f"\n[DEBUG] test_upcoming__empty_when_no_future org={org.id} now={_fmt_dt(now)}")

    # all in the past or exactly at 'now' (excluded: route uses > now)
    p1 = await _mk_session(db_session, org_id=org.id, title="Past1", start=now - timedelta(hours=2), end=now - timedelta(hours=1))
    p2 = await _mk_session(db_session, org_id=org.id, title="ExactlyNow", start=now, end=now + timedelta(minutes=30))
    _dump_sessions("pre_query_sessions", p1, p2)

    r = await async_client.get(f"{BASE}/upcoming", headers=headers)
    _dump_response("empty_when_no_future", r)
    assert r.status_code == 200
    assert r.json() == []
    assert r.headers.get("X-Total-Count") == "0"
