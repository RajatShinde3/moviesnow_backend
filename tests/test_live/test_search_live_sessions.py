import pytest
from datetime import datetime, timedelta, timezone
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole  # adjust import if your project places OrgRole elsewhere
from app.db.models.live_sessions import LiveSession, LiveSessionStatus

# Course model is optional across codebases; handle both common module names.
try:
    from app.db.models.course import Course as _Course
except Exception:
    try:
        from app.db.models.course import Course as _Course
    except Exception:
        _Course = None  # tests that need Course will skip if unavailable

BASE = "/api/v1/course/live/session"


# ----------------------------- helpers -----------------------------

def _utcnow_naive():
    # Naive UTC so TIMESTAMP WITHOUT TIME ZONE columns accept it without errors
    return datetime.now(timezone.utc).replace(microsecond=0)


from uuid import uuid4

async def _mk_course(db: AsyncSession, *, org_id, title="Course A", slug=None):
    if _Course is None:
        pytest.skip("Course model not available; skipping course-title keyword tests.")

    # always provide a unique, non-null slug
    slug = slug or f"{title.lower().replace(' ', '-')}-{uuid4().hex[:8]}"

    c = _Course(
        title=title,
        organization_id=org_id,
    )

    # set required fields if the model has them
    if hasattr(c, "slug"):
        c.slug = slug
    if hasattr(c, "language") and getattr(c, "language", None) in (None, "",):
        c.language = "en"
    if hasattr(c, "level") and getattr(c, "level", None) in (None, "",):
        try:
            from app.schemas.enums import CourseLevel
            c.level = getattr(CourseLevel, "BEGINNER", "BEGINNER")
        except Exception:
            c.level = "BEGINNER"
    if hasattr(c, "visibility") and getattr(c, "visibility", None) in (None, "",):
        try:
            from app.schemas.enums import CourseVisibility
            c.visibility = getattr(CourseVisibility, "PUBLIC", "PUBLIC")
        except Exception:
            c.visibility = "PUBLIC"
    if hasattr(c, "status") and getattr(c, "status", None) in (None, "",):
        try:
            from app.schemas.enums import CourseStatus
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
    return c



async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
    title="Session",
    description=None,
    start=None,
    end=None,
    instructor_id=None,
    course_id=None,
    deleted=False,
    deleted_days_ago=30,
):
    t0 = _utcnow_naive() + timedelta(hours=1)
    start = start or t0
    end = end or (start + timedelta(hours=1))

    # Enum may vary; accept string fallback if import changes
    status_val = getattr(LiveSessionStatus, "SCHEDULED", "SCHEDULED")

    s = LiveSession(
        title=title,
        description=description,
        organization_id=org_id,
        start_time=start,
        end_time=end,
        status=status_val,
        instructor_id=instructor_id,
        course_id=course_id,
    )
    # Soft-deletion knobs vary per schema
    if hasattr(s, "is_deleted"):
        s.is_deleted = bool(deleted)
    if deleted and hasattr(s, "deleted_at"):
        s.deleted_at = _utcnow_naive() - timedelta(days=deleted_days_ago)

    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


def _ids(resp_json):
    # Response_model is LiveSessionRead; id is a string UUID
    return [x["id"] for x in resp_json]


# ------------------------------ tests ------------------------------

@pytest.mark.anyio
async def test_search__200_pagination_headers(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    t = _utcnow_naive()
    s1 = await _mk_session(db_session, org_id=org.id, title="A", start=t + timedelta(minutes=0), end=t + timedelta(minutes=30))
    s2 = await _mk_session(db_session, org_id=org.id, title="B", start=t + timedelta(minutes=30), end=t + timedelta(minutes=60))
    s3 = await _mk_session(db_session, org_id=org.id, title="C", start=t + timedelta(minutes=60), end=t + timedelta(minutes=90))

    r = await async_client.get(f"{BASE}/search?limit=2&offset=1&order_by=start_time&order_dir=asc", headers=headers)
    assert r.status_code == 200, r.text
    assert r.headers.get("X-Total-Count") == "3"
    assert r.headers.get("X-Page-Offset") == "1"
    assert r.headers.get("X-Page-Limit") == "2"

    # Expect middle two in ascending start_time
    all_sorted = sorted([s1, s2, s3], key=lambda s: (s.start_time, str(s.id)))
    expected = [str(all_sorted[1].id), str(all_sorted[2].id)]
    assert _ids(r.json()) == expected


@pytest.mark.anyio
async def test_search__org_scoped(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    u1, h1, org1 = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    u2, h2, org2 = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    s1 = await _mk_session(db_session, org_id=org1.id, title="O1")
    _ = await _mk_session(db_session, org_id=org2.id, title="O2")

    r = await async_client.get(f"{BASE}/search", headers=h1)
    assert r.status_code == 200
    ids = set(_ids(r.json()))
    assert str(s1.id) in ids
    # Make sure org2's session is not visible to org1
    assert all(x["organization_id"] == str(org1.id) for x in r.json() if "organization_id" in x)


@pytest.mark.anyio
async def test_search__400_invalid_sort_and_dates(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    r1 = await async_client.get(f"{BASE}/search?order_by=does_not_exist", headers=headers)
    assert r1.status_code == 400

    # start_date > end_date -> 400
    a = (_utcnow_naive() + timedelta(hours=2)).isoformat()
    b = (_utcnow_naive() + timedelta(hours=1)).isoformat()
    r2 = await async_client.get(f"{BASE}/search?start_date={a}&end_date={b}", headers=headers)
    assert r2.status_code == 400


@pytest.mark.anyio
async def test_search__time_window_overlap_semantics(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    _, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    t = _utcnow_naive().replace(second=0)

    # s1: [t, t+60], s2: [t+90, t+150], s3: [t+180, t+240]
    s1 = await _mk_session(db_session, org_id=org.id, title="S1", start=t, end=t + timedelta(minutes=60))
    s2 = await _mk_session(db_session, org_id=org.id, title="S2", start=t + timedelta(minutes=90), end=t + timedelta(minutes=150))
    s3 = await _mk_session(db_session, org_id=org.id, title="S3", start=t + timedelta(minutes=180), end=t + timedelta(minutes=240))

    # start & end -> overlap with [t+30, t+120] -> S1 & S2
    r_overlap = await async_client.get(
        f"{BASE}/search?start_date={(t + timedelta(minutes=30)).isoformat()}&end_date={(t + timedelta(minutes=120)).isoformat()}&order_by=start_time",
        headers=headers,
    )
    assert r_overlap.status_code == 200
    assert set(_ids(r_overlap.json())) == {str(s1.id), str(s2.id)}

    # only start_date -> end >= start_date -> S2 & S3
    r_only_start = await async_client.get(
        f"{BASE}/search?start_date={(t + timedelta(minutes=120)).isoformat()}&order_by=start_time",
        headers=headers,
    )
    assert r_only_start.status_code == 200
    assert set(_ids(r_only_start.json())) == {str(s2.id), str(s3.id)}

    # only end_date -> start <= end_date -> S1 & S2
    r_only_end = await async_client.get(
        f"{BASE}/search?end_date={(t + timedelta(minutes=120)).isoformat()}&order_by=start_time",
        headers=headers,
    )
    assert r_only_end.status_code == 200
    assert set(_ids(r_only_end.json())) == {str(s1.id), str(s2.id)}


@pytest.mark.anyio
async def test_search__keyword_matches_title_and_description(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    _, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    t = _utcnow_naive()

    s_title = await _mk_session(db_session, org_id=org.id, title="Growth Hacking 101", start=t, end=t + timedelta(minutes=30))
    s_desc = await _mk_session(db_session, org_id=org.id, title="Boring", description="Deep onboarding best practices", start=t + timedelta(minutes=60), end=t + timedelta(minutes=90))

    r1 = await async_client.get(f"{BASE}/search?keyword=growth", headers=headers)
    assert r1.status_code == 200
    assert set(_ids(r1.json())) == {str(s_title.id)}

    r2 = await async_client.get(f"{BASE}/search?keyword=onboarding", headers=headers)
    assert r2.status_code == 200
    assert set(_ids(r2.json())) == {str(s_desc.id)}


@pytest.mark.anyio
async def test_search__keyword_matches_course_title_if_available(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    if _Course is None:
        pytest.skip("Course model not available; skipping course-title keyword test.")

    _, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    c = await _mk_course(db_session, org_id=org.id, title="Linear Algebra I")
    s = await _mk_session(db_session, org_id=org.id, title="Session", description="no match", course_id=c.id)

    r = await async_client.get(f"{BASE}/search?keyword=algebra", headers=headers)
    assert r.status_code == 200
    assert set(_ids(r.json())) == {str(s.id)}


@pytest.mark.anyio
async def test_search__filter_instructor_and_course(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Instructor filter
    s_instructor = await _mk_session(db_session, org_id=org.id, title="I1", instructor_id=admin.id)
    _ = await _mk_session(db_session, org_id=org.id, title="I2", instructor_id=None)

    r1 = await async_client.get(f"{BASE}/search?instructor_id={admin.id}", headers=headers)
    assert r1.status_code == 200
    assert set(_ids(r1.json())) == {str(s_instructor.id)}

    # Course filter (if Course model exists)
    if _Course is not None:
        c1 = await _mk_course(db_session, org_id=org.id, title="C1")
        c2 = await _mk_course(db_session, org_id=org.id, title="C2")
        s_c1 = await _mk_session(db_session, org_id=org.id, title="C1-s", course_id=c1.id)
        _ = await _mk_session(db_session, org_id=org.id, title="C2-s", course_id=c2.id)

        r2 = await async_client.get(f"{BASE}/search?course_id={c1.id}", headers=headers)
        assert r2.status_code == 200
        assert set(_ids(r2.json())) == {str(s_c1.id)}


@pytest.mark.anyio
async def test_search__ordering_asc_desc_with_secondary_id(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    _, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    t = _utcnow_naive()

    # sA & sB share the same start_time; sC later
    sA = await _mk_session(db_session, org_id=org.id, title="A", start=t, end=t + timedelta(minutes=30))
    sB = await _mk_session(db_session, org_id=org.id, title="B", start=t, end=t + timedelta(minutes=30))
    sC = await _mk_session(db_session, org_id=org.id, title="C", start=t + timedelta(minutes=10), end=t + timedelta(minutes=40))

    # asc (start_time asc, then id asc)
    r_asc = await async_client.get(f"{BASE}/search?order_by=start_time&order_dir=asc", headers=headers)
    assert r_asc.status_code == 200
    ids_asc = _ids(r_asc.json())
    expected_asc = [str(s.id) for s in sorted([sA, sB, sC], key=lambda s: (s.start_time, str(s.id)))]
    assert ids_asc == expected_asc

    # desc (start_time desc, then id desc)
    r_desc = await async_client.get(f"{BASE}/search?order_by=start_time&order_dir=desc", headers=headers)
    assert r_desc.status_code == 200
    ids_desc = _ids(r_desc.json())
    expected_desc = [str(s.id) for s in sorted([sA, sB, sC], key=lambda s: (s.start_time, str(s.id)), reverse=True)]
    assert ids_desc == expected_desc


@pytest.mark.anyio
async def test_search__respects_offset_limit(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    _, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    t = _utcnow_naive()

    sessions = []
    for i in range(5):
        s = await _mk_session(db_session, org_id=org.id, title=f"S{i}", start=t + timedelta(minutes=i), end=t + timedelta(minutes=i + 30))
        sessions.append(s)

    # Default sort is start_time asc
    all_sorted = [str(s.id) for s in sorted(sessions, key=lambda s: (s.start_time, str(s.id)))]

    r = await async_client.get(f"{BASE}/search?limit=2&offset=2&order_by=start_time&order_dir=asc", headers=headers)
    assert r.status_code == 200
    assert _ids(r.json()) == all_sorted[2:4]
