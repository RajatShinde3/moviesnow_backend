import anyio
import pytest
from uuid import uuid4
from typing import Optional
from sqlalchemy import select, and_
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Course,
    Lesson,
    LessonProgress,
    CourseEnrollment,
    User,
    UserOrganization,
)
from app.schemas.enums import CourseVisibility, CourseLevel, OrgRole
from app.core.redis_client import redis_wrapper
from sqlalchemy.exc import SQLAlchemyError
from app.services.courses.progress_service import (
    mark_lesson_viewed as _mark_lesson_viewed_service,
)

# -------------------------
# Minimal helpers (mirrors the style you used in other tests)
# -------------------------
def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if v is not None and hasattr(obj, k):
            setattr(obj, k, v)

async def _get_or_create_user_org(db, *, user_id, org_id):
    uo = await db.scalar(
        select(UserOrganization).where(
            UserOrganization.user_id == user_id,
            UserOrganization.organization_id == org_id,
        )
    )
    if uo is None:
        uo = UserOrganization(user_id=user_id, organization_id=org_id)
        db.add(uo)
        await db.commit()
        await db.refresh(uo)
    return uo

async def _create_course(db, *, org_id, creator_id, title, is_published=True):
    course = Course(
        title=title,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
        description=f"{title} description",
        visibility=CourseVisibility.PUBLIC,
        is_published=is_published,
        organization_id=org_id,
        created_by=creator_id,
        language="en",
        level=CourseLevel.BEGINNER,
        is_free=True,
    )
    db.add(course)
    await db.commit()
    await db.refresh(course)
    return course

async def _create_lesson(
    db,
    *,
    course_id,
    org_id,
    creator_id,
    title="Lesson",
    order: Optional[int] = 1,
    is_published: bool = True,
):
    lesson = Lesson(
        title=title,
        course_id=course_id,
    )
    _set_if_has(
        lesson,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
        order=order,
        organization_id=org_id,
        is_published=is_published,
        created_by=creator_id,
    )
    db.add(lesson)
    await db.commit()
    await db.refresh(lesson)
    return lesson


BASE = "/api/v1/lessons"


# ============================================================
# ✅ 204 on first view: creates LessonProgress (+ auto-enroll)
# ============================================================
@pytest.mark.anyio
async def test_mark_viewed__204_creates_progress_and_enrolls(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_user_with_token,
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="ViewMe")
    lesson = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Intro", order=1)

    r = await async_client.post(f"{BASE}/{lesson.id}/view", headers=headers)
    assert r.status_code == 204, r.text

    # Progress exists (either user_id or user_org_id set, depending on dependency principal)
    lp_q = select(LessonProgress).where(
        LessonProgress.lesson_id == lesson.id,
        LessonProgress.course_id == course.id,
    )
    lp = (await db_session.execute(lp_q)).scalars().first()
    assert lp is not None

    # If your schema has these fields, assert reasonable values
    if hasattr(lp, "is_viewed"):
        assert lp.is_viewed is True
    if hasattr(lp, "view_count"):
        assert (lp.view_count or 0) >= 1
    if hasattr(lp, "first_viewed_at"):
        assert lp.first_viewed_at is not None
    if hasattr(lp, "last_viewed_at"):
        assert lp.last_viewed_at is not None

    # Auto-enrollment should exist for the user in this course
    enr_q = select(CourseEnrollment).where(
        and_(
            CourseEnrollment.course_id == course.id,
            CourseEnrollment.user_id == user.id,
        )
    )
    enr = (await db_session.execute(enr_q)).scalars().first()
    assert enr is not None


# ======================================================================
# ✅ Repeated views without idempotency header update progress (idempotent)
#    Ensure view_count increments when the column exists
# ======================================================================
@pytest.mark.anyio
async def test_mark_viewed__repeat_updates_increments_count(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_user_with_token,
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Repeat")
    lesson = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Topic", order=1)

    # First view
    r1 = await async_client.post(f"{BASE}/{lesson.id}/view", headers=headers)
    assert r1.status_code == 204, r1.text

    lp_q = select(LessonProgress).where(
        LessonProgress.lesson_id == lesson.id, LessonProgress.course_id == course.id
    )
    lp1 = (await db_session.execute(lp_q)).scalars().first()
    assert lp1 is not None
    before_count = getattr(lp1, "view_count", None)
    before_last = getattr(lp1, "last_viewed_at", None)

    # Second view (no idempotency header → should update counters)
    r2 = await async_client.post(f"{BASE}/{lesson.id}/view", headers=headers)
    assert r2.status_code == 204, r2.text

    lp2 = (await db_session.execute(lp_q)).scalars().first()
    assert lp2 is not None

    if hasattr(lp2, "view_count") and before_count is not None:
        assert lp2.view_count >= before_count + 1
    if hasattr(lp2, "last_viewed_at") and before_last is not None:
        assert lp2.last_viewed_at >= before_last


# =====================================================================================
# ✅ Idempotency lock conflict → route returns 204 and does NOT call service (no-op)
#     We monkeypatch redis.set to simulate nx=False (lock already taken)
# =====================================================================================
@pytest.mark.anyio
async def test_mark_viewed__idempotent_duplicate_lock_returns_204_noop(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_user_with_token,
    monkeypatch,
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Idemp")
    lesson = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Once", order=1)

    # Ensure no progress initially
    lp_q = select(LessonProgress).where(
        LessonProgress.lesson_id == lesson.id, LessonProgress.course_id == course.id
    )
    assert (await db_session.execute(lp_q)).scalars().first() is None

    # Patch redis .set to behave as "nx=True → lock NOT acquired"
    original_set = redis_wrapper.client.set

    async def fake_set(key, value, **kw):
        # If caller tries to use nx, pretend key exists → return False
        if kw.get("nx") is True:
            return False
        return await original_set(key, value, ex=kw.get("px"))

    monkeypatch.setattr(redis_wrapper.client, "set", fake_set)

    hdrs = {**headers, "Idempotency-Key": "lock-me-please"}
    r = await async_client.post(f"{BASE}/{lesson.id}/view", headers=hdrs)
    assert r.status_code == 204, r.text

    # Still no progress (service was short-circuited)
    assert (await db_session.execute(lp_q)).scalars().first() is None


# ==========================================
# ❌ 404 if lesson_id doesn't exist
# ==========================================
@pytest.mark.anyio
async def test_mark_viewed__404_unknown_lesson(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_user_with_token,
):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.post(f"{BASE}/{uuid4()}/view", headers=headers)
    assert r.status_code == 404, r.text
    assert "not found" in r.json()["detail"].lower() or "access" in r.json()["detail"].lower()


# ==========================================
# ❌ 500 bubble-up on DB error (monkeypatch)
# ==========================================
@pytest.mark.anyio
async def test_mark_viewed__500_db_error(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_user_with_token,
    monkeypatch,
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Boom")
    lesson = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Crash", order=1)

    # Patch the service to simulate DB failure inside route
    from app.services.courses.progress_service import mark_lesson_viewed as svc_mark_viewed

    async def raise_db_err(*args, **kwargs):
        raise SQLAlchemyError("simulated")

    # Patch the symbol used by the route module
    monkeypatch.setattr(
        "app.services.courses.progress_service.mark_lesson_viewed",
        raise_db_err,
        raising=True,
    )

    r = await async_client.post(f"{BASE}/{lesson.id}/view", headers=headers)
    assert r.status_code == 500, r.text
    assert "database error" in r.json()["detail"].lower() or "failed to mark" in r.json()["detail"].lower()
