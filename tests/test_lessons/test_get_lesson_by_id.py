import pytest
from uuid import uuid4
from datetime import datetime, timezone
from sqlalchemy import select

from app.db.models import (
    Course,
    Lesson,
    LessonProgress,
    UserOrganization,
)
from app.schemas.enums import CourseVisibility, CourseLevel, OrgRole

BASE = "/api/v1/lessons"


# ── Small local helpers (same style as your other test files) ──────────────
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

async def _create_course(
    db, *, org_id, creator_id, title, is_published=True, visibility=CourseVisibility.PUBLIC
):
    c = Course(
        id=uuid4(),
        title=title,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
        description=f"{title} description",
        visibility=visibility,
        is_published=is_published,
        organization_id=org_id,
        created_by=creator_id,
        language="en",
        level=CourseLevel.BEGINNER,
        is_free=True,
    )
    db.add(c)
    await db.commit()
    await db.refresh(c)
    return c

async def _create_lesson(
    db, *, course_id, org_id, creator_id, title="L", order=1, is_published=True
):
    l = Lesson(
        id=uuid4(),
        title=title,
        course_id=course_id,
    )
    _set_if_has(
        l,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
        order=order,
        organization_id=org_id,
        is_published=is_published,
        created_by=creator_id,
    )
    db.add(l)
    await db.commit()
    await db.refresh(l)
    return l


# ======================================================================
# ✅ 200 OK — returns lesson + progress snapshot (for org user)
# ======================================================================
@pytest.mark.anyio
async def test_get_lesson__200_with_progress(async_client, db_session, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Systems")
    lesson = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Intro", order=1)

    # Seed a progress record so the handler can compute is_completed/last_viewed_at
    uo = await _get_or_create_user_org(db_session, user_id=user.id, org_id=org.id)
    lp = LessonProgress(
        user_id=user.id,
        user_org_id=uo.id,
        lesson_id=lesson.id,
        course_id=course.id,
        is_completed=True,
        last_viewed_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )
    db_session.add(lp)
    await db_session.commit()

    r = await async_client.get(f"{BASE}/{lesson.id}", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()

    # Basic shape
    assert data["id"] == str(lesson.id)
    assert data["title"] == "Intro"
    assert data["course_id"] == str(course.id)
    # Derived fields from progress
    assert data["is_completed"] is True
    assert isinstance(data.get("last_viewed_at"), str)


# ======================================================================
# ✅ 200 OK — resources normalization (list -> list[str])
# ======================================================================
@pytest.mark.anyio
async def test_get_lesson__200_resources_list_normalized(async_client, db_session, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="ResList")
    lesson = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="R", order=1)

    # Set resources to a raw list and commit
    lesson.resources = ["a", 42, "c"]
    await db_session.commit()

    r = await async_client.get(f"{BASE}/{lesson.id}", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["resources"] == ["a", "42", "c"]


# ======================================================================
# ✅ 200 OK — resources normalization (dict -> list[str])
# ======================================================================
@pytest.mark.anyio
async def test_get_lesson__200_resources_dict_normalized(async_client, db_session, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="ResDict")
    lesson = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="R2", order=1)

    # Set resources to a dict and commit
    lesson.resources = {"one": "http://x", "two": 7, "junk": {"k": "v"}}
    await db_session.commit()

    r = await async_client.get(f"{BASE}/{lesson.id}", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    # Only str/int/float values become strings; nested dict skipped
    assert set(data["resources"]) == {"http://x", "7"}


# ======================================================================
# ✅ 304 Not Modified — ETag short-circuit
# ======================================================================
@pytest.mark.anyio
async def test_get_lesson__304_etag(async_client, db_session, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="ET")
    lesson = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Tag", order=1)

    r1 = await async_client.get(f"{BASE}/{lesson.id}", headers=headers)
    assert r1.status_code == 200, r1.text
    etag = r1.headers.get("ETag")
    assert etag

    r2 = await async_client.get(f"{BASE}/{lesson.id}", headers={**headers, "If-None-Match": etag})
    assert r2.status_code == 304
    # No body expected with 304
    assert r2.text == ""


# ======================================================================
# ✅ 404 Not Found — bogus lesson id
# ======================================================================
@pytest.mark.anyio
async def test_get_lesson__404_not_found(async_client, db_session, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.get(f"{BASE}/{uuid4()}", headers=headers)
    assert r.status_code == 404, r.text
    assert "not found" in r.json()["detail"].lower()


# ======================================================================
# ✅ 403 Forbidden — user from a different org / no access
#     (uses a different user token not tied to the course org)
# ======================================================================
@pytest.mark.anyio
async def test_get_lesson__403_forbidden_for_nonmember(async_client, db_session, org_user_with_token, user_with_headers):
    # Creator in Org A
    creator, creator_headers, org_a = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(
        db_session,
        org_id=org_a.id,
        creator_id=creator.id,
        title="PrivateCourse",
        visibility=CourseVisibility.PRIVATE,
    )
    lesson = await _create_lesson(
        db_session, course_id=course.id, org_id=org_a.id, creator_id=creator.id, title="Hidden", order=1
    )

    # Separate user (not in org_a), with their own headers
    other_user, other_headers = await user_with_headers()

    r = await async_client.get(f"{BASE}/{lesson.id}", headers=other_headers)
    assert r.status_code == 403, r.text
    assert "do not have access" in r.json()["detail"].lower()
