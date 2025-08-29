# tests/test_courses/test_course_progress.py

import pytest
from uuid import uuid4
from datetime import datetime, timezone

from fastapi import status
from sqlalchemy import select

from app.db.models import (
    Course,
    Lesson,
    LessonProgress,
    CourseEnrollment,
    Organization,
    UserOrganization,
)
from app.schemas.enums import (
    CourseVisibility,
    CourseLevel,
    LessonTypeEnum,
    OrgRole,
    EnrollmentSourceEnum,
)



@pytest.mark.anyio
async def test_progress_user_public_course(async_client, db_session, user_with_headers):
    """
    User on a PUBLIC, published course (no org).
    Progress should be computed from LessonProgress(user_id=...).
    NOTE: lessons still require organization_id → use a platform org.
    """
    user, headers = await user_with_headers()

    # Platform org to satisfy lessons.organization_id NOT NULL
    platform_org = Organization(
        name=f"Platform Org {user.id.hex[:6]}",
        slug=f"platform-{user.id.hex[:6]}",  # slug is NOT NULL
    )
    db_session.add(platform_org)
    await db_session.commit()
    await db_session.refresh(platform_org)

    # PUBLIC course without organization (organization_id=None is allowed for courses)
    course = Course(
        id=uuid4(),
        title="Public Course",
        slug=f"public-course-{user.id.hex[:6]}",
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        is_published=True,
        organization_id=None,
        created_by=user.id,
        language="en",
        level=CourseLevel.BEGINNER,
    )
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    # 3 published lessons, tied to platform org (required)
    lessons = [
        Lesson(
            title=f"L{i+1}",
            course_id=course.id,
            organization_id=platform_org.id,  # ✅ required
            order=i + 1,
            type=LessonTypeEnum.VIDEO,
            is_published=True,
        )
        for i in range(3)
    ]
    db_session.add_all(lessons)
    await db_session.commit()
    await db_session.refresh(lessons[0])

    # Mark 1 lesson complete for this user (user_id path)
    lp = LessonProgress(
        course_id=course.id,
        lesson_id=lessons[0].id,
        user_id=user.id,
        is_completed=True,
        progress_percent=100.0,
        first_viewed_at=datetime.now(timezone.utc),
    )
    db_session.add(lp)
    await db_session.commit()

    # Call route
    r = await async_client.get(f"/api/v1/courses/{course.id}/progress", headers=headers)
    assert r.status_code == status.HTTP_200_OK, r.text
    data = r.json()
    assert data["total_lessons"] == 3
    assert data["completed_lessons"] == 1
    assert data["progress_percent"] == 33.33


@pytest.mark.anyio
async def test_progress_org_user_org_course(async_client, db_session, org_user_with_token):
    """
    Org user on a course owned by their org (ORG_ONLY or PUBLIC).
    Progress must be computed via LessonProgress(user_org_id=membership.id).
    """
    org_user, org_headers, org = await org_user_with_token(role=OrgRole.INTERN)

    # Org membership row (fixture creates it; we fetch its id)
    membership = (
        await db_session.execute(
            select(UserOrganization).where(
                UserOrganization.user_id == org_user.id,
                UserOrganization.organization_id == org.id,
            )
        )
    ).scalar_one()

    # Course owned by org
    course = Course(
        id=uuid4(),
        title="Org Course",
        slug=f"org-course-{org_user.id.hex[:6]}",
        description="desc",
        visibility=CourseVisibility.ORG_ONLY,
        is_published=True,
        organization_id=org.id,
        created_by=org_user.id,
        language="en",
        level=CourseLevel.BEGINNER,
    )
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    # 3 published lessons, tied to the owning org (required)
    lessons = [
        Lesson(
            title=f"L{i+1}",
            course_id=course.id,
            organization_id=org.id,  # ✅ required
            order=i + 1,
            type=LessonTypeEnum.VIDEO,
            is_published=True,
        )
        for i in range(3)
    ]
    db_session.add_all(lessons)
    await db_session.commit()

    # Enroll org user (via membership id)
    db_session.add(
        CourseEnrollment(
            user_org_id=membership.id,
            course_id=course.id,
            is_active=True,
            source=EnrollmentSourceEnum.self,
        )
    )
    await db_session.commit()

    # Complete 1 lesson via org membership (user_org_id path)
    db_session.add(
        LessonProgress(
            course_id=course.id,
            lesson_id=lessons[1].id,
            user_org_id=membership.id,
            is_completed=True,
            progress_percent=100.0,
            first_viewed_at=datetime.now(timezone.utc),
        )
    )
    await db_session.commit()

    # Call route
    r = await async_client.get(f"/api/v1/courses/{course.id}/progress", headers=org_headers)
    assert r.status_code == status.HTTP_200_OK, r.text
    data = r.json()
    assert data["total_lessons"] == 3
    assert data["completed_lessons"] == 1
    assert data["progress_percent"] == 33.33


@pytest.mark.anyio
async def test_progress_totals_only_published_lessons(async_client, db_session, user_with_headers):
    """
    Only published lessons should count in totals.
    Uses PUBLIC course (no org); lessons still need organization_id → platform org.
    """
    user, headers = await user_with_headers()

    # Platform org to satisfy lessons.organization_id NOT NULL
    platform_org = Organization(
        name=f"Platform Org {user.id.hex[:6]}",
        slug=f"platform-{user.id.hex[:6]}",
    )
    db_session.add(platform_org)
    await db_session.commit()
    await db_session.refresh(platform_org)

    course = Course(
        id=uuid4(),
        title="Mixed Lessons",
        slug=f"mix-{user.id.hex[:6]}",
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        is_published=True,
        organization_id=None,
        created_by=user.id,
        language="en",
        level=CourseLevel.BEGINNER,
    )
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    # 2 published + 2 draft lessons (all tied to platform org)
    lessons = [
        Lesson(
            title=f"L{i+1}",
            course_id=course.id,
            organization_id=platform_org.id,  # ✅ required
            order=i + 1,
            type=LessonTypeEnum.VIDEO,
            is_published=(i < 2),
        )
        for i in range(4)
    ]
    db_session.add_all(lessons)
    await db_session.commit()

    # Complete one published lesson (user_id path)
    db_session.add(
        LessonProgress(
            course_id=course.id,
            lesson_id=lessons[0].id,
            user_id=user.id,
            is_completed=True,
            progress_percent=100.0,
            first_viewed_at=datetime.now(timezone.utc),
        )
    )
    await db_session.commit()

    # Call route
    r = await async_client.get(f"/api/v1/courses/{course.id}/progress", headers=headers)
    assert r.status_code == status.HTTP_200_OK, r.text
    data = r.json()
    assert data["total_lessons"] == 2  # only published counted
    assert data["completed_lessons"] == 1
    assert data["progress_percent"] == 50.0


@pytest.mark.anyio
async def test_progress_unpublished_course_404(
    async_client,
    db_session,
    user_with_headers,
):
    """
    Unpublished courses should return 404.
    """
    user, headers = await user_with_headers()

    course = Course(
        title="Draft Course",
        slug=f"draft-{uuid4().hex[:6]}",
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        is_published=False,
        created_by=user.id,
        language="en",
        level=CourseLevel.BEGINNER,
    )
    db_session.add(course)
    await db_session.commit()

    r = await async_client.get(f"/api/v1/courses/{course.id}/progress", headers=headers)
    assert r.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.anyio
async def test_progress_access_denied_org_mismatch(
    async_client,
    db_session,
    org_user_with_token,
    create_organization_fixture,
):
    """
    Org user cannot access a course from another org.
    """
    org_user, org_headers, org_a = await org_user_with_token(role=OrgRole.EMPLOYEE)
    org_b = await create_organization_fixture()

    course = Course(
        title="Other Org Course",
        slug=f"oorg-{uuid4().hex[:6]}",
        description="desc",
        visibility=CourseVisibility.ORG_ONLY,
        is_published=True,
        organization_id=org_b.id,  # different org
        created_by=org_user.id,
        language="en",
        level=CourseLevel.BEGINNER,
    )
    db_session.add(course)
    await db_session.commit()

    r = await async_client.get(f"/api/v1/courses/{course.id}/progress", headers=org_headers)
    assert r.status_code == status.HTTP_403_FORBIDDEN



@pytest.mark.anyio
async def test_progress_cache_short_circuit(
    async_client,
    db_session,
    user_with_headers,
    monkeypatch,
):
    """
    If cache has a value, route should return it without hitting DB compute.
    """
    user, headers = await user_with_headers()

    # a minimal published course (won't matter; we'll hit cache)
    course = Course(
        title="Cached Course",
        slug=f"cached-{uuid4().hex[:6]}",
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        is_published=True,
        created_by=user.id,
        language="en",
        level=CourseLevel.BEGINNER,
    )
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    # fake cached payload
    cached_payload = {
        "completed_lessons": 7,
        "total_lessons": 10,
        "progress_percent": 70.0,
        "completed_lesson_ids": [],
    }

    async def fake_cache_get(key: str):
        return cached_payload

    async def fake_cache_set(key: str, value, ttl: int):
        # ensure we don't accidentally try to set during this path
        raise AssertionError("cache_set should not be called when cache_get hits")

    # patch cache utils
    monkeypatch.setattr("app.api.v1.courses.views.cache_get", fake_cache_get)
    monkeypatch.setattr("app.api.v1.courses.views.cache_set", fake_cache_set)

    r = await async_client.get(f"/api/v1/courses/{course.id}/progress", headers=headers)
    assert r.status_code == status.HTTP_200_OK
    data = r.json()
    assert data == cached_payload
