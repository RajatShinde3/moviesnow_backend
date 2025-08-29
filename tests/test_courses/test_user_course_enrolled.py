import pytest
from fastapi import status
from typing import List
from uuid import UUID, uuid4
from datetime import datetime, timezone
from sqlalchemy import select
from app.db.models import (
    Course,
    CourseEnrollment,
    Lesson,
    LessonProgress,
    UserOrganization,
    Organization
)
from app.schemas.enums import CourseVisibility, CourseLevel, LessonTypeEnum, EnrollmentSourceEnum, OrgRole
from app.services.courses.progress_service import get_course_progress_for_user_or_org_user, get_course_progress
from app.services.courses.dashboard import get_enrolled_courses_with_progress


@pytest.mark.anyio
async def test_get_my_enrolled_courses_empty(
    async_client,
    user_with_headers,
):
    user, headers = await user_with_headers()

    response = await async_client.get("/api/v1/courses/enrolled", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data == []  # no enrollments yet



@pytest.mark.anyio
async def test_get_my_enrolled_courses_user_and_org(
    async_client,
    db_session,
    user_with_headers,
    org_user_with_token,
):
    user, headers = await user_with_headers()
    org_user, org_headers, org = await org_user_with_token()

    now = datetime.now(timezone.utc)

    # Step 1: Create a course
    course = Course(
        title="Enrolled Course",
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        is_published=True,
        organization_id=None,
        created_by=user.id,
        slug=f"enrolled-course-{user.id.hex[:6]}",
        language="en",
        level=CourseLevel.BEGINNER,
        version=1,
        is_latest=True,
        version_created_at=now,
        created_at=now,
    )
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    # Step 2: Create lessons
    lessons = [
        Lesson(
            title=f"Lesson {i}",
            course_id=course.id,
            organization_id=org.id,
            order=i + 1,
            type=LessonTypeEnum.VIDEO,
            version=1,
            is_latest=True,
            version_created_at=now,
            created_at=now,
            is_published=True,
        ) for i in range(3)
    ]
    db_session.add_all(lessons)
    await db_session.commit()
    for lesson in lessons:
        await db_session.refresh(lesson)

    # Step 3: Get-or-create membership for org_user (fixtures often already created this)
    existing_uo = (
        await db_session.execute(
            select(UserOrganization).where(
                UserOrganization.user_id == org_user.id,
                UserOrganization.organization_id == org.id,
            )
        )
    ).scalar_one_or_none()

    if existing_uo is None:
        user_org_entity = UserOrganization(
            organization_id=org.id,
            user_id=org_user.id,
            role=OrgRole.INTERN,
            joined_at=now,
            is_active=True,
        )
        db_session.add(user_org_entity)
        await db_session.commit()
        await db_session.refresh(user_org_entity)
    else:
        user_org_entity = existing_uo


    print(f"user_org_entity.id: {user_org_entity.id}")

    # Step 4: Enroll user and org user in the course
    user_enrollment = CourseEnrollment(
        user_id=user.id,
        course_id=course.id,
        enrolled_at=now,
        is_active=True,
        source=EnrollmentSourceEnum.self,
    )
    org_enrollment = CourseEnrollment(
        user_org_id=user_org_entity.id,
        course_id=course.id,
        enrolled_at=now,
        is_active=True,
        source=EnrollmentSourceEnum.self,
    )
    db_session.add_all([user_enrollment, org_enrollment])
    await db_session.commit()

    # Step 5: Add lesson progress records for user and org user
    lp_user = LessonProgress(
        lesson_id=lessons[0].id,
        user_id=user.id,
        course_id=course.id,
        is_completed=True,
        progress_percent=100.0,
        first_viewed_at=now,
        created_at=now,
    )
    lp_org = LessonProgress(
        lesson_id=lessons[1].id,
        user_org_id=user_org_entity.id,
        course_id=course.id,
        is_completed=True,
        progress_percent=100.0,
        first_viewed_at=now,
        created_at=now,
    )
    print(f"lp_org before commit: user_org_id={lp_org.user_org_id}, user_id={lp_org.user_id}")

    db_session.add_all([lp_user, lp_org])
    await db_session.commit()

    # Verify LessonProgress for org user persisted correctly
    result = await db_session.execute(
        select(LessonProgress).where(LessonProgress.user_org_id == user_org_entity.id)
    )
    lp_org_list = result.scalars().all()
    print(f"LessonProgress for org user after commit: {lp_org_list}")

    # Step 6: Test user enrolled courses API response
    response = await async_client.get("/api/v1/courses/enrolled", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    print(f"User enrolled courses data: {data}")
    assert len(data) == 1, "User should have exactly one enrolled course"
    enrolled_course = data[0]
    assert enrolled_course["title"] == "Enrolled Course"
    assert enrolled_course["total_lessons"] == 3
    assert enrolled_course["completed_lessons"] == 1
    assert enrolled_course["progress_percent"] == round(1 / 3 * 100, 2)

    # Step 7: Test org user enrolled courses API response
    response_org = await async_client.get("/api/v1/courses/enrolled", headers=org_headers)
    assert response_org.status_code == status.HTTP_200_OK
    data_org = response_org.json()
    print(f"Org user enrolled courses data: {data_org}")
    assert len(data_org) == 1, "Org user should have exactly one enrolled course"
    enrolled_course_org = data_org[0]
    assert enrolled_course_org["title"] == "Enrolled Course"
    assert enrolled_course_org["total_lessons"] == 3
    assert enrolled_course_org["completed_lessons"] == 1
    assert enrolled_course_org["progress_percent"] == round(1 / 3 * 100, 2)



@pytest.mark.anyio
async def test_get_enrolled_courses_with_progress_returns_correct_data(
    db_session,
    user_with_headers,
):
    user, _ = await user_with_headers()
    now = datetime.now(timezone.utc)

    # ── Create a platform org so lessons can satisfy NOT NULL org FK
    platform_org = Organization(
        name=f"Platform Org {user.id.hex[:6]}",
        slug=f"platform-{user.id.hex[:6]}",  # << important: slug is NOT NULL & often UNIQUE
        is_active=True,
    )
    db_session.add(platform_org)
    await db_session.commit()
    await db_session.refresh(platform_org)

    # ── Course (PUBLIC; course.org may be None, that's fine)
    course = Course(
        title="Test Course",
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        is_published=True,
        created_by=user.id,
        slug=f"test-course-{user.id.hex[:6]}",
        language="en",
        level=CourseLevel.BEGINNER,
        version=1,
        is_latest=True,
        version_created_at=now,
        created_at=now,
        # organization_id can be None for PUBLIC course in your tests
        organization_id=None,
    )
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    # ── Lessons must have organization_id set (NOT NULL constraint)
    lessons = [
        Lesson(
            title=f"Lesson {i}",
            course_id=course.id,
            order=i + 1,
            type=LessonTypeEnum.VIDEO,
            version=1,
            is_latest=True,
            version_created_at=now,
            created_at=now,
            is_published=True,
            organization_id=platform_org.id,  # << attach to platform org
        )
        for i in range(2)
    ]
    db_session.add_all(lessons)
    await db_session.commit()
    for l in lessons:
        await db_session.refresh(l)

    # ── Enrollment for the user
    enrollment = CourseEnrollment(
        user_id=user.id,
        course_id=course.id,
        enrolled_at=now,
        is_active=True,
        source=EnrollmentSourceEnum.self,
    )
    db_session.add(enrollment)
    await db_session.commit()

    # ── Complete one lesson
    lp = LessonProgress(
        lesson_id=lessons[0].id,
        user_id=user.id,
        course_id=course.id,
        is_completed=True,
        progress_percent=100.0,
        first_viewed_at=now,
        created_at=now,
    )
    db_session.add(lp)
    await db_session.commit()

    # ── Function under test
    from app.services.courses.dashboard import get_enrolled_courses_with_progress

    results = await get_enrolled_courses_with_progress(db_session, user)

    assert len(results) == 1
    course_with_progress = results[0]
    assert course_with_progress.title == "Test Course"
    assert course_with_progress.total_lessons == 2
    assert course_with_progress.completed_lessons == 1
    assert course_with_progress.progress_percent == 50.0



@pytest.mark.anyio
async def test_get_course_progress_for_user_and_org(
    db_session,
    user_with_headers,
    org_user_with_token,
):
    user, _ = await user_with_headers()
    org_user, _, org = await org_user_with_token()

    now = datetime.now(timezone.utc)

    course = Course(
        title="Progress Course",
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        is_published=True,
        created_by=user.id,
        slug=f"progress-course-{user.id.hex[:6]}",
        language="en",
        level=CourseLevel.BEGINNER,
        version=1,
        is_latest=True,
        version_created_at=now,
        created_at=now,
    )
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    lessons = [
        Lesson(
            title=f"Lesson {i}",
            course_id=course.id,
            organization_id=org.id,
            order=i + 1,
            type=LessonTypeEnum.VIDEO,
            version=1,
            is_latest=True,
            version_created_at=now,
            created_at=now,
            is_published=True
        ) for i in range(3)
    ]
    db_session.add_all(lessons)
    await db_session.commit()
    for lesson in lessons:
        await db_session.refresh(lesson)

    # Get-or-create membership to avoid unique violation
    existing_uo = (
        await db_session.execute(
            select(UserOrganization).where(
                UserOrganization.user_id == org_user.id,
                UserOrganization.organization_id == org.id,
            )
        )
    ).scalar_one_or_none()

    if existing_uo is None:
        user_org_entity = UserOrganization(
            organization_id=org.id,
            user_id=org_user.id,
            role=OrgRole.INTERN,
            joined_at=now,
            is_active=True,
        )
        db_session.add(user_org_entity)
        await db_session.commit()
        await db_session.refresh(user_org_entity)
    else:
        user_org_entity = existing_uo


    # Lesson progress for user
    lp_user = LessonProgress(
        lesson_id=lessons[0].id,
        user_id=user.id,
        course_id=course.id,
        is_completed=True,
        progress_percent=100.0,
        first_viewed_at=now,
        created_at=now,
    )
    # Lesson progress for org user
    lp_org = LessonProgress(
        lesson_id=lessons[1].id,
        user_org_id=user_org_entity.id,  # Use UserOrganization id here
        course_id=course.id,
        is_completed=True,
        progress_percent=100.0,
        first_viewed_at=now,
        created_at=now,
    )
    db_session.add_all([lp_user, lp_org])
    await db_session.commit()

    progress_user = await get_course_progress_for_user_or_org_user(db_session, course.id, user)
    assert progress_user.total_lessons == 3
    assert progress_user.completed_lessons == 1
    assert progress_user.progress_percent == round(1 / 3 * 100, 2)

    progress_org = await get_course_progress_for_user_or_org_user(db_session, course.id, user_org_entity)

    assert progress_org.total_lessons == 3
    assert progress_org.completed_lessons == 1
    assert progress_org.progress_percent == round(1 / 3 * 100, 2)

@pytest.mark.anyio
async def test_get_course_progress_counts(
    db_session,
    user_with_headers,
):
    user, _ = await user_with_headers()
    now = datetime.now(timezone.utc)

    # Create an org because lessons.organization_id is NOT NULL in your schema
    org = Organization(
        name=f"Core Org {uuid4().hex[:6]}",
        slug=f"core-org-{uuid4().hex[:6]}",
        is_active=True,
    )
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)

    # Course can be PUBLIC but still belong to an org to satisfy FK/NOT NULLs
    course = Course(
        title="Core Progress Course",
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        is_published=True,
        created_by=user.id,
        organization_id=org.id,                   # 👈 ensure lessons can reference an org
        slug=f"core-progress-{user.id.hex[:6]}",
        language="en",
        level=CourseLevel.BEGINNER,
        version=1,
        is_latest=True,
        version_created_at=now,
        created_at=now,
    )
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    # 4 published lessons in the same org
    lessons = [
        Lesson(
            title=f"Lesson {i}",
            course_id=course.id,
            organization_id=org.id,               # 👈 NOT NULL satisfied
            order=i + 1,
            type=LessonTypeEnum.VIDEO,
            version=1,
            is_latest=True,
            version_created_at=now,
            created_at=now,
            is_published=True,
        )
        for i in range(4)
    ]
    db_session.add_all(lessons)
    await db_session.commit()
    for lesson in lessons:
        await db_session.refresh(lesson)

    # Complete 2 lessons for the user (user-scoped progress, not org-scoped)
    lp1 = LessonProgress(
        lesson_id=lessons[0].id,
        user_id=user.id,
        course_id=course.id,
        is_completed=True,
        progress_percent=100.0,
        first_viewed_at=now,
        created_at=now,
    )
    lp2 = LessonProgress(
        lesson_id=lessons[1].id,
        user_id=user.id,
        course_id=course.id,
        is_completed=True,
        progress_percent=100.0,
        first_viewed_at=now,
        created_at=now,
    )
    db_session.add_all([lp1, lp2])
    await db_session.commit()

    # Act
    progress = await get_course_progress(db_session, course.id, user_id=user.id)

    # Assert
    assert progress.total_lessons == 4
    assert progress.completed_lessons == 2
    assert progress.progress_percent == 50.0
    assert len(progress.completed_lesson_ids) == 2
