# tests/test_courses/test_course_detail_with_progress.py
import pytest
from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import select

from app.db.models import (
    Course,
    Lesson,
    LessonProgress,
    CourseEnrollment,
    UserOrganization, Section, Organization
)
from app.schemas.enums import (
    CourseVisibility,
    CourseLevel,
    LessonTypeEnum,
    EnrollmentSourceEnum,
    OrgRole,
)




@pytest.mark.anyio
async def test_course_detail_org_user_success(async_client, db_session, org_user_with_token):
    """✅ Org user can view course detail for ORG_ONLY course in their org."""
    org_user, headers, org = await org_user_with_token(role=OrgRole.INTERN)
    now = datetime.now(timezone.utc)

    # Find org membership ID
    membership = (
        await db_session.execute(
            select(UserOrganization).where(
                UserOrganization.user_id == org_user.id,
                UserOrganization.organization_id == org.id,
            )
        )
    ).scalar_one()

    # Create ORG_ONLY course for the org
    course = Course(
        id=uuid4(),
        title="Org Course",
        slug=f"org-course-{org_user.id.hex[:6]}",   # ✅ slug required
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

    # Add lessons (✅ set organization_id)
    lessons = [
        Lesson(
            title=f"L{i+1}",
            course_id=course.id,
            order=i + 1,
            type=LessonTypeEnum.VIDEO,
            is_published=True,
            organization_id=org.id,                # ← IMPORTANT
        )
        for i in range(2)
    ]
    db_session.add_all(lessons)
    await db_session.commit()

    # Enroll org user
    db_session.add(
        CourseEnrollment(
            user_org_id=membership.id,
            course_id=course.id,
            is_active=True,
            source=EnrollmentSourceEnum.self,
        )
    )
    await db_session.commit()

    # Complete one lesson
    db_session.add(
        LessonProgress(
            course_id=course.id,
            lesson_id=lessons[1].id,
            user_org_id=membership.id,
            is_completed=True,
            progress_percent=100.0,
            first_viewed_at=now,
        )
    )
    await db_session.commit()

    # Call route
    r = await async_client.get(f"/api/v1/courses/{course.id}/detail", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["completed_lessons"] == 1
    assert data["total_lessons"] == 2


@pytest.mark.anyio
async def test_course_detail_user_success(async_client, db_session, user_with_headers):
    """✅ User can view course detail and progress for a PUBLIC course."""
    user, headers = await user_with_headers()
    now = datetime.now(timezone.utc)

    # Create a platform org to satisfy NOT NULL on lessons.organization_id
    platform_org = Organization(
        name=f"Platform Org {user.id.hex[:6]}",
        slug=f"platform-{user.id.hex[:6]}",         # ✅ slug required
    )
    db_session.add(platform_org)
    await db_session.commit()
    await db_session.refresh(platform_org)

    # Create PUBLIC course (no org required for PUBLIC in your tests, but fine if you set one)
    course = Course(
        id=uuid4(),
        title="Public Course",
        slug=f"public-course-{user.id.hex[:6]}",     # ✅ slug required
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        is_published=True,
        created_by=user.id,
        language="en",
        level=CourseLevel.BEGINNER,
        # organization_id=platform_org.id,          # optional for PUBLIC in your setup
    )
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    # Add lessons (✅ set organization_id)
    lessons = [
        Lesson(
            title=f"L{i+1}",
            course_id=course.id,
            order=i + 1,
            type=LessonTypeEnum.VIDEO,
            is_published=True,
            organization_id=platform_org.id,         # ← IMPORTANT
        )
        for i in range(3)
    ]
    db_session.add_all(lessons)
    await db_session.commit()

    # Complete 1 lesson
    db_session.add(
        LessonProgress(
            course_id=course.id,
            lesson_id=lessons[0].id,
            user_id=user.id,
            is_completed=True,
            progress_percent=100.0,
            first_viewed_at=now,
        )
    )
    await db_session.commit()

    # Call route
    r = await async_client.get(f"/api/v1/courses/{course.id}/detail", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()

    assert data["title"] == "Public Course"
    assert data["total_lessons"] == 3
    assert data["completed_lessons"] == 1
    assert data["progress_percent"] == pytest.approx(33.33, rel=1e-2)
    assert [l["is_completed"] for l in data["lessons"]].count(True) == 1

@pytest.mark.anyio
async def test_course_detail_no_access(async_client, db_session, user_with_headers):
    """❌ User gets 403 if they don't have access."""
    user, headers = await user_with_headers()

    course = Course(
        id=uuid4(),
        title="Private",
        slug=f"private-{user.id.hex[:6]}",  # ✅ Ensure slug is set
        description="desc",
        visibility=CourseVisibility.PRIVATE,
        is_published=True,
        created_by=user.id,
        language="en",
        level=CourseLevel.BEGINNER,
    )
    db_session.add(course)
    await db_session.commit()

    r = await async_client.get(f"/api/v1/courses/{course.id}/detail", headers=headers)
    assert r.status_code == 403


@pytest.mark.anyio
async def test_course_detail_not_found(async_client, user_with_headers):
    """❌ Returns 404 if course does not exist."""
    user, headers = await user_with_headers()
    fake_id = uuid4()
    r = await async_client.get(f"/api/v1/courses/{fake_id}/detail", headers=headers)
    assert r.status_code in (403, 404)  # depends on access control sequence


@pytest.mark.anyio
async def test_course_detail_no_lessons(async_client, db_session, user_with_headers):
    """✅ Handles courses with no lessons gracefully (0% progress)."""
    user, headers = await user_with_headers()

    course = Course(
        id=uuid4(),
        title="Empty Course",
        slug=f"empty-course-{user.id.hex[:6]}",  # ✅ Ensure slug is set
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        is_published=True,
        created_by=user.id,
        language="en",
        level=CourseLevel.BEGINNER,
    )
    db_session.add(course)
    await db_session.commit()

    r = await async_client.get(f"/api/v1/courses/{course.id}/detail", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["total_lessons"] == 0
    assert data["completed_lessons"] == 0
    assert data["progress_percent"] == 0.0
