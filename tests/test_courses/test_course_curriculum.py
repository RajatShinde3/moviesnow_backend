# tests/test_courses/test_course_curriculum.py

import pytest
from uuid import uuid4
from app.db.models import Course, Section, Lesson
from app.schemas.enums import CourseVisibility, CourseLevel, LessonTypeEnum, OrgRole


def _set_attr_if_present(obj, **kwargs):
    """Helper to set attributes if they exist on the object."""
    for k, v in kwargs.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


@pytest.mark.anyio
async def test_curriculum_success_sorted(async_client, db_session, org_user_with_token):
    """
    ✅ Returns ordered sections and lessons for a course in the caller's org.
    """
    org_user, headers, org = await org_user_with_token(
        role=OrgRole.ADMIN, set_active_org=True
    )

    # Create a course within org
    course = Course(
        id=uuid4(),
        title="Curriculum Course",
        slug=f"cur-{org_user.id.hex[:6]}",
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

    # Two sections, intentionally out of order
    s2 = Section(title="Section B", course_id=course.id, organization_id=org.id)
    _set_attr_if_present(s2, order=2)  # use `order` instead of `position`

    s1 = Section(title="Section A", course_id=course.id, organization_id=org.id)
    _set_attr_if_present(s1, order=1)  # use `order` instead of `position`

    db_session.add_all([s2, s1])
    await db_session.commit()
    await db_session.refresh(s1)
    await db_session.refresh(s2)

    # Lessons out of order for each section
    lessons = [
        Lesson(
            title="B-2",
            section_id=s2.id,
            course_id=course.id,
            organization_id=org.id,
            type=LessonTypeEnum.VIDEO,
            order=2,  # use `order`
        ),
        Lesson(
            title="B-1",
            section_id=s2.id,
            course_id=course.id,
            organization_id=org.id,
            type=LessonTypeEnum.VIDEO,
            order=1,
        ),
        Lesson(
            title="A-2",
            section_id=s1.id,
            course_id=course.id,
            organization_id=org.id,
            type=LessonTypeEnum.VIDEO,
            order=2,
        ),
        Lesson(
            title="A-1",
            section_id=s1.id,
            course_id=course.id,
            organization_id=org.id,
            type=LessonTypeEnum.VIDEO,
            order=1,
        ),
    ]
    db_session.add_all(lessons)
    await db_session.commit()

    # Call route
    r = await async_client.get(
        f"/api/v1/courses/{course.id}/curriculum", headers=headers
    )
    assert r.status_code == 200, r.text
    data = r.json()

    # Sections ordered A → B
    assert [s["title"] for s in data["sections"]] == ["Section A", "Section B"]

    # Lessons ordered by position in JSON (mapped from `order`)
    assert [l["title"] for l in data["sections"][0]["lessons"]] == ["A-1", "A-2"]
    assert [l["title"] for l in data["sections"][1]["lessons"]] == ["B-1", "B-2"]


@pytest.mark.anyio
async def test_curriculum_empty(async_client, db_session, org_user_with_token):
    """
    ✅ Handles a course with no sections/lessons gracefully.
    """
    org_user, headers, org = await org_user_with_token(
        role=OrgRole.ADMIN, set_active_org=True
    )

    course = Course(
        id=uuid4(),
        title="Empty",
        slug=f"empty-{org_user.id.hex[:6]}",
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

    r = await async_client.get(
        f"/api/v1/courses/{course.id}/curriculum", headers=headers
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["id"] == str(course.id)
    assert data["sections"] == []


@pytest.mark.anyio
async def test_curriculum_course_in_other_org_is_404(
    async_client, db_session, org_user_with_token
):
    """
    ❌ Course exists but belongs to another organization → 404.
    """
    org_user, headers, org = await org_user_with_token(
        role=OrgRole.ADMIN, set_active_org=True
    )
    other_user, _, other_org = await org_user_with_token(role=OrgRole.ADMIN)

    course_other_org = Course(
        id=uuid4(),
        title="Other Org Course",
        slug=f"other-{other_user.id.hex[:6]}",
        description="desc",
        visibility=CourseVisibility.ORG_ONLY,
        is_published=True,
        organization_id=other_org.id,
        created_by=other_user.id,
        language="en",
        level=CourseLevel.BEGINNER,
    )
    db_session.add(course_other_org)
    await db_session.commit()

    r = await async_client.get(
        f"/api/v1/courses/{course_other_org.id}/curriculum", headers=headers
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_curriculum_course_not_found(async_client, org_user_with_token):
    """
    ❌ Totally missing course → 404.
    """
    _, headers, _ = await org_user_with_token(
        role=OrgRole.ADMIN, set_active_org=True
    )
    r = await async_client.get(
        f"/api/v1/courses/{uuid4()}/curriculum", headers=headers
    )
    assert r.status_code == 404
