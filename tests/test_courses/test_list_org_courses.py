import pytest
from httpx import AsyncClient
from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import patch
from slugify import slugify

from app.db.models import Course
from app.schemas.enums import CourseVisibility
from app.utils.audit import AuditEventType


@pytest.mark.anyio
async def test_list_courses_for_org_user_basic(
    async_client: AsyncClient,
    org_user_with_token,
    db_session: AsyncSession,
):
    user, headers, org = await org_user_with_token()

    courses = [
        Course(
            title=f"Course {i}",
            description="desc",
            slug=slugify(f"course-{i}-{user.id}"),
            visibility=CourseVisibility.PUBLIC,
            is_published=True,
            organization_id=org.id,
            created_by=user.id,
            updated_by=user.id,
        )
        for i in range(3)
    ]
    db_session.add_all(courses)
    await db_session.commit()

    response = await async_client.get(
        "/api/v1/courses/org",
        headers=headers,
        params={"limit": 10, "offset": 0},
    )
    assert response.status_code == status.HTTP_200_OK

    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 3
    titles = [c["title"] for c in data]
    for course in courses:
        assert course.title in titles


@pytest.mark.anyio
async def test_list_courses_for_org_user_with_search(
    async_client: AsyncClient,
    org_user_with_token,
    db_session: AsyncSession,
):
    user, headers, org = await org_user_with_token()

    course1 = Course(
        title="Python Basics",
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        slug=slugify(f"course-python-{user.id}"),
        is_published=True,
        organization_id=org.id,
        created_by=user.id,
        updated_by=user.id,
    )
    course2 = Course(
        title="Java Advanced",
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        slug=slugify(f"course-java-{user.id}"),
        is_published=True,
        organization_id=org.id,
        created_by=user.id,
        updated_by=user.id,
    )
    db_session.add_all([course1, course2])
    await db_session.commit()

    response = await async_client.get(
        "/api/v1/courses/org",
        headers=headers,
        params={"limit": 10, "offset": 0, "search": "python"},
    )
    assert response.status_code == status.HTTP_200_OK

    data = response.json()
    assert len(data) == 1
    assert data[0]["title"] == "Python Basics"


@pytest.mark.anyio
async def test_list_courses_for_org_user_pagination(
    async_client: AsyncClient,
    org_user_with_token,
    db_session: AsyncSession,
):
    user, headers, org = await org_user_with_token()

    courses = [
        Course(
            title=f"Course {i}",
            description="desc",
            slug=slugify(f"course-{i}-{user.id}"),
            visibility=CourseVisibility.PUBLIC,
            is_published=True,
            organization_id=org.id,
            created_by=user.id,
            updated_by=user.id,
        )
        for i in range(5)
    ]
    db_session.add_all(courses)
    await db_session.commit()

    response = await async_client.get(
        "/api/v1/courses/org",
        headers=headers,
        params={"limit": 2, "offset": 0},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data) == 2


@pytest.mark.anyio
async def test_list_courses_for_org_user_audit_logged(
    async_client: AsyncClient,
    org_user_with_token,
    db_session: AsyncSession,
):
    user, headers, org = await org_user_with_token()

    course = Course(
        title="Audit Test",
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        slug=slugify(f"course-audit-{user.id}"),
        is_published=True,
        organization_id=org.id,
        created_by=user.id,
        updated_by=user.id,
    )
    db_session.add(course)
    await db_session.commit()

    with patch("app.api.v1.courses.crud.log_org_event") as mock_audit_log:
        response = await async_client.get(
            "/api/v1/courses/org",
            headers=headers,
            params={"limit": 10, "offset": 0},
        )
        assert response.status_code == status.HTTP_200_OK
        mock_audit_log.assert_called_once()
        call_args = mock_audit_log.call_args[1]
        assert call_args["organization_id"] == org.id
        assert call_args["actor_id"] == user.id
        assert call_args["action"] == AuditEventType.ORG_COURSES_LISTED


@pytest.mark.anyio
async def test_list_courses_for_org_user_invalid_pagination(
    async_client: AsyncClient,
    org_user_with_token,
):
    user, headers, org = await org_user_with_token()

    response = await async_client.get(
        "/api/v1/courses/org",
        headers=headers,
        params={"limit": 0, "offset": 0},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = await async_client.get(
        "/api/v1/courses/org",
        headers=headers,
        params={"limit": 101, "offset": 0},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = await async_client.get(
        "/api/v1/courses/org",
        headers=headers,
        params={"limit": 10, "offset": -1},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
