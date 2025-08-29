import pytest
from httpx import AsyncClient
from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas.enums import CourseVisibility
from app.services.courses.course_service import get_public_courses

@pytest.mark.anyio
async def test_get_public_courses_service_filters(
    db_session: AsyncSession,
    org_user_with_token,
    create_test_course,
):
    user, headers, org = await org_user_with_token()

    # Create courses via fixture, slug auto-generated
    public_published = await create_test_course(
        title="Public Published",
        visibility=CourseVisibility.PUBLIC,
        is_published=True,
        organization_id=org.id,
        created_by=user.id,
    )
    private_published = await create_test_course(
        title="Private Published",
        visibility=CourseVisibility.PRIVATE,
        is_published=True,
        organization_id=org.id,
        created_by=user.id,
    )
    public_unpublished = await create_test_course(
        title="Public Unpublished",
        visibility=CourseVisibility.PUBLIC,
        is_published=False,
        organization_id=org.id,
        created_by=user.id,
    )

    courses = await get_public_courses(db_session, limit=10, offset=0, search=None)

    assert all(c.visibility == CourseVisibility.PUBLIC for c in courses)
    assert all(c.is_published for c in courses)
    assert any(c.id == public_published.id for c in courses)
    assert all(c.id != private_published.id for c in courses)
    assert all(c.id != public_unpublished.id for c in courses)


@pytest.mark.anyio
async def test_get_public_courses_service_search_filter(
    db_session: AsyncSession,
    org_user_with_token,
    create_test_course,
):
    user, headers, org = await org_user_with_token()

    course1 = await create_test_course(
        title="Learn Python",
        description="Python course",
        visibility=CourseVisibility.PUBLIC,
        is_published=True,
        organization_id=org.id,
        created_by=user.id,
    )
    course2 = await create_test_course(
        title="Learn Java",
        description="Java course",
        visibility=CourseVisibility.PUBLIC,
        is_published=True,
        organization_id=org.id,
        created_by=user.id,
    )

    courses = await get_public_courses(db_session, limit=10, offset=0, search="python")

    assert any("python" in c.title.lower() or "python" in c.description.lower() for c in courses)
    assert all(
        ("python" in c.title.lower() or "python" in c.description.lower()) and
        c.visibility == CourseVisibility.PUBLIC and
        c.is_published
        for c in courses
    )


@pytest.mark.anyio
async def test_list_public_courses_endpoint(async_client: AsyncClient, org_user_with_token):
    user, headers, org = await org_user_with_token()

    response = await async_client.get(
        "/api/v1/courses/public",
        headers=headers,
        params={"limit": 5, "offset": 0, "search": "test"},
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    for course in data:
        assert "id" in course
        assert course["is_published"] is True
        assert course["visibility"] == "public"
        assert "categories" in course
        assert isinstance(course["categories"], list)

@pytest.mark.anyio
async def test_list_public_courses_invalid_pagination(async_client: AsyncClient, org_user_with_token):
    user, headers, org = await org_user_with_token()

    response = await async_client.get(
        "/api/v1/courses/public",
        headers=headers,
        params={"limit": -1, "offset": 0},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = await async_client.get(
        "/api/v1/courses/public",
        headers=headers,
        params={"limit": 101, "offset": 0},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = await async_client.get(
        "/api/v1/courses/public",
        headers=headers,
        params={"limit": 10, "offset": -1},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
