import pytest
from fastapi import status
from uuid import uuid4
from app.db.models import Course
from app.services.courses.course_service import get_courses_by_org

@pytest.mark.anyio
async def test_list_courses_for_org_success(
    async_client,
    org_user_with_token,  # fixture returns (user, headers, org)
    create_test_course,
):
    user, headers, org = await org_user_with_token()

    # Create some courses for the organization
    courses_created = []
    for i in range(3):
        course = await create_test_course(
            organization_id=org.id,
            created_by=user.id,
            title=f"Test Course {i}",
        )
        courses_created.append(course)

    # Request with limit=2
    response = await async_client.get(
        "/api/v1/courses/",
        headers=headers,
        params={"limit": 2, "offset": 0},
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    print(data)
    assert isinstance(data, list)
    assert len(data) <= 2
    # Check returned courses belong to org
    assert all(course["organization_id"] == str(org.id) for course in data)
    # Check each course has an 'id' field
    assert all("id" in course for course in data)

@pytest.mark.anyio
async def test_list_courses_for_org_invalid_pagination(
    async_client,
    org_user_with_token,
):
    _, headers, _ = await org_user_with_token()

    # limit less than 1 (invalid)
    response = await async_client.get("/api/v1/courses/", headers=headers, params={"limit": 0})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # offset negative (invalid)
    response = await async_client.get("/api/v1/courses/", headers=headers, params={"offset": -1})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

@pytest.mark.anyio
async def test_list_courses_for_org_audit_log_failure(
    async_client,
    org_user_with_token,
    monkeypatch,
):
    _, headers, _ = await org_user_with_token()

    # Patch audit log function to raise an exception
    async def fake_log_org_event(*args, **kwargs):
        raise Exception("Audit failure")

    monkeypatch.setattr("app.api.v1.courses.crud.log_org_event", fake_log_org_event)

    response = await async_client.get("/api/v1/courses/", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    # Test ensures failure in audit logging does not break the endpoint

@pytest.mark.anyio
async def test_get_courses_by_org_returns_courses(
    db_session,
    create_organization_fixture,
    create_test_user,   # Add this fixture to create a valid user
):
    org = await create_organization_fixture()
    user = await create_test_user(email="test@example.com")  # Create a valid user

    # Create courses linked to the org
    for i in range(3):
        course = Course(
            title=f"Course {i}",
            slug=f"course-{i}",
            description="desc",
            visibility="public",
            organization_id=org.id,
            is_published=True,
            created_by=user.id,   # Use real user id here
            updated_by=user.id,   # Use real user id here
        )
        db_session.add(course)
    await db_session.commit()

    results = await get_courses_by_org(db_session, org.id, limit=10, offset=0)
    assert len(results) == 3
    assert all(course.organization_id == org.id for course in results)


@pytest.mark.anyio
async def test_get_courses_by_org_pagination(
    db_session,
    create_organization_fixture,
    create_test_user,
    create_test_course,
):
    org = await create_organization_fixture()
    user = await create_test_user(email="user@example.com")  # create test user for FK

    # Create 5 courses linked to the org and user
    for i in range(5):
        slug = f"course-{i}-{uuid4().hex[:6]}" 
        await create_test_course(
            title=f"Course {i}",
            slug=slug,
            description="desc",
            visibility="public",
            organization_id=org.id,
            is_published=True,
            created_by=user.id,
            updated_by=user.id,
        )

    first_page = await get_courses_by_org(db_session, org.id, limit=2, offset=0)
    second_page = await get_courses_by_org(db_session, org.id, limit=2, offset=2)

    assert len(first_page) == 2
    assert len(second_page) == 2
    assert first_page[0].created_at >= first_page[1].created_at
