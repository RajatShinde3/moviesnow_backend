import pytest
from httpx import AsyncClient
from fastapi import status, HTTPException
from app.db.models import Course
from app.services.courses.course_service import create_course
from app.schemas.course import CourseCreate
from unittest.mock import AsyncMock, patch
from uuid import uuid4
from app.schemas.enums import OrgRole

@pytest.mark.anyio
async def test_create_new_course_endpoint(
    async_client: AsyncClient,
    org_user_with_token,   # -> (user, headers, org)
    category_factory,
    create_test_user,
    create_user_org_link,
):
    # Arrange
    user, headers, org = await org_user_with_token()
    category = await category_factory()
    instructor = await create_test_user()
    await create_user_org_link(user=instructor, organization=org, role=OrgRole.ADMIN)

    # Make the title unique to avoid slug collisions across runs
    suffix = uuid4().hex[:6]
    title = f"Async Test Course {suffix}"
    expected_slug = f"async-test-course-{suffix}"

    payload = {
        "title": title,
        "description": "Test description",
        "visibility": "public",
        "category_ids": [str(category.id)],
        "instructor_id": str(instructor.id),
        "is_published": True,
    }

    # Required best-practice headers
    idem_key = f"test-create-{uuid4()}"
    req_id = f"test-{uuid4()}"
    headers = {
        **headers,
        "Idempotency-Key": idem_key,
        "X-Request-ID": req_id,
    }

    # Act
    # NOTE: patch where the route actually imports the symbol.
    with patch("app.api.v1.courses.crud.log_org_event", new=AsyncMock()) as mock_log:
        resp1 = await async_client.post("/api/v1/courses/create", json=payload, headers=headers)

    # Assert (first call)
    assert resp1.status_code == status.HTTP_201_CREATED, f"Unexpected: {resp1.status_code}, body={resp1.text}"
    assert "ETag" in resp1.headers, "ETag header missing"
    assert "Location" in resp1.headers, "Location header missing"

    data1 = resp1.json()
    assert "slug" in data1, f"Response missing 'slug': {data1}"
    assert data1["title"] == payload["title"]
    assert data1["slug"] == expected_slug

    mock_log.assert_awaited_once()

    # Idempotency replay: SAME request + SAME Idempotency-Key
    with patch("app.api.v1.courses.crud.log_org_event", new=AsyncMock()) as mock_log2:
        resp2 = await async_client.post("/api/v1/courses/create", json=payload, headers=headers)

    assert resp2.status_code == status.HTTP_201_CREATED
    data2 = resp2.json()
    assert data2["slug"] == expected_slug
    assert resp2.headers.get("Location") == resp1.headers.get("Location")
    # Snapshot replay shouldn't emit a second audit event
    mock_log2.assert_not_awaited()


@pytest.mark.anyio
async def test_create_course_service_invalid_category(
    db_session,
    org_user_with_token,
):
    user, _, org = await org_user_with_token()
    invalid_cat_id = uuid4()
    course_data = CourseCreate(
        title="Invalid Cat",
        description="desc",
        visibility="private",
        category_ids=[invalid_cat_id],
        instructor_id=None,
        is_published=False,
    )
    with pytest.raises(HTTPException) as exc:
        await create_course(db_session, course_data, org.id, user.id)

    assert exc.value.status_code == 400
    assert "category" in exc.value.detail.lower()


@pytest.mark.anyio
async def test_create_course_service_instructor_not_in_org(
    db_session,
    org_user_with_token,
    create_test_user,
):
    user, _, org = await org_user_with_token()
    # Create instructor NOT in the org
    other_org_user = await create_test_user()
    course_data = CourseCreate(
        title="Instr Not Org",
        description="desc",
        visibility="public",
        category_ids=[],
        instructor_id=other_org_user.id,
        is_published=True,
    )
    with pytest.raises(HTTPException) as exc:
        await create_course(db_session, course_data, org.id, user.id)
    assert exc.value.status_code == 403
    assert "organization" in exc.value.detail.lower()


@pytest.mark.anyio
async def test_create_course_service_slug_collision(
    db_session,
    org_user_with_token,
    category_factory,
    create_test_user,
    create_user_org_link
):
    user, _, org = await org_user_with_token()
    category = await category_factory()
    instructor = await create_test_user()
    await create_user_org_link(user=instructor, organization=org, role=OrgRole.INTERN)


    base_title = "Slug Collision Course"
    # Precreate a course to force slug collision
    preexisting_course = Course(
        title=base_title,
        slug="slug-collision-course",
        description="desc",
        visibility="public",
        organization_id=org.id,
        is_published=True,
        created_by=user.id,
        updated_by=user.id,
        instructor_id=instructor.id,
    )
    db_session.add(preexisting_course)
    await db_session.commit()

    course_data = CourseCreate(
        title=base_title,
        description="desc",
        visibility="public",
        category_ids=[category.id],
        instructor_id=instructor.id,
        is_published=True,
    )
    course = await create_course(db_session, course_data, org.id, user.id)
    assert course.slug != "slug-collision-course"
    assert course.slug.startswith("slug-collision-course")


@pytest.mark.anyio
async def test_create_course_service_missing_instructor(
    db_session,
    org_user_with_token,
):
    user, _, org = await org_user_with_token()
    fake_instructor_id = uuid4()
    course_data = CourseCreate(
        title="Missing Instructor",
        description="desc",
        visibility="public",
        category_ids=[],
        instructor_id=fake_instructor_id,
        is_published=True,
    )
    with pytest.raises(HTTPException) as exc:
        await create_course(db_session, course_data, org.id, user.id)

    assert exc.value.status_code == 400
    assert "instructor" in exc.value.detail.lower()
