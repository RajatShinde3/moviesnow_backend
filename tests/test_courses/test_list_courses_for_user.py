import pytest
from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import Course
from app.schemas.enums import CourseVisibility

@pytest.mark.anyio
async def test_get_my_accessible_courses_public_user(
    async_client,
    user_with_headers,
    db_session: AsyncSession,
):
    user, headers = await user_with_headers()

    courses = [
        Course(
            title="Public Published",
            description="desc",
            visibility=CourseVisibility.PUBLIC,
            is_published=True,
            organization_id=None,
            created_by=user.id,
            slug=f"public-published-{user.id.hex[:6]}"
        ),
        Course(
            title="Public Unpublished",
            description="desc",
            visibility=CourseVisibility.PUBLIC,
            is_published=False,
            organization_id=None,
            created_by=user.id,
            slug=f"public-unpublished-{user.id.hex[:6]}"
        ),
        Course(
            title="Private Published Org Course",
            description="desc",
            visibility=CourseVisibility.PRIVATE,
            is_published=True,
            organization_id=None,  # no org for public user
            created_by=user.id,
            slug=f"private-org-course-{user.id.hex[:6]}"
        )
    ]
    db_session.add_all(courses)
    await db_session.commit()

    response = await async_client.get("/api/v1/courses/me", headers=headers)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    # Only public published course should be visible
    assert any(c["title"] == "Public Published" for c in data)
    assert all(c["visibility"] == "public" for c in data)
    assert all(c["is_published"] for c in data)


@pytest.mark.anyio
async def test_get_my_accessible_courses_org_user(
    async_client,
    org_user_with_token,
    db_session: AsyncSession,
):
    user, headers, org = await org_user_with_token()

    # Set the active_org_id so your service can detect org membership
    user.active_org_id = org.id
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    org_course = Course(
        title="Org Course Published",
        description="desc",
        visibility=CourseVisibility.PRIVATE,
        is_published=True,
        organization_id=org.id,
        created_by=user.id,
        slug=f"org-course-published-{user.id.hex[:6]}"
    )
    public_course = Course(
        title="Public Course Published",
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        is_published=True,
        organization_id=None,
        created_by=user.id,
        slug=f"public-course-published-{user.id.hex[:6]}"
    )
    db_session.add_all([org_course, public_course])
    await db_session.commit()

    response = await async_client.get("/api/v1/courses/me", headers=headers)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()

    titles = [c["title"] for c in data]
    print("User type:", type(user))
    print("User org id:", getattr(user, "active_org_id", None))
    print("Returned courses titles:", titles)

    assert "Org Course Published" in titles
    assert "Public Course Published" not in titles



@pytest.mark.anyio
async def test_get_visible_courses_for_user_service(
    db_session: AsyncSession,
    user_with_headers,
    org_user_with_token,
):
    user, _ = await user_with_headers()
    org_user, _, org = await org_user_with_token()

    public_course = Course(
        title="Public Published",
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        is_published=True,
        organization_id=None,
        created_by=user.id,
        slug=f"public-published-{user.id.hex[:6]}"
    )
    org_course = Course(
        title="Org Published",
        description="desc",
        visibility=CourseVisibility.PRIVATE,
        is_published=True,
        organization_id=org.id,
        created_by=org_user.id,
        slug=f"org-published-{org_user.id.hex[:6]}"
    )
    db_session.add_all([public_course, org_course])
    await db_session.commit()

    from app.api.v1.courses.listing import get_visible_courses_for_user

    # For public user, no org id needed
    public_courses = await get_visible_courses_for_user(db_session, user)
    print("Public user sees courses visibilities:", [c.visibility for c in public_courses])
    assert all(c.visibility == CourseVisibility.PUBLIC for c in public_courses)

    # Set org id on org_user so filtering works
    org_user.active_org_id = org.id
    db_session.add(org_user)
    await db_session.commit()
    await db_session.refresh(org_user)

    org_courses = await get_visible_courses_for_user(db_session, org_user)
    print("Org user sees courses org_ids:", [str(c.organization_id) for c in org_courses])
    assert all(c.organization_id == org.id for c in org_courses)





@pytest.mark.anyio
async def test_get_my_accessible_courses_unauthenticated(async_client):
    response = await async_client.get("/api/v1/courses/me")
    assert response.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)

