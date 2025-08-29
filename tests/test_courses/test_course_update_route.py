# tests/test_courses/test_course_update_route.py

import pytest
from uuid import uuid4
from unittest.mock import AsyncMock, patch

from sqlalchemy import select
from fastapi import HTTPException

from app.db.models import Course
from app.schemas.enums import OrgRole, CourseVisibility, CourseLevel


@pytest.fixture
async def course_in_org(db_session, org_user_with_token):
    """
    Creates a single course within the caller's org and yields:
    (course, org_user, headers, org)
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Make a course with a unique slug per test to avoid accidental collisions
    base_slug = f"original-title-{org_user.id.hex[:6]}"
    course = Course(
        id=uuid4(),
        title="Original Title",
        slug=base_slug,
        subtitle=None,
        description="original",
        language="en",
        level=CourseLevel.BEGINNER,
        organization_id=org.id,
        created_by=org_user.id,
        is_published=False,
        is_latest=True,
        visibility=CourseVisibility.ORG_ONLY,
    )
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)
    return course, org_user, headers, org


# ──────────────────────────────────────────────────────────────────────────────
# Title change → slug regenerates; other scalar fields update; audit is called.
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_update_course_scalar_fields_and_slug_regen(async_client, db_session, course_in_org):
    course, org_user, headers, org = course_in_org
    payload = {
        "title": "New Title",
        "description": "Updated description",
        "is_published": True,
    }

    with patch(
        "app.api.v1.courses.crud._generate_unique_course_slug",
        AsyncMock(return_value="new-title"),
    ) as mock_slug, patch(
        "app.api.v1.courses.crud.log_org_event",
        AsyncMock(),
    ) as _mock_audit:

        r = await async_client.patch(f"/api/v1/courses/{course.id}", json=payload, headers=headers)
        assert r.status_code == 200, r.text
        data = r.json()

        # Response reflects user-facing fields
        assert data["title"] == "New Title"
        assert data["description"] == "Updated description"
        assert data["slug"] == "new-title"

        # Verify DB flag changed (robust to serializer differences)
        refreshed = await db_session.scalar(select(Course).where(Course.id == course.id))
        assert refreshed.is_published is True

        # Slug helper got the expected args
        mock_slug.assert_awaited_once()
        called_kwargs = mock_slug.await_args.kwargs
        assert called_kwargs["org_id"] == org.id
        assert called_kwargs["base_title"] == "New Title"
        assert called_kwargs["current_course_id"] == course.id


# ──────────────────────────────────────────────────────────────────────────────
# No title change → slug preserved and slug helper is NOT called.
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_update_course_without_title_change_keeps_slug(async_client, db_session, course_in_org):
    course, _org_user, headers, _org = course_in_org

    payload = {"description": "Only description changed", "is_published": True}

    with patch(
        "app.api.v1.courses.crud._generate_unique_course_slug",
        AsyncMock(),
    ) as mock_slug, patch(
        "app.api.v1.courses.crud.log_org_event",
        AsyncMock(),
    ):
        r = await async_client.patch(f"/api/v1/courses/{course.id}", json=payload, headers=headers)
        assert r.status_code == 200, r.text
        data = r.json()

        # Slug stays the same
        assert data["slug"] == course.slug
        # Description reflected
        assert data["description"] == "Only description changed"

        # DB verification for is_published
        refreshed = await db_session.scalar(select(Course).where(Course.id == course.id))
        assert refreshed.is_published is True

        mock_slug.assert_not_called()


# ──────────────────────────────────────────────────────────────────────────────
# Providing category_ids → validator + replacement helpers called with expected args
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_update_course_with_categories_calls_helpers(async_client, db_session, course_in_org):
    course, org_user, headers, org = course_in_org
    cat_ids = [uuid4(), uuid4(), uuid4()]

    with patch(
        "app.api.v1.courses.crud._validate_categories_exist",
        AsyncMock(return_value=cat_ids),
    ) as mock_validate, patch(
        "app.api.v1.courses.crud._replace_course_categories",
        AsyncMock(),
    ) as mock_replace, patch(
        "app.api.v1.courses.crud._generate_unique_course_slug",
        AsyncMock(),  # not relevant here
    ), patch(
        "app.api.v1.courses.crud.log_org_event",
        AsyncMock(),
    ):
        r = await async_client.patch(
            f"/api/v1/courses/{course.id}",
            json={"category_ids": [str(x) for x in cat_ids]},
            headers=headers,
        )
        assert r.status_code == 200, r.text

        # Both helpers run
        mock_validate.assert_awaited_once()
        mock_replace.assert_awaited_once()

        # Check arguments into _replace_course_categories
        kwargs = mock_replace.await_args.kwargs
        assert kwargs["course_id"] == course.id
        assert kwargs["org_id"] == org.id

        # org_user might be a UserOrganization or a plain User depending on fixtures
        expected_actor = getattr(org_user, "user_id", getattr(org_user, "id", None))
        assert kwargs["actor_user_id"] == expected_actor

        # our route sorts IDs before passing
        assert sorted(kwargs["new_category_ids"]) == sorted(cat_ids)


# ──────────────────────────────────────────────────────────────────────────────
# Invalid category IDs → validator raises HTTP 400 → route surfaces 400, no replace call
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_update_course_invalid_categories_bubbles_400(async_client, db_session, course_in_org):
    course, _org_user, headers, _org = course_in_org

    async def _boom(*args, **kwargs):
        raise HTTPException(status_code=400, detail="Bad category IDs")

    with patch(
        "app.api.v1.courses.crud._validate_categories_exist",
        AsyncMock(side_effect=_boom),
    ), patch(
        "app.api.v1.courses.crud._replace_course_categories",
        AsyncMock(),
    ) as mock_replace, patch(
        "app.api.v1.courses.crud.log_org_event",
        AsyncMock(),
    ):
        r = await async_client.patch(
            f"/api/v1/courses/{course.id}",
            json={"category_ids": [str(uuid4())]},
            headers=headers,
        )
        assert r.status_code == 400
        mock_replace.assert_not_called()


# ──────────────────────────────────────────────────────────────────────────────
# 404 for course outside org / non-existent
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_update_course_not_found_404(async_client, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.patch(f"/api/v1/courses/{uuid4()}", json={"title": "X"}, headers=headers)
    assert r.status_code == 404


# ──────────────────────────────────────────────────────────────────────────────
# Empty payload (idempotent) → 200, slug unchanged, no helpers for slug
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_update_course_idempotent_no_changes(async_client, db_session, course_in_org):
    course, _org_user, headers, _org = course_in_org
    original_slug = course.slug

    with patch(
        "app.api.v1.courses.crud._generate_unique_course_slug",
        AsyncMock(),
    ) as mock_slug, patch(
        "app.api.v1.courses.crud.log_org_event",
        AsyncMock(),
    ):
        # Empty body should be valid Pydantic payload with exclude_unset == {}
        r = await async_client.patch(f"/api/v1/courses/{course.id}", json={}, headers=headers)
        assert r.status_code == 200, r.text
        data = r.json()

        assert data["slug"] == original_slug
        mock_slug.assert_not_called()

        # DB row still present
        refreshed = await db_session.scalar(select(Course).where(Course.id == course.id))
        assert refreshed is not None
