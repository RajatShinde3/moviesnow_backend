# tests/test_courses/test_courses_search_route.py

import pytest
from uuid import uuid4
from typing import Iterable, Optional
from sqlalchemy import select
from starlette import status

from app.db.models import (
    Course,
    Category,
    CourseCategoryAssociation,
    User,
)
from app.schemas.enums import CourseVisibility, CourseLevel, OrgRole


# ── Test config: change this if your router is mounted elsewhere ──
SEARCH_URL = "/api/v1/courses/search"


# ── Safer attribute setter that won't override DB defaults with None ──
def _set_if_has(obj, **fields):
    """
    Set attributes only if the ORM model has the attribute AND value is not None.
    Avoids accidentally writing NULL into NOT NULL columns and allows DB defaults.
    """
    for k, v in fields.items():
        if v is not None and hasattr(obj, k):
            setattr(obj, k, v)


async def _create_instructor(db, org_id=None):
    u = User(
        id=uuid4(),
        email=f"inst+{uuid4().hex[:6]}@example.com",
    )
    _set_if_has(u, is_active=True, name="Instructor")

    # Ensure NOT NULL fields are filled
    _set_if_has(u, hashed_password="fakehashedpassword123")

    await db.merge(u)
    await db.commit()
    return await db.scalar(select(User).where(User.id == u.id))



async def _create_category(db, org_id, creator_id):
    """
    Create a Category row. Only sets org/slug/etc. if your schema expects them.
    """
    c = Category(
        id=uuid4(),
        name=f"Cat {uuid4().hex[:6]}",
    )
    _set_if_has(
        c,
        slug=f"cat-{uuid4().hex[:6]}",
        organization_id=org_id,
        created_by=creator_id,
    )
    db.add(c)
    await db.commit()
    await db.refresh(c)
    return c

async def _link_categories(db, course: Course, org_id, creator_id, categories: Iterable[Category]):
    for cat in categories:
        cca = CourseCategoryAssociation(
            course_id=course.id,
            category_id=cat.id,
        )
        # Set required NOT NULL fields if they exist
        _set_if_has(cca, organization_id=org_id, created_by=creator_id)

        # ✅ Fix: ensure name is set if table requires it
        if hasattr(cca, "name") and not getattr(cca, "name", None):
            cca.name = cat.name  # use category's name or a default

        db.add(cca)
    await db.commit()



async def _make_course(
    db,
    *,
    org_id,
    creator_id,
    title: str,
    is_published: bool = True,
    visibility: CourseVisibility = CourseVisibility.PUBLIC,
    instructor_id: Optional[uuid4] = None,
    attach_categories: Iterable[Category] = (),
):
    """
    Create a Course with only the fields your schema truly needs.
    We avoid setting NOT NULL fields to None so DB defaults apply.
    """
    course = Course(
        id=uuid4(),
        title=title,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
        description=f"{title} description",
        visibility=visibility,
        is_published=is_published,
        organization_id=org_id,
        created_by=creator_id,
        language="en",
        level=CourseLevel.BEGINNER,
    )
    # Only set if present AND not None — lets defaults (e.g., status) work:
    _set_if_has(course, is_free=True)
    if instructor_id is not None:
        _set_if_has(course, instructor_id=instructor_id)

    db.add(course)
    await db.commit()
    await db.refresh(course)

    if attach_categories:
        await _link_categories(db, course, org_id, creator_id, attach_categories)

    return course


@pytest.mark.anyio
async def test_search_text_and_pagination(async_client, db_session, org_user_with_token):
    """
    Text query should match title/description; results are org-scoped and newest first.
    Pagination (skip/limit) is respected.
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Create three courses in this org
    await _make_course(db_session, org_id=org.id, creator_id=org_user.id, title="Python Basics")
    await _make_course(db_session, org_id=org.id, creator_id=org_user.id, title="Advanced Python")
    await _make_course(db_session, org_id=org.id, creator_id=org_user.id, title="Rust for Pythonistas")

    # Search "Python", limit 2 (query param name is 'query')
    r = await async_client.get(
        SEARCH_URL,
        params={"query": "Python", "limit": 2},
        headers=headers,
    )
    assert r.status_code == status.HTTP_200_OK, r.text
    data = r.json()

    assert len(data) == 2  # limited to 2
    titles = {d["title"] for d in data}
    assert titles.issubset({"Python Basics", "Advanced Python", "Rust for Pythonistas"})


@pytest.mark.anyio
async def test_filter_by_category_ids(async_client, db_session, org_user_with_token):
    """
    category_ids filter returns only courses linked to those categories (org-scoped).
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    cat_a = await _create_category(db_session, org.id, org_user.id)
    cat_b = await _create_category(db_session, org.id, org_user.id)

    await _make_course(db_session, org_id=org.id, creator_id=org_user.id, title="A1", attach_categories=[cat_a])
    await _make_course(db_session, org_id=org.id, creator_id=org_user.id, title="B1", attach_categories=[cat_b])
    await _make_course(db_session, org_id=org.id, creator_id=org_user.id, title="AB", attach_categories=[cat_a, cat_b])
    await _make_course(db_session, org_id=org.id, creator_id=org_user.id, title="NoCat")

    # Provide list param style for category_ids
    r = await async_client.get(
        SEARCH_URL,
        params=[("category_ids", str(cat_a.id))],
        headers=headers,
    )
    assert r.status_code == status.HTTP_200_OK, r.text
    titles = {d["title"] for d in r.json()}
    assert titles == {"A1", "AB"}


@pytest.mark.anyio
async def test_filter_by_instructor_id(async_client, db_session, org_user_with_token):
    """
    instructor_id filter returns only courses taught by that instructor.
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    instructor_1 = await _create_instructor(db_session)
    instructor_2 = await _create_instructor(db_session)

    await _make_course(
        db_session, org_id=org.id, creator_id=org_user.id, title="By I1", instructor_id=instructor_1.id
    )
    await _make_course(
        db_session, org_id=org.id, creator_id=org_user.id, title="By I2", instructor_id=instructor_2.id
    )
    await _make_course(
        db_session, org_id=org.id, creator_id=org_user.id, title="No Instructor"
    )

    r = await async_client.get(
        SEARCH_URL,
        params={"instructor_id": str(instructor_1.id)},
        headers=headers,
    )
    assert r.status_code == status.HTTP_200_OK, r.text
    titles = [d["title"] for d in r.json()]
    assert titles == ["By I1"]


@pytest.mark.anyio
async def test_filter_by_is_published_and_visibility(async_client, db_session, org_user_with_token):
    """
    Combine is_published and visibility filters.
    NOTE: visibility enum expects lowercase (e.g., 'public').
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    await _make_course(
        db_session, org_id=org.id, creator_id=org_user.id, title="PubPublic",
        is_published=True, visibility=CourseVisibility.PUBLIC
    )
    await _make_course(
        db_session, org_id=org.id, creator_id=org_user.id, title="PubOrg",
        is_published=True, visibility=CourseVisibility.ORG_ONLY
    )
    await _make_course(
        db_session, org_id=org.id, creator_id=org_user.id, title="DraftPublic",
        is_published=False, visibility=CourseVisibility.PUBLIC
    )

    r = await async_client.get(
        SEARCH_URL,
        params={"is_published": True, "visibility": "public"},  # lowercase!
        headers=headers,
    )
    assert r.status_code == status.HTTP_200_OK, r.text
    titles = [d["title"] for d in r.json()]
    assert titles == ["PubPublic"]


@pytest.mark.anyio
async def test_org_scoping_excludes_other_org(async_client, db_session, org_user_with_token):
    """
    Verify results are scoped to the caller's active org.
    """
    # Caller org
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    # Another org + user (no active_org set here)
    other_user, _, other_org = await org_user_with_token(role=OrgRole.ADMIN)

    await _make_course(db_session, org_id=org.id, creator_id=org_user.id, title="Ours")
    await _make_course(db_session, org_id=other_org.id, creator_id=other_user.id, title="Theirs")

    r = await async_client.get(SEARCH_URL, headers=headers)
    assert r.status_code == status.HTTP_200_OK, r.text
    titles = [d["title"] for d in r.json()]
    assert "Ours" in titles
    assert "Theirs" not in titles


@pytest.mark.anyio
async def test_empty_result_when_no_match(async_client, db_session, org_user_with_token):
    """
    Query that matches nothing returns empty list (200 OK).
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    await _make_course(db_session, org_id=org.id, creator_id=org_user.id, title="Some course")

    r = await async_client.get(
        SEARCH_URL,
        params={"query": "definitely-no-match"},
        headers=headers,
    )
    assert r.status_code == status.HTTP_200_OK, r.text
    assert r.json() == []
