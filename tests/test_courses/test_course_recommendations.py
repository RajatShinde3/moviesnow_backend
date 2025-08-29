import pytest
from uuid import uuid4
from sqlalchemy import select
from datetime import datetime, timezone
from app.db.models import (
    Course,
    Category,
    CourseCategoryAssociation,
    Lesson,
    LessonProgress,
    CourseEnrollment,
    User,
)
from app.schemas.enums import CourseVisibility, CourseLevel, OrgRole


# ── Helper to set attributes safely ──
def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if v is not None and hasattr(obj, k):
            setattr(obj, k, v)


from app.db.models import UserOrganization

async def _get_or_create_user_org(db, *, user_id, org_id):
    """Return a UserOrganization row for (user, org); create if missing."""
    uo = await db.scalar(
        select(UserOrganization).where(
            UserOrganization.user_id == user_id,
            UserOrganization.organization_id == org_id,
        )
    )
    if uo is None:
        uo = UserOrganization(user_id=user_id, organization_id=org_id)
        db.add(uo)
        await db.commit()
        await db.refresh(uo)
    return uo


async def _create_category(db, org_id, creator_id, name=None):
    """Create and return a category."""
    c = Category(
        id=uuid4(),
        name=name or f"Cat {uuid4().hex[:6]}",
    )
    _set_if_has(
        c,
        slug=f"cat-{uuid4().hex[:6]}",
        organization_id=org_id,
        created_by=creator_id
    )
    db.add(c)
    await db.commit()
    await db.refresh(c)
    return c


async def _create_course(
    db, *, org_id, creator_id, title, category_ids=(), is_published=True
):
    """Create a course with optional categories."""
    course = Course(
        id=uuid4(),
        title=title,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
        description=f"{title} description",
        visibility=CourseVisibility.PUBLIC,
        is_published=is_published,
        organization_id=org_id,
        created_by=creator_id,
        language="en",
        level=CourseLevel.BEGINNER,
        is_free=True,
    )
    db.add(course)
    await db.commit()
    await db.refresh(course)

    # Create associations if categories provided
    for cat_id in category_ids:
        cca = CourseCategoryAssociation(
            course_id=course.id,
            category_id=cat_id,
            organization_id=org_id,
            created_by=creator_id,
            # Optional: ensure 'name' is filled if model requires
            name=f"Assoc-{title}"
        )
        db.add(cca)
    if category_ids:
        await db.commit()

    # Refresh course to make sure relationship is loaded
    await db.refresh(course)
    return course


async def _create_lesson(db, course_id, org_id, creator_id, title="Lesson"):
    """Create a lesson linked to a course; set required NOT NULLs defensively."""
    lesson = Lesson(
        id=uuid4(),
        title=title,
        course_id=course_id,
    )
    # Set fields only if they exist in your schema
    _set_if_has(
        lesson,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
        order=1,                    # many schemas require it
        organization_id=org_id,     # avoid FK NOT NULL failures
        is_published=True,          # harmless default for tests
        created_by=creator_id,
    )
    db.add(lesson)
    await db.commit()
    await db.refresh(lesson)
    return lesson




@pytest.mark.anyio
async def test_recommended_courses_fallback(async_client, db_session, org_user_with_token):
    """If no personalized results, return recent courses."""
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Create some courses
    await _create_course(db_session, org_id=org.id, creator_id=org_user.id, title="Course 1")
    await _create_course(db_session, org_id=org.id, creator_id=org_user.id, title="Course 2")

    r = await async_client.get("/api/v1/courses/recommended", headers=headers)
    assert r.status_code == 200
    titles = {c["title"] for c in r.json()}
    assert {"Course 1", "Course 2"}.issubset(titles)


@pytest.mark.anyio
async def test_recommended_courses_with_personalization(async_client, db_session, org_user_with_token):
    """Personalized courses should be returned if categories match completed lessons."""
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    cat1 = await _create_category(db_session, org.id, org_user.id)

    # Create a course with this category and a lesson
    course_personal = await _create_course(
        db_session,
        org_id=org.id,
        creator_id=org_user.id,
        title="Personalized",
        category_ids=[cat1.id],
    )
    lesson = await _create_lesson(db_session, course_personal.id, org.id, org_user.id)

    # Ensure we have the correct user_org row for the FK
    user_org = await _get_or_create_user_org(db_session, user_id=org_user.id, org_id=org.id)

    # Record completion (must include course_id and correct user_org_id)
    lp = LessonProgress(
        user_id=org_user.id,
        user_org_id=user_org.id,                # ✅ actual FK to user_organizations.id
        lesson_id=lesson.id,
        course_id=course_personal.id,           # ✅ required by DB
        is_completed=True,                      # optional but nice for clarity
        completed_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )
    db_session.add(lp)
    await db_session.commit()

    r = await async_client.get("/api/v1/courses/recommended", headers=headers)
    assert r.status_code == 200
    titles = [c["title"] for c in r.json()]
    assert "Personalized" in titles




@pytest.mark.anyio
async def test_related_courses_basic(async_client, db_session, org_user_with_token):
    """Related courses should share at least one category with the base course."""
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    print(f"[DEBUG] Org ID: {org.id}, Org User ID: {org_user.id}")

    cat_shared = await _create_category(db_session, org.id, org_user.id)
    print(f"[DEBUG] Created category: ID={cat_shared.id}, Name={cat_shared.name}")

    base_course = await _create_course(
        db_session,
        org_id=org.id,
        creator_id=org_user.id,
        title="Base",
        category_ids=[cat_shared.id]
    )
    print(f"[DEBUG] Base course: ID={base_course.id}, Title={base_course.title}")

    related_course = await _create_course(
        db_session,
        org_id=org.id,
        creator_id=org_user.id,
        title="Related",
        category_ids=[cat_shared.id]
    )
    print(f"[DEBUG] Related course: ID={related_course.id}, Title={related_course.title}")

    # Verify DB state before calling API
    all_courses = await db_session.execute(select(Course))
    all_courses_list = all_courses.scalars().all()
    print(f"[DEBUG] All courses in DB: {[ (c.id, c.title) for c in all_courses_list ]}")

    all_assocs = await db_session.execute(select(CourseCategoryAssociation))
    all_assocs_list = all_assocs.scalars().all()
    print(f"[DEBUG] All course-category associations: "
          f"{[ (a.course_id, a.category_id, a.organization_id) for a in all_assocs_list ]}")

    # Call the API
    r = await async_client.get(f"/api/v1/courses/related/{base_course.id}", headers=headers)
    print(f"[DEBUG] API status: {r.status_code}")
    print(f"[DEBUG] API response: {r.json()}")

    assert r.status_code == 200
    titles = [c["title"] for c in r.json()]
    assert "Related" in titles


@pytest.mark.anyio
async def test_related_courses_exclude_ids(async_client, db_session, org_user_with_token):
    """Excluded IDs should not appear in results."""
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    cat_shared = await _create_category(db_session, org.id, org_user.id)

    base_course = await _create_course(db_session, org_id=org.id, creator_id=org_user.id, title="Base", category_ids=[cat_shared.id])
    to_exclude = await _create_course(db_session, org_id=org.id, creator_id=org_user.id, title="ExcludeMe", category_ids=[cat_shared.id])

    r = await async_client.get(
        f"/api/v1/courses/related/{base_course.id}",
        params={"exclude_ids": str(to_exclude.id)},
        headers=headers
    )
    assert r.status_code == 200
    titles = [c["title"] for c in r.json()]
    assert "ExcludeMe" not in titles


@pytest.mark.anyio
async def test_related_courses_exclude_completed(async_client, db_session, org_user_with_token):
    """Completed courses should not appear in related list."""
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    cat_shared = await _create_category(db_session, org.id, org_user.id)

    base_course = await _create_course(db_session, org_id=org.id, creator_id=org_user.id, title="Base", category_ids=[cat_shared.id])
    completed_course = await _create_course(db_session, org_id=org.id, creator_id=org_user.id, title="Completed", category_ids=[cat_shared.id])

    # Mark completed
    enrollment = CourseEnrollment(
        user_id=org_user.id,
        course_id=completed_course.id,
        completed_at=datetime(2025, 1, 1, tzinfo=timezone.utc)
    )
    db_session.add(enrollment)
    await db_session.commit()

    r = await async_client.get(f"/api/v1/courses/related/{base_course.id}", headers=headers)
    assert r.status_code == 200
    titles = [c["title"] for c in r.json()]
    assert "Completed" not in titles


@pytest.mark.anyio
async def test_related_courses_no_categories(async_client, db_session, org_user_with_token):
    """If base course has no categories, return empty list."""
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    base_course = await _create_course(db_session, org_id=org.id, creator_id=org_user.id, title="BaseNoCats")

    r = await async_client.get(f"/api/v1/courses/related/{base_course.id}", headers=headers)
    assert r.status_code == 200
    assert r.json() == []
