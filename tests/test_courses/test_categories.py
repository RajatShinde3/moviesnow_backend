# tests/test_courses/test_course_category_routes.py

import pytest
from uuid import uuid4
from sqlalchemy import select, and_

from app.db.models import Category, CourseCategoryAssociation
from app.schemas.enums import OrgRole


def _slug(s: str) -> str:
    """Tiny slug helper for tests; production uses real slugify."""
    return s.strip().lower().replace(" ", "-")


@pytest.mark.anyio
async def test_create_category_success(async_client, db_session, org_user_with_token):
    """
    ✅ Org user can create a new category.
    - Creates a global Category (if missing)
    - Creates an org-scoped CourseCategoryAssociation
    - Returns CategoryRead with id/name/slug
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    payload = {"name": "Engineering"}
    r = await async_client.post("/api/v1/courses/category", json=payload, headers=headers)
    assert r.status_code == 201, r.text

    data = r.json()
    assert data["name"] == "Engineering"
    assert data["slug"] == _slug("Engineering")

    # Global Category exists
    cat = await db_session.scalar(select(Category).where(Category.id == data["id"]))
    assert cat is not None
    assert cat.slug == _slug("Engineering")

    # Org-scoped association exists
    assoc = await db_session.scalar(
        select(CourseCategoryAssociation).where(
            and_(
                CourseCategoryAssociation.category_id == cat.id,
                CourseCategoryAssociation.organization_id == org.id,
            )
        )
    )
    assert assoc is not None
    assert assoc.name == "Engineering"


@pytest.mark.anyio
async def test_create_category_duplicate_in_org(async_client, db_session, org_user_with_token):
    """
    ❌ Creating a category with the same name already linked to the same org should return 400.
    Setup:
    - Pre-create global Category
    - Pre-create org association
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Pre-create global category + association in this org
    cat = Category(name="Marketing", slug=_slug("Marketing"))
    db_session.add(cat)
    await db_session.flush()

    assoc = CourseCategoryAssociation(
        name="Marketing",
        category_id=cat.id,
        organization_id=org.id,
        created_by=org_user.id,
    )
    db_session.add(assoc)
    await db_session.commit()

    # Attempt to create same name again for the same org
    r = await async_client.post("/api/v1/courses/category", json={"name": "Marketing"}, headers=headers)
    assert r.status_code == 400
    assert "already exists" in r.text


@pytest.mark.anyio
async def test_list_categories_filters_by_org(async_client, db_session, org_user_with_token):
    """
    ✅ List returns only categories linked to the current org via CourseCategoryAssociation.
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    # Create two categories + associations for this org
    c1 = Category(name="Backend", slug=_slug("Backend"))
    c2 = Category(name="Design", slug=_slug("Design"))
    db_session.add_all([c1, c2])
    await db_session.flush()

    a1 = CourseCategoryAssociation(
        name=c1.name, category_id=c1.id, organization_id=org.id, created_by=org_user.id
    )
    a2 = CourseCategoryAssociation(
        name=c2.name, category_id=c2.id, organization_id=org.id, created_by=org_user.id
    )
    db_session.add_all([a1, a2])
    await db_session.commit()

    # Create a category in another org (should not be returned)
    other_user, _, other_org = await org_user_with_token(role=OrgRole.ADMIN)
    c3 = Category(name="Unrelated", slug=_slug("Unrelated"))
    db_session.add(c3)
    await db_session.flush()
    a3 = CourseCategoryAssociation(
        name=c3.name, category_id=c3.id, organization_id=other_org.id, created_by=other_user.id
    )
    db_session.add(a3)
    await db_session.commit()

    r = await async_client.get("/api/v1/courses/category", headers=headers)
    assert r.status_code == 200
    payload = r.json()
    names = [c["name"] for c in payload]

    assert "Backend" in names
    assert "Design" in names
    assert "Unrelated" not in names


@pytest.mark.anyio
async def test_update_category_success(async_client, db_session, org_user_with_token):
    """
    ✅ Update category (global rename) that is linked to current org.
    Ensures global Category.name/slug change and association remains valid.
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Create global category and link to this org
    cat = Category(name="Old Name", slug=_slug("Old Name"))
    db_session.add(cat)
    await db_session.flush()
    assoc = CourseCategoryAssociation(
        name=cat.name,
        category_id=cat.id,
        organization_id=org.id,
        created_by=org_user.id,
    )
    db_session.add(assoc)
    await db_session.commit()
    await db_session.refresh(cat)

    # Update via API
    r = await async_client.patch(
        f"/api/v1/courses/category/{cat.id}",
        json={"name": "New Name"},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["name"] == "New Name"
    assert data["slug"] == _slug("New Name")

    # Verify DB changes
    updated = await db_session.get(Category, cat.id)
    assert updated.name == "New Name"
    assert updated.slug == _slug("New Name")

    # Association should still exist for this org
    assoc2 = await db_session.scalar(
        select(CourseCategoryAssociation).where(
            and_(
                CourseCategoryAssociation.category_id == cat.id,
                CourseCategoryAssociation.organization_id == org.id,
            )
        )
    )
    assert assoc2 is not None
    # Optional: association display name can drift or be normalized; we don't enforce here.


@pytest.mark.anyio
async def test_update_category_not_found_in_org(async_client, db_session, org_user_with_token):
    """
    ❌ Updating a category that is NOT linked to the current org must return 404.
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Create a category not linked to this org
    cat = Category(name="Lonely", slug=_slug("Lonely"))
    db_session.add(cat)
    await db_session.commit()

    r = await async_client.patch(
        f"/api/v1/courses/category/{cat.id}",
        json={"name": "Updated"},
        headers=headers,
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_delete_category_success(async_client, db_session, org_user_with_token):
    """
    ✅ Deleting removes only the org-scoped association; the global Category remains.
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    cat = Category(name="ToDelete", slug=_slug("ToDelete"))
    db_session.add(cat)
    await db_session.flush()

    assoc = CourseCategoryAssociation(
        name=cat.name,
        category_id=cat.id,
        organization_id=org.id,
        created_by=org_user.id,
    )
    db_session.add(assoc)
    await db_session.commit()

    r = await async_client.delete(f"/api/v1/courses/category/{cat.id}", headers=headers)
    assert r.status_code == 204

    # Association gone
    gone = await db_session.scalar(
        select(CourseCategoryAssociation).where(
            and_(
                CourseCategoryAssociation.category_id == cat.id,
                CourseCategoryAssociation.organization_id == org.id,
            )
        )
    )
    assert gone is None

    # Global category should still exist
    still_there = await db_session.get(Category, cat.id)
    assert still_there is not None
    assert still_there.slug == _slug("ToDelete")


@pytest.mark.anyio
async def test_delete_category_not_found(async_client, org_user_with_token):
    """
    ❌ Deleting a category not associated with the current org returns 404.
    """
    org_user, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.delete(f"/api/v1/courses/category/{uuid4()}", headers=headers)
    assert r.status_code == 404
