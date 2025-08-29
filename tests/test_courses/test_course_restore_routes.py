# tests/test_courses/test_course_restore_routes.py

import pytest
from uuid import uuid4
from sqlalchemy import select

from app.db.models import Course
from app.schemas.enums import CourseVisibility, CourseLevel, OrgRole


def _new_course(*, cid, title, slug, org_id, creator_id, archived=False):
    """Factory: a minimal, valid Course row for tests."""
    return Course(
        id=cid,
        title=title,
        slug=slug,
        description="desc",
        visibility=CourseVisibility.ORG_ONLY,
        is_published=False,
        organization_id=org_id,
        created_by=creator_id,
        language="en",
        level=CourseLevel.BEGINNER,
        is_archived=archived,
    )


# ───────────────────────────────────────────────────────────────
# Single restore: PATCH /api/v1/courses/{course_id}/restore
# ───────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_restore_course_unarchives_course(async_client, db_session, org_user_with_token, monkeypatch):
    """
    ✅ Restores a soft-deleted course (is_archived=True → False) in caller's org.
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    course_id = uuid4()
    course = _new_course(
        cid=course_id,
        title="Archived Course",
        slug="archived-course",
        org_id=org.id,
        creator_id=org_user.id,
        archived=True,
    )
    db_session.add(course)
    await db_session.commit()

    # Call route
    r = await async_client.patch(f"/api/v1/courses/{course_id}/restore", headers=headers)
    assert r.status_code == 200, r.text

    # DB verification
    refreshed = await db_session.scalar(select(Course).where(Course.id == course_id))
    assert refreshed is not None
    assert refreshed.is_archived is False   # unarchived


@pytest.mark.anyio
async def test_restore_course_is_idempotent_when_already_active(async_client, db_session, org_user_with_token):
    """
    ✅ If the course is already active (is_archived=False), still returns 200 and keeps it active.
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    course_id = uuid4()
    course = _new_course(
        cid=course_id,
        title="Active Course",
        slug="active-course",
        org_id=org.id,
        creator_id=org_user.id,
        archived=False,
    )
    db_session.add(course)
    await db_session.commit()

    r = await async_client.patch(f"/api/v1/courses/{course_id}/restore", headers=headers)
    assert r.status_code == 200, r.text

    refreshed = await db_session.scalar(select(Course).where(Course.id == course_id))
    assert refreshed.is_archived is False


@pytest.mark.anyio
async def test_restore_course_404_when_in_other_org(async_client, db_session, org_user_with_token):
    """
    ❌ Course exists but belongs to another org → 404.
    """
    # Caller org + headers
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    # Another org
    other_user, _, other_org = await org_user_with_token(role=OrgRole.ADMIN)

    course_id = uuid4()
    course = _new_course(
        cid=course_id,
        title="Other Org Archived",
        slug="other-org-archived",
        org_id=other_org.id,
        creator_id=other_user.id,
        archived=True,
    )
    db_session.add(course)
    await db_session.commit()

    r = await async_client.patch(f"/api/v1/courses/{course_id}/restore", headers=headers)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_restore_course_404_when_missing(async_client, org_user_with_token):
    """
    ❌ Missing course → 404.
    """
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.patch(f"/api/v1/courses/{uuid4()}/restore", headers=headers)
    assert r.status_code == 404


# ───────────────────────────────────────────────────────────────
# Bulk restore: POST /api/v1/courses/restore  (payload: {"ids": [...]})
# ───────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_bulk_restore_mixed_ids(async_client, db_session, org_user_with_token):
    """
    ✅ Bulk restore:
       - Restores courses that are archived and belong to caller's org
       - Leaves already-active ones as-is
       - Ignores IDs from other orgs and missing IDs
       - Returns *all* courses that belong to the org (restored + already active)
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    other_user, _, other_org = await org_user_with_token(role=OrgRole.ADMIN)

    # In caller's org
    archived_1 = _new_course(
        cid=uuid4(), title="A1", slug="a1", org_id=org.id, creator_id=org_user.id, archived=True
    )
    archived_2 = _new_course(
        cid=uuid4(), title="A2", slug="a2", org_id=org.id, creator_id=org_user.id, archived=True
    )
    active_1 = _new_course(
        cid=uuid4(), title="B1", slug="b1", org_id=org.id, creator_id=org_user.id, archived=False
    )

    # Outside org
    other_archived = _new_course(
        cid=uuid4(), title="X1", slug="x1", org_id=other_org.id, creator_id=other_user.id, archived=True
    )

    db_session.add_all([archived_1, archived_2, active_1, other_archived])
    await db_session.commit()

    missing_id = uuid4()

    r = await async_client.post(
        "/api/v1/courses/restore",
        json={"ids": [str(archived_1.id), str(archived_2.id), str(active_1.id), str(other_archived.id), str(missing_id)]},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    data = r.json()

    # Only courses in caller's org are returned (3 items)
    returned_ids = {c["id"] for c in data}
    assert returned_ids == {str(archived_1.id), str(archived_2.id), str(active_1.id)}

    # DB checks: archived ones are now active
    rows = await db_session.execute(select(Course).where(Course.id.in_([archived_1.id, archived_2.id, active_1.id])))
    courses = {c.id: c for c in rows.scalars().all()}
    assert courses[archived_1.id].is_archived is False
    assert courses[archived_2.id].is_archived is False
    assert courses[active_1.id].is_archived is False


@pytest.mark.anyio
async def test_bulk_restore_empty_payload_returns_empty_list(async_client, org_user_with_token):
    """
    ✅ Empty payload → 200 with [] (idempotent, no work).
    """
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.post("/api/v1/courses/restore", json={"ids": []}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json() == []
