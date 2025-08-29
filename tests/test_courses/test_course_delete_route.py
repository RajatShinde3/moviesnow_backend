# tests/test_courses/test_course_delete_route.py

import pytest
from uuid import uuid4
from sqlalchemy import select, and_

from app.db.models import (
    Course,
    CourseCategoryAssociation,
    Category,
)
from app.schemas.enums import CourseVisibility, CourseLevel, OrgRole
from unittest.mock import AsyncMock, patch


def _new_course(*, org, creator, title="My Course", slug_prefix="c"):
    return Course(
        id=uuid4(),
        title=title,
        slug=f"{slug_prefix}-{creator.id.hex[:6]}",
        description="desc",
        language="en",
        level=CourseLevel.BEGINNER,
        visibility=CourseVisibility.ORG_ONLY,
        is_published=False,
        is_archived=False,
        organization_id=org.id,
        created_by=creator.id,
    )


@pytest.mark.anyio
async def test_soft_delete_archives_course(async_client, db_session, org_user_with_token):
    """
    Soft delete (default) sets is_archived=True and returns 204. Audit is called.
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    course = _new_course(org=org, creator=org_user, title="SoftDel", slug_prefix="sd")
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    with patch("app.api.v1.courses.crud.log_org_event", AsyncMock()) as mock_audit:
        r = await async_client.delete(f"/api/v1/courses/{course.id}", headers=headers)
        assert r.status_code == 204

        refreshed = await db_session.scalar(select(Course).where(Course.id == course.id))
        assert refreshed is not None
        assert refreshed.is_archived is True

        # audit called with meta includes hard=False
        mock_audit.assert_awaited()
        md = mock_audit.await_args.kwargs.get("meta_data", {})
        assert md.get("course_id") == str(course.id)
        assert md.get("hard") is False


@pytest.mark.anyio
async def test_soft_delete_404_when_not_in_org(async_client, db_session, org_user_with_token):
    """
    404 when the course does not exist in the caller's org.
    """
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.delete(f"/api/v1/courses/{uuid4()}", headers=headers)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_soft_delete_can_include_reason_in_audit(async_client, db_session, org_user_with_token):
    """
    Reason query param is propagated to audit meta on soft delete.
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = _new_course(org=org, creator=org_user, title="WithReason", slug_prefix="wr")
    db_session.add(course)
    await db_session.commit()

    with patch("app.api.v1.courses.crud.log_org_event", AsyncMock()) as mock_audit:
        r = await async_client.delete(
            f"/api/v1/courses/{course.id}?reason=cleanup", headers=headers
        )
        assert r.status_code == 204

        mock_audit.assert_awaited()
        meta = mock_audit.await_args.kwargs.get("meta_data", {})
        assert meta.get("reason") == "cleanup"
        assert meta.get("hard") is False


@pytest.mark.anyio
async def test_hard_delete_blocked_without_force_returns_409(async_client, db_session, org_user_with_token):
    """
    hard=true with blocking references and force=false => 409 and course remains.
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = _new_course(org=org, creator=org_user, title="Blocked", slug_prefix="blk")
    db_session.add(course)
    await db_session.commit()

    with patch(
        "app.api.v1.courses.crud._blocking_references_summary",
        AsyncMock(return_value={"enrollments": 7, "reviews": 0})
    ):
        r = await async_client.delete(
            f"/api/v1/courses/{course.id}?hard=true", headers=headers
        )
        assert r.status_code == 409
        body = r.json()
        assert "blocking_counts" in body["detail"]
        assert body["detail"]["blocking_counts"]["enrollments"] == 7

        # Course still exists
        still_there = await db_session.scalar(select(Course).where(Course.id == course.id))
        assert still_there is not None


@pytest.mark.anyio
async def test_hard_delete_no_blockers_deletes_course_and_unlinks_categories(async_client, db_session, org_user_with_token):
    """
    hard=true with no blockers removes course and org-scoped course↔category links.
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Create course
    course = _new_course(org=org, creator=org_user, title="CleanPurge", slug_prefix="hp")
    db_session.add(course)
    await db_session.flush()

    # Create a global category + org-scoped association to this course
    cat = Category(name="PurgeCat", slug=f"purge-{org.id.hex[:6]}")
    db_session.add(cat)
    await db_session.flush()

    assoc = CourseCategoryAssociation(
        name="PurgeCat",
        course_id=course.id,
        category_id=cat.id,
        organization_id=org.id,
        created_by=org_user.id,
    )
    db_session.add(assoc)
    await db_session.commit()

    with patch(
        "app.api.v1.courses.crud._blocking_references_summary",
        AsyncMock(return_value={})
    ), patch(
        "app.api.v1.courses.crud.log_org_event",
        AsyncMock()
    ) as mock_audit:
        r = await async_client.delete(
            f"/api/v1/courses/{course.id}?hard=true", headers=headers
        )
        assert r.status_code == 204

        # Course removed
        gone = await db_session.scalar(select(Course).where(Course.id == course.id))
        assert gone is None

        # Association removed
        assoc_gone = await db_session.scalar(
            select(CourseCategoryAssociation).where(
                and_(
                    CourseCategoryAssociation.course_id == course.id,
                    CourseCategoryAssociation.organization_id == org.id,
                )
            )
        )
        assert assoc_gone is None

        # Audit called with hard=True
        mock_audit.assert_awaited()
        meta = mock_audit.await_args.kwargs.get("meta_data", {})
        assert meta.get("hard") is True
        assert meta.get("force") is False
        assert isinstance(meta.get("predelete_counts"), dict)


@pytest.mark.anyio
async def test_hard_delete_with_blockers_and_force_true_purges(async_client, db_session, org_user_with_token):
    """
    hard=true&force=true with blockers => purge proceeds and course is deleted.
    """
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    course = _new_course(org=org, creator=org_user, title="ForcePurge", slug_prefix="fp")
    db_session.add(course)
    await db_session.commit()

    blockers = {"enrollments": 3, "progress": 10}
    with patch(
        "app.api.v1.courses.crud._blocking_references_summary",
        AsyncMock(return_value=blockers)
    ), patch(
        "app.api.v1.courses.crud.log_org_event",
        AsyncMock()
    ) as mock_audit:
        r = await async_client.delete(
            f"/api/v1/courses/{course.id}?hard=true&force=true&reason=reorg",
            headers=headers,
        )
        assert r.status_code == 204

        gone = await db_session.scalar(select(Course).where(Course.id == course.id))
        assert gone is None

        mock_audit.assert_awaited()
        meta = mock_audit.await_args.kwargs.get("meta_data", {})
        assert meta.get("hard") is True
        assert meta.get("force") is True
        assert meta.get("predelete_counts") == blockers
        assert meta.get("reason") == "reorg"

@pytest.mark.anyio
async def test_delete_idempotent_replay(async_client, db_session, org_user_with_token):
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = _new_course(org=org, creator=org_user, title="IdemDel", slug_prefix="idem")
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    idem_key = f"del-{uuid4()}"
    headers = {**headers, "Idempotency-Key": idem_key}

    with patch("app.api.v1.courses.crud.log_org_event", AsyncMock()) as mock_audit:
        r1 = await async_client.delete(f"/api/v1/courses/{course.id}", headers=headers)
        assert r1.status_code == 204
        mock_audit.assert_awaited()

    # second call (same key) should 204 again, without new audit
    with patch("app.api.v1.courses.crud.log_org_event", AsyncMock()) as mock_audit2:
        r2 = await async_client.delete(f"/api/v1/courses/{course.id}", headers=headers)
        assert r2.status_code == 204
        mock_audit2.assert_not_awaited()


@pytest.mark.anyio
async def test_delete_if_match_mismatch_returns_412(async_client, db_session, org_user_with_token):
    org_user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = _new_course(org=org, creator=org_user, title="Precond", slug_prefix="pc")
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    bad_etag = "not-the-right-etag"
    headers = {**headers, "If-Match": bad_etag}

    r = await async_client.delete(f"/api/v1/courses/{course.id}", headers=headers)
    assert r.status_code == 412
