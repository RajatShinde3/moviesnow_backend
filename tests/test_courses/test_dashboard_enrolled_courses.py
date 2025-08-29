# tests/test_courses/test_dashboard_enrolled_courses.py

import pytest
from uuid import uuid4
from datetime import datetime, timezone
from typing import Optional, Union

from sqlalchemy.orm.attributes import InstrumentedAttribute

from app.db.models import (
    Course,
    CourseEnrollment,
    User,
    UserOrganization,
)
from app.schemas.enums import CourseVisibility, CourseLevel, OrgRole

# ──────────────────────────────────────────────────────────────────────────────
# Utilities (schema‑resilient setters & creators)
# ──────────────────────────────────────────────────────────────────────────────

def _set_if_has(obj, **fields):
    """
    Set attributes only if the ORM model has them, the value is not None,
    and the value is not a SQLAlchemy InstrumentedAttribute (column).
    """
    for k, v in fields.items():
        if v is None or not hasattr(obj, k):
            continue
        if isinstance(v, InstrumentedAttribute):
            continue
        setattr(obj, k, v)


async def _create_course(
    db,
    *,
    org_id,
    creator_id,
    title: str = "Course",
    is_published: bool = True,
    visibility: Optional[CourseVisibility] = CourseVisibility.PUBLIC,
) -> Course:
    c = Course(
        id=uuid4(),
        title=title,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
        description=f"{title} description",
        organization_id=org_id,
        is_published=is_published,
        language="en",
        level=CourseLevel.BEGINNER,
    )

    # Harden for stricter schemas with real values
    _set_if_has(
        c,
        created_by=creator_id,
        is_free=True,
        visibility=visibility,
        total_lessons=0,
        total_enrollments=0,
        rating=0.0,
    )

    # If status enum/column exists, set a proper enum value (not the column)
    try:
        from app.schemas.enums import CourseStatus  # optional
        if hasattr(c, "status"):
            c.status = CourseStatus.PUBLISHED if is_published else CourseStatus.DRAFT
    except Exception:
        pass

    db.add(c)
    await db.commit()
    await db.refresh(c)
    return c


async def _enroll_user_in_course(
    db,
    *,
    user_or_org_user: Union[User, UserOrganization],
    course: Course,
    completed: bool = False,
) -> CourseEnrollment:
    """
    Create a CourseEnrollment for either a personal User or an org membership (UserOrganization).
    Sets user_id / user_org_id correctly to avoid FK violations.
    """
    # Resolve IDs safely
    if isinstance(user_or_org_user, UserOrganization):
        user_id = user_or_org_user.user_id
        user_org_id = user_or_org_user.id
        enrolled_by = user_or_org_user.user_id
    else:  # User
        user_id = user_or_org_user.id
        user_org_id = None  # don’t set if your schema enforces FK; helper will skip if column absent
        enrolled_by = user_or_org_user.id

    e = CourseEnrollment(
        id=uuid4(),
        course_id=course.id,
        user_id=user_id,
    )

    # Only set membership FK if column exists
    _set_if_has(e, user_org_id=user_org_id)

    # Typical optional fields
    _set_if_has(
        e,
        is_active=True,
        enrolled_by=enrolled_by,
        progress_percent=100 if completed else 0,
        rating=None,
        review=None,
        certificate_url=None,
        price_paid=None,
    )
    if completed:
        _set_if_has(e, completed_at=datetime(2025, 1, 1, tzinfo=timezone.utc))

    db.add(e)
    await db.commit()
    await db.refresh(e)
    return e


# ──────────────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_enrolled_courses_returns_list_for_org_user(async_client, db_session, org_user_with_token):
    """
    200 + returns at least one enrolled course for an org-context caller with permissions.
    Works whether the fixture returns a User or a UserOrganization.
    """
    org_user_or_membership, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    course = await _create_course(db_session, org_id=org.id, creator_id=org_user_or_membership.user_id if isinstance(org_user_or_membership, UserOrganization) else org_user_or_membership.id, title="My Enrolled Course")
    await _enroll_user_in_course(db_session, user_or_org_user=org_user_or_membership, course=course)

    r = await async_client.get("/api/v1/org/dashboard/enrolled-courses", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    titles = {c["title"] for c in data}
    assert "My Enrolled Course" in titles


@pytest.mark.anyio
async def test_enrolled_courses_empty_when_no_enrollments(async_client, db_session, org_user_with_token):
    """
    200 + returns empty list when the caller has no enrollments.
    """
    org_user_or_membership, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    r = await async_client.get("/api/v1/org/dashboard/enrolled-courses", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json() == []


@pytest.mark.anyio
async def test_enrolled_courses_org_scoping(async_client, db_session, org_user_with_token):
    """
    Results are scoped to the active org: courses/enrollments from other orgs do not appear.
    """
    # Active org + caller
    ours_member, ours_headers, ours_org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    # Another org + caller (no active org set)
    theirs_member, _, theirs_org = await org_user_with_token(role=OrgRole.ADMIN)

    # Course/enrollment in the active org
    creator_id = ours_member.user_id if isinstance(ours_member, UserOrganization) else ours_member.id
    ours_course = await _create_course(db_session, org_id=ours_org.id, creator_id=creator_id, title="In Our Org")
    await _enroll_user_in_course(db_session, user_or_org_user=ours_member, course=ours_course)

    # Course/enrollment in a different org
    creator_id2 = theirs_member.user_id if isinstance(theirs_member, UserOrganization) else theirs_member.id
    theirs_course = await _create_course(db_session, org_id=theirs_org.id, creator_id=creator_id2, title="Other Org Course")
    await _enroll_user_in_course(db_session, user_or_org_user=theirs_member, course=theirs_course)

    r = await async_client.get("/api/v1/org/dashboard/enrolled-courses", headers=ours_headers)
    assert r.status_code == 200, r.text
    titles = {c["title"] for c in r.json()}
    assert "In Our Org" in titles
    assert "Other Org Course" not in titles


@pytest.mark.anyio
async def test_enrolled_courses_permission_denied_for_member(async_client, db_session, org_user_with_token):
    """
    403 when the user does not have VIEW_DASHBOARD permission (e.g., INTERN).
    If your policy allows INTERN, adjust expected status to 200.
    """
    member, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    creator_id = member.user_id if isinstance(member, UserOrganization) else member.id
    course = await _create_course(db_session, org_id=org.id, creator_id=creator_id, title="Hidden Course")
    await _enroll_user_in_course(db_session, user_or_org_user=member, course=course)

    r = await async_client.get("/api/v1/org/dashboard/enrolled-courses", headers=headers)
    assert r.status_code in (403, 401), r.text
