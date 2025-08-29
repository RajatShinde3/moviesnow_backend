import pytest
from uuid import uuid4
from sqlalchemy import select
from datetime import datetime, timezone

from app.schemas.enums import OrgRole, CourseVisibility
from app.db.models import Course, CourseEnrollment, UserOrganization
from app.services.courses.access_control import can_access_course


def _utcnow():
    return datetime.now(timezone.utc)

def _rand_slug(prefix: str = "course") -> str:
    return f"{prefix}-{uuid4().hex[:10]}"

def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


@pytest.mark.anyio
async def test_access_public_published_for_any_principal(db_session, org_user_with_token, user_with_token):
    org_user, _, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    plain_user, _ = await user_with_token()

    c = Course(
        title="Public",
        slug=_rand_slug("public"),
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PUBLIC,
    )
    _set_if_has(c, created_by=org_user.id)
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)

    assert await can_access_course(db_session, c.id, org_user) is True
    assert await can_access_course(db_session, c.id, plain_user) is True


@pytest.mark.anyio
async def test_access_private_requires_matching_enrollment(db_session, org_user_with_token, user_with_token):
    org_user, _, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    plain_user, _ = await user_with_token()

    c = Course(
        title="Private",
        slug=_rand_slug("private"),
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PRIVATE,
    )
    _set_if_has(c, created_by=org_user.id)
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)

    # No enrollment yet → both denied
    assert await can_access_course(db_session, c.id, org_user) is False
    assert await can_access_course(db_session, c.id, plain_user) is False

    # Add org-scoped enrollment for org_user
    mem = (
        await db_session.execute(
            select(UserOrganization).where(
                UserOrganization.user_id == org_user.id,
                UserOrganization.organization_id == org.id,
            )
        )
    ).scalars().first()
    assert mem is not None

    e_org = CourseEnrollment(
        course_id=c.id,
        user_id=org_user.id,
        user_org_id=mem.id,
        is_active=True,
        enrolled_at=_utcnow(),
    )
    _set_if_has(e_org, organization_id=org.id)
    db_session.add(e_org)
    await db_session.commit()

    assert await can_access_course(db_session, c.id, org_user) is True
    assert await can_access_course(db_session, c.id, plain_user) is False

    # Add user-scoped enrollment for plain_user
    e_user = CourseEnrollment(
        course_id=c.id,
        user_id=plain_user.id,
        is_active=True,
        enrolled_at=_utcnow(),
    )
    _set_if_has(e_user, organization_id=org.id)
    db_session.add(e_user)
    await db_session.commit()

    assert await can_access_course(db_session, c.id, plain_user) is True


@pytest.mark.anyio
async def test_access_org_only_rules_for_user_and_userorg(db_session, org_user_with_token, user_with_token):
    org_user, _, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    plain_user, _ = await user_with_token()

    c = Course(
        title="OrgOnly",
        slug=_rand_slug("orgonly"),
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.ORG_ONLY,
    )
    _set_if_has(c, created_by=org_user.id)
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)

    # Org_user without enrollment → deny
    assert await can_access_course(db_session, c.id, org_user) is False

    # Plain user with no org membership → deny
    assert await can_access_course(db_session, c.id, plain_user) is False

    # Give the plain user a membership in the org + enrollment through that membership
    mem = UserOrganization(
        user_id=plain_user.id,
        organization_id=org.id,
        role=OrgRole.INTERN,   # or OrgRole.ADMIN/INTERN etc. — any valid enum
    )
    _set_if_has(mem, created_by=org_user.id)
    db_session.add(mem)
    await db_session.commit()
    await db_session.refresh(mem)

    enroll = CourseEnrollment(
        course_id=c.id,
        user_id=plain_user.id,
        user_org_id=mem.id,
        is_active=True,
        enrolled_at=_utcnow(),
    )
    _set_if_has(enroll, organization_id=org.id)
    db_session.add(enroll)
    await db_session.commit()

    assert await can_access_course(db_session, c.id, plain_user) is True
