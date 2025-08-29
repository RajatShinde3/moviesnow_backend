import pytest
from sqlalchemy.ext.asyncio import AsyncSession
import uuid
from datetime import datetime, timezone
from sqlalchemy import select
from app.db.models import User, Organization, UserOrganization
from app.schemas.enums import OrgRole
from typing import Callable, Awaitable, Tuple, Optional, Union
from app.core.security import create_access_token
from collections import namedtuple

# Use NamedTuple for clean attribute access in tests

OrgWithUsers = namedtuple(
    "OrgWithUsers",
    ["owner", "member", "org", "token", "owner_token", "member_token", "member_role"]
)


@pytest.fixture
def create_user_org_link(db_session: AsyncSession):
    """
    ✅ Factory fixture to link a user to an organization with a specific role.

    Returns:
        Callable[..., Awaitable[UserOrganization]]: Async function to create and return the user-org link.

    Usage:
        await create_user_org_link(user=user, organization=org, role=OrgRole.ADMIN)
    """

    async def _link(
        user: User,
        organization: Organization,
        role: OrgRole,
        is_active: bool = True,
    ) -> UserOrganization:
        link = UserOrganization(
            user_id=user.id,
            organization_id=organization.id,
            role=role,
            is_active=is_active,
        )

        db_session.add(link)
        await db_session.commit()
        await db_session.refresh(link)
        return link

    return _link





async def create_organization(db: AsyncSession, name: str = None) -> Organization:
    org = Organization(
        name=name or f"Test Org {uuid.uuid4()}",
        slug=f"test-org-{uuid.uuid4().hex[:6]}",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(org)
    await db.flush()  # Use flush instead of commit in nested helpers
    return org


@pytest.fixture
def create_organization_fixture(db_session: AsyncSession):
    async def _create(name: str = None) -> Organization:
        if name:
            result = await db_session.execute(select(Organization).where(Organization.name == name))
            org = result.scalar_one_or_none()
            if org:
                return org
        org = await create_organization(db_session, name)
        await db_session.commit()
        await db_session.refresh(org)
        return org
    return _create




@pytest.fixture
def user_with_org(
    db_session: AsyncSession,
    create_test_user,
    create_organization_fixture,
) -> Callable[..., Awaitable[Tuple[User, str]]]:
    """
    🔧 Fixture factory to create a user linked to a new organization, and return a JWT token.

    Args:
        role (OrgRole, optional): Role to assign to the user. Defaults to OrgRole.INTERN.
        is_active (bool, optional): Whether the user-org link is active. Defaults to True.
        only_user (bool, optional): If True, creates only this one user in the org.

    Returns:
        Tuple[User, str]: The user and a valid JWT token with active_org payload.
    """

    async def _create(
        role: OrgRole = OrgRole.INTERN,
        is_active: bool = True,
        only_user: bool = False,
        email: Optional[str] = None,
    ) -> Tuple[User, str]:
        user = await create_test_user(email=email)
        org = await create_organization_fixture()

        # Link user to org
        link = UserOrganization(
            user_id=user.id,
            organization_id=org.id,
            role=role,
            is_active=is_active,
        )
        db_session.add(link)
        await db_session.commit()
        await db_session.refresh(link)

        # Create token with org context
        token = await create_access_token(user_id=str(user.id), active_org={
            "org_id": str(org.id),
            "role": role.value,
        })

        return user, token

    return _create



@pytest.fixture
def org_with_users(
    create_organization_fixture,
    create_test_user,
    create_user_org_link,
    get_auth_headers,
) -> Callable[..., Union[Tuple, OrgWithUsers]]:
    """
    🔧 Fixture factory to create an organization with:
    - an OWNER user (with auth token)
    - an optional MEMBER user

    Args (passed to inner factory):
        owner_role (OrgRole): Role for the owner user (default: OWNER)
        member_role (OrgRole | None): Role for a second user. None to skip (default: INTERN)
        as_tuple (bool): If True, return (owner, member, token); else return OrgWithUsers (default: True)

    Returns:
        Callable[..., Union[Tuple[User, Optional[User], str], OrgWithUsers]]:
            A factory to generate users + org. Use `await org_with_users(...)`.
    """

    async def _create_org_users(
        owner_role: OrgRole = OrgRole.OWNER,
        member_role: Optional[OrgRole] = OrgRole.INTERN,
        as_tuple: bool = True,
        use_member_token: bool = False,  # NEW: choose which token to return
    ) -> Union[Tuple, OrgWithUsers]:
        # Create organization
        org = await create_organization_fixture()

        # Create and link owner
        owner = await create_test_user()
        await create_user_org_link(user=owner, organization=org, role=owner_role)
        owner_headers = await get_auth_headers(owner, org, owner_role)
        owner_token = owner_headers["Authorization"].split(" ")[1]

        # Optional member
        member = None
        member_token = None
        if member_role:
            member = await create_test_user()
            await create_user_org_link(user=member, organization=org, role=member_role)
            member_headers = await get_auth_headers(member, org, member_role)
            member_token = member_headers["Authorization"].split(" ")[1]

        # Backward-compatible tuple return (default: use owner token)
        if as_tuple:
            token = member_token if use_member_token and member_token else owner_token
            return owner, member, token

        return OrgWithUsers(
            owner=owner,
            member=member,
            org=org,
            token=member_token if use_member_token and member_token else owner_token,
            owner_token=owner_token,
            member_token=member_token,
            member_role=member_role,
        )

    return _create_org_users


@pytest.fixture
async def another_user_in_same_org(
    create_test_user,
    create_organization_fixture,
    create_user_org_link,
):
    """
    👥 Fixture to create a user and associate them with a newly created org.

    Useful for testing scenarios where multiple users exist in the same organization.

    Returns:
        tuple: (User, UserOrganization)
    """
    org = await create_organization_fixture()
    user = await create_test_user(email="member1@example.com")
    user_org = await create_user_org_link(
        user=user,
        organization=org,
        role=OrgRole.INTERN,
    )
    return user, user_org


@pytest.fixture
def org_user_with_token_for_id_override(org_user_with_token):
    """
    Same as org_user_with_token, but allows passing an existing org explicitly.
    """
    async def _create_with_org(org: Organization, role: OrgRole = OrgRole.EMPLOYEE):
        user, headers, _ = await org_user_with_token(role=role)
        # Override user's org association with the provided one
        await create_user_org_link(user=user, organization=org, role=role)
        return user, headers, org

    return _create_with_org
