# tests/utils/factory.py

import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import uuid4
import pytest
from app.db.models.user import User
from app.db.models.organization import Organization
from app.db.models.user_organization import UserOrganization
from app.core.security import get_password_hash
from tests.utils.faker import fake
from app.schemas.enums import OrgRole

async def create_user(
    session: AsyncSession,
    *,
    email: Optional[str] = None,
    password: str = "password",
    is_active: bool = True,
    is_verified: bool = True,
    is_superuser: bool = False,
    full_name: str = "Test User",
    organizations: Optional[list[Organization]] = None,
    org_roles: Optional[list[str]] = None,
    **kwargs
) -> User:
    """
    ✅ Utility function to create a test user with optional organization memberships.

    Args:
        session (AsyncSession): SQLAlchemy async session.
        email (str, optional): Email for the user. Defaults to a fake one.
        password (str): Plain password. Defaults to "password".
        is_active (bool): Whether the user is active.
        is_verified (bool): Whether the user is verified.
        is_superuser (bool): Whether the user is a superuser.
        full_name (str): Full name of the user.
        organizations (list[Organization], optional): List of organizations to link the user to.
        org_roles (list[str], optional): Roles corresponding to each organization.
        **kwargs: Extra fields for the user model.

    Returns:
        User: Created user object (refreshed from DB).
    """

    user = User(
        id=uuid4(),
        email=email or fake.email(),
        full_name=full_name,
        username = f"{fake.user_name()}_{uuid4().hex[:8]}",
        phone=fake.phone_number(),
        hashed_password=get_password_hash(password),
        is_active=is_active,
        is_verified=is_verified,
        is_superuser=is_superuser,
        can_create_org=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        **kwargs,
    )

    session.add(user)
    await session.flush()

    # 🔗 Link to organizations (if provided)
    if organizations:
        for idx, org in enumerate(organizations):
            role = (
                org_roles[idx]
                if org_roles and idx < len(org_roles)
                else (OrgRole.ADMIN if is_superuser else OrgRole.INTERN)
            )
            membership = UserOrganization(
                user_id=user.id,
                organization_id=org.id,
                role=role,
                is_active=True,
                joined_at=datetime.now(timezone.utc),
            )
            session.add(membership)

    await session.commit()
    await session.refresh(user)
    return user


async def create_superuser(
    session: AsyncSession,
    *,
    email: Optional[str] = None,
    password: str = "adminpass",
    full_name: str = "Admin User"
) -> User:
    """
    Creates a verified, active superuser for testing.

    Returns:
        User: Superuser instance.
    """
    return await create_user(
        session=session,
        email=email,
        password=password,
        full_name=full_name,
        is_superuser=True,
        is_verified=True,
        is_active=True,
    )


async def create_org_for_user(
    session: AsyncSession,
    *,
    user: User,
    org_name: Optional[str] = None,
    role: str = "OWNER"
) -> Organization:
    """
    Create an organization and assign the user a role in it.

    Args:
        session (AsyncSession): DB session.
        user (User): The user to assign to the organization.
        org_name (str, optional): Optional org name; auto-generated if not provided.
        role (str): Role of the user in the org ("OWNER", "ADMIN", etc.)

    Returns:
        Organization: The created organization instance.
    """
    organization = Organization(
        name=org_name or fake.company(),
        created_by=user.id,
    )
    session.add(organization)
    await session.flush()

    membership = UserOrganization(
        user_id=user.id,
        organization_id=organization.id,
        role=role,
        is_active=True,
        joined_at=datetime.now(timezone.utc)
    )
    session.add(membership)
    await session.flush()
    await session.refresh(organization)
    return organization


def make_email(prefix: str = "user") -> str:
    """
    Generate a unique, realistic-looking email address.

    Args:
        prefix (str): Prefix before the underscore.

    Returns:
        str: Randomized test email, e.g., "user_a9d21b@example.com"
    """
    unique = fake.uuid4()[:6]
    domain = fake.free_email_domain()
    return f"{prefix}_{unique}@{domain}"


@pytest.fixture
def create_user_org_link_factory():
    """
    ✅ Fixture factory to create UserOrganization links.
    """
    async def _create(db: AsyncSession, user: User, organization: Organization, role=OrgRole.SUPERADMIN, is_active=True):
        link = UserOrganization(
            user_id=user.id,
            organization_id=organization.id,
            role=role,
            is_active=is_active,
        )
        db.add(link)
        await db.commit()
        await db.refresh(link)
        return link
    return _create
