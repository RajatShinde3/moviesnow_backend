import pytest
from typing import Callable, Awaitable, Dict, Tuple
from uuid import uuid4
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import User, Organization
from app.schemas.enums import OrgRole
from app.core.security import create_access_token
from tests.utils.factory import create_user

# ─────────────────────────────────────────────────────────────
# 🔐 Token + Auth Fixtures for Testing
# ─────────────────────────────────────────────────────────────
# ─── Fixture: Create user and return (user, token) ────────────
@pytest.fixture
def user_with_token(db_session: AsyncSession) -> Callable[..., Awaitable[Tuple[User, str]]]:
    """
    Creates a test user and returns (user, token) tuple.
    """
    async def _create(**kwargs):
        email = kwargs.get("email")
        if email:
            existing = (await db_session.execute(select(User).where(User.email == email))).scalar_one_or_none()
            if existing:
                user = existing
            else:
                user = await create_user(session=db_session, **kwargs)
                await db_session.commit()
                await db_session.refresh(user)
        else:
            user = await create_user(session=db_session, **kwargs)
            await db_session.commit()
            await db_session.refresh(user)

        token = await create_access_token(str(user.id))
        return user, token


    return _create


@pytest.fixture
def user_with_headers(user_with_token) -> Callable[..., Awaitable[Tuple[User, Dict[str, str]]]]:
    """
    Same as user_with_token but returns (user, headers) instead of (user, token).
    Useful for tests expecting ready-to-use auth headers.
    """
    async def _create(**kwargs):
        user, token = await user_with_token(**kwargs)
        headers = {"Authorization": f"Bearer {token}"}
        return user, headers
    return _create


# ─── Fixture: User in Org with Role + Headers ────────────────
@pytest.fixture
def org_user_with_token(
    create_test_user,
    create_organization_fixture,
    create_user_org_link,
    get_auth_headers,
    db_session: AsyncSession,  # Needed for committing active_org_id
) -> Callable[..., Awaitable[Tuple[User, Dict[str, str], Organization]]]:
    """
    ✅ Fixture Factory: Creates a user linked to an organization and returns auth headers.

    Args:
        role: Role to assign to the user in the organization.
        set_active_org: Whether to set user's active/default org (optional; defaults to False)

    Returns:
        (User, auth headers, Organization)
    """

    async def _create(
        role: OrgRole = OrgRole.ADMIN,
        set_active_org: bool = False,  # <-- NEW ARG
    ):
        user = await create_test_user()
        org = await create_organization_fixture()
        await create_user_org_link(user=user, organization=org, role=role)

        if set_active_org:
            user.active_org_id = org.id
            user.default_org_id = org.id
            db_session.add(user)
            await db_session.commit()

        headers = await get_auth_headers(user, org, role)
        return user, headers, org

    return _create



# ─── Fixture: Token for a normal user in an org ──────────────
@pytest.fixture
async def normal_user_token_headers(another_user_in_same_org) -> Dict[str, str]:
    """
    Returns Bearer token header for a regular user in an org.
    """
    user, _ = another_user_in_same_org
    token = await create_access_token(user_id=user.id)
    return {"Authorization": f"Bearer {token}"}


# ─── Fixture: Callable to return Bearer token headers ────────
@pytest.fixture()
def auth_headers() -> Callable[[User], Callable[[], Awaitable[Dict[str, str]]]]:
    """
    Returns a function to generate headers from a given user.
    Usage:
        headers = await auth_headers(user)()
    """
    def _get_headers(user: User):
        async def headers():
            token = await create_access_token(str(user.id))
            return {"Authorization": f"Bearer {token}"}
        return headers

    return _get_headers


# ─── Fixture: Return headers with org-scoped JWT ─────────────

@pytest.fixture
def get_auth_headers():
    """
    🔐 Fixture that returns an async function to generate valid Bearer auth headers for a user/org context.

    Usage:
        headers = await get_auth_headers(user, org, role)

    Returns:
        Callable[[User, Organization, OrgRole], Awaitable[dict]]:
            A coroutine that returns a dict with the Authorization header.
    """

    async def _generate_headers(
        user: User,
        organization: Organization,
        role: OrgRole = OrgRole.INTERN,
        mfa_authenticated: bool = False,
    ) -> dict:
        token = await create_access_token(
            user_id=str(user.id),
            active_org={"org_id": str(organization.id), "role": role.value},
            mfa_authenticated=mfa_authenticated,
        )
        return {"Authorization": f"Bearer {token}"}

    return _generate_headers

# ─── Fixture: Superadmin + another user in shared org ────────
@pytest.fixture
async def superuser_token_headers(
    superadmin_user,
    create_user_org_link,
    create_organization_fixture,
    another_user_in_same_org,
) -> Dict[str, str]:
    """
    Superadmin user linked to shared test org, returns valid token header.
    """
    superuser = superadmin_user
    org = await create_organization_fixture(name="Shared Test Org")

    await create_user_org_link(user=superuser, organization=org, role=OrgRole.SUPERADMIN)

    user, _ = another_user_in_same_org
    await create_user_org_link(user=user, organization=org, role=OrgRole.INTERN)

    token = await create_access_token(
        user_id=str(superuser.id),
        active_org={"org_id": str(org.id), "role": OrgRole.SUPERADMIN.value},
    )

    return {"Authorization": f"Bearer {token}"}


