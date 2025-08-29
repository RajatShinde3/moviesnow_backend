import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import status
from uuid import uuid4

from app.schemas.enums import Visibility
from app.db.models import Organization, UserOrganization, EnterpriseProfile
from app.schemas.enums import OrgRole
from tests.fixtures.orgs import create_organization

@pytest.fixture
async def created_enterprise_profile(org_with_users, db_session: AsyncSession):
    """Fixture to create a default enterprise profile for the test org."""
    owner_user, org, _ = await org_with_users()
    await db_session.flush()

    profile = EnterpriseProfile(
        user_id=owner_user.id,
        organization_id=org.id,
        website="https://test.org",
        visibility=Visibility.PUBLIC,
    )
    db_session.add(profile)
    await db_session.commit()

    return profile, (owner_user, org)


@pytest.mark.anyio
async def test_owner_can_view_own_profile(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_with_users,
):
    org_obj = await org_with_users(as_tuple=False)

    profile = EnterpriseProfile(
        organization_id=org_obj.org.id,
        user_id=org_obj.owner.id,
        visibility=Visibility.ORG_ONLY,
        website="https://example.com",
        contact_phone="123-456-7890",
    )
    db_session.add(profile)
    await db_session.commit()

    res = await async_client.get(
        "/api/v1/org/enterprise/profile",
        headers={"Authorization": f"Bearer {org_obj.owner_token}"}
    )
    assert res.status_code == status.HTTP_200_OK
    assert res.json()["website"] == "https://example.com/"

@pytest.mark.anyio
async def test_cross_org_view_with_permission(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_with_users,
    create_test_user,
    create_user_org_link,
    get_auth_headers,
):
    # Create org and enterprise profile
    org_obj = await org_with_users(as_tuple=False)
    print(f"Created org: {org_obj.org.id}, owner: {org_obj.owner.id}")

    profile = EnterpriseProfile(
        user_id=org_obj.owner.id,
        organization_id=org_obj.org.id,
        visibility=Visibility.PUBLIC,
        website="https://private.com",
        contact_phone="123-456-7890",
    )
    db_session.add(profile)
    await db_session.commit()
    print("Enterprise profile created.")

    # Create external user and add to the org
    external_user = await create_test_user()
    print(f"Created external user: {external_user.id}")

    await create_user_org_link(
        user=external_user,
        organization=org_obj.org,
        role=OrgRole.ADMIN,
        is_active=True,
    )
    print(f"Linked external user {external_user.id} to org {org_obj.org.id} as ADMIN")

    # Get auth headers
    external_headers = await get_auth_headers(
        user=external_user,
        organization=org_obj.org,
        role=OrgRole.ADMIN,
        mfa_authenticated=True,
    )

    print(f"Auth headers generated: {external_headers}")

    # Make request
    res = await async_client.get(
        "/api/v1/org/enterprise/profile",
        headers={**external_headers, "X-Org-ID": str(org_obj.org.id)},
    )
    print(f"Response status: {res.status_code}")
    print(f"Response JSON: {res.text}")

    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["website"] == "https://private.com/"





@pytest.mark.anyio
async def test_cross_org_forbidden_without_link(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_with_users,
    create_test_user,
    create_organization_fixture,
    get_auth_headers,
):
    org_obj = await org_with_users(as_tuple=False)
    profile = EnterpriseProfile(
        user_id=org_obj.owner.id,
        organization_id=org_obj.org.id,
        visibility=Visibility.PRIVATE,
        website="https://private.com",
        contact_phone="123-456-7890",
    )
    db_session.add(profile)
    await db_session.commit()

    external_user = await create_test_user()
    external_org = await create_organization_fixture()
    external_headers = await get_auth_headers(external_user, external_org, OrgRole.OWNER)

    res = await async_client.get(
        "/api/v1/org/enterprise/profile",
        headers={**external_headers, "X-Org-ID": str(org_obj.org.id)},
    )
    assert res.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.anyio
@pytest.mark.parametrize(
    "visibility, expected_status",
    [
        (Visibility.PUBLIC, 200),
        (Visibility.ORG_ONLY, 200),
        (Visibility.PRIVATE, 403),
    ],
)
async def test_visibility_rules(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_with_users,
    visibility,
    expected_status,
):
    org_obj = await org_with_users(as_tuple=False)

    profile = EnterpriseProfile(
        user_id=org_obj.owner.id,
        organization_id=org_obj.org.id,
        visibility=visibility,
        website="https://visibility.com",
        contact_phone="123-456-7890",
    )
    db_session.add(profile)
    await db_session.commit()

    res = await async_client.get(
        "/api/v1/org/enterprise/profile",
        headers={
            "Authorization": f"Bearer {org_obj.member_token}",
            "X-Org-ID": str(org_obj.org.id),
        },
    )
    assert res.status_code == expected_status
    if expected_status == 200:
        data = res.json()
        assert data["website"] == "https://visibility.com/"


@pytest.mark.anyio
async def test_org_only_visibility_blocks_external_users(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_with_users,
    create_test_user,
    create_organization_fixture,
    get_auth_headers,
):
    # Get full structured org + users with as_tuple=False to access .org
    org_obj = await org_with_users(as_tuple=False)

    # Create profile with ORG_ONLY visibility
    profile = EnterpriseProfile(
        user_id=org_obj.owner.id,
        organization_id=org_obj.org.id,
        visibility=Visibility.ORG_ONLY,
        website="https://internal.only",
        contact_phone="123-456-7890",
    )
    db_session.add(profile)
    await db_session.commit()

    # Create external user in another org
    outsider = await create_test_user()
    outsider_org = await create_organization_fixture()
    outsider_headers = await get_auth_headers(outsider, outsider_org, OrgRole.ADMIN)

    res = await async_client.get(
        "/api/v1/org/enterprise/profile",
        headers={
            **outsider_headers,
            "X-Org-ID": str(org_obj.org.id),
        },
    )
    assert res.status_code == status.HTTP_403_FORBIDDEN