import pytest
from httpx import AsyncClient
from app.schemas.enums import OrgRole
from app.core.security import create_access_token
from tests.test_org.test_org_settings import auth_header

@pytest.mark.anyio
async def test_get_user_orgs_returns_all_active_orgs(
    async_client: AsyncClient,
    create_test_user,
    create_organization_fixture,
    create_user_org_link,
):
    """
    ✅ Should return all organizations the user belongs to with correct roles.
    """
    user = await create_test_user()
    org1 = await create_organization_fixture(name="Org Alpha")
    org2 = await create_organization_fixture(name="Org Beta")

    await create_user_org_link(user, org1, role=OrgRole.ADMIN)
    await create_user_org_link(user, org2, role=OrgRole.INTERN)

    token = await create_access_token(user_id=user.id)

    response = await async_client.get(
        "/api/v1/org/me/orgs",
        headers=auth_header(token),
    )

    assert response.status_code == 200
    orgs = response.json()["data"]

    assert len(orgs) == 2
    assert {o["organization_name"] for o in orgs} == {"Org Alpha", "Org Beta"}
    assert {o["role"] for o in orgs} == {OrgRole.ADMIN, OrgRole.INTERN}


@pytest.mark.anyio
async def test_get_user_orgs_returns_empty_list_if_none(
    async_client: AsyncClient,
    create_test_user,
):
    """
    ✅ Should return empty list if user belongs to no organizations.
    """
    user = await create_test_user()
    token = await create_access_token(user_id=user.id)

    response = await async_client.get(
        "/api/v1/org/me/orgs",
        headers=auth_header(token),
    )

    assert response.status_code == 200
    assert response.json()["data"] == []


@pytest.mark.anyio
async def test_get_current_user_context_success(
    async_client: AsyncClient,
    create_test_user,
    create_organization_fixture,
    create_user_org_link,
):
    """
    ✅ Should return current user profile along with active org context.
    """
    user = await create_test_user(email="user@example.com", full_name="Test User")
    org = await create_organization_fixture(name="Active Org")
    await create_user_org_link(user, org, role=OrgRole.OWNER)

    token = await create_access_token(
        user_id=user.id,
        active_org={"org_id": str(org.id), "role": OrgRole.OWNER},
    )

    response = await async_client.get(
        "/api/v1/org/me/current",
        headers=auth_header(token),
    )

    assert response.status_code == 200
    data = response.json()["data"]

    assert data["user_id"] == str(user.id)
    assert data["email"] == user.email
    assert data["full_name"] == user.full_name
    assert data["org"]["organization_id"] == str(org.id)
    assert data["org"]["organization_name"] == org.name
    assert data["org"]["role"] == OrgRole.OWNER


@pytest.mark.anyio
async def test_get_current_user_context_fails_if_no_active_org(
    async_client: AsyncClient,
    create_test_user,
):
    """
    🚫 Should return 403 if user has no active org context in token.
    """
    user = await create_test_user()

    token = await create_access_token(
        user_id=user.id,
        active_org=None,  # ⛔️ no active org in token
    )

    response = await async_client.get(
        "/api/v1/org/me/current",
        headers=auth_header(token),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Organization context required. Please switch organization."
