import pytest
from httpx import AsyncClient
from uuid import uuid4
from app.db.models import Organization, User, UserOrganization
from app.core.security import create_access_token
from app.schemas.enums import OrgRole
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

@pytest.mark.anyio
async def test_assign_superadmin_success(
    async_client: AsyncClient,
    create_organization_fixture,
    create_user_org_link,
    create_test_user,
):
    # ✅ Arrange
    org = await create_organization_fixture(name="SomeOrg")
    superadmin = await create_test_user(email="superadmin@example.com")
    target_user = await create_test_user(email="member1@example.com")

    await create_user_org_link(user=superadmin, organization=org, role=OrgRole.SUPERADMIN, is_active=True)
    user_org = await create_user_org_link(user=target_user, organization=org, role=OrgRole.INTERN, is_active=True)

    token = await create_access_token(
        user_id=superadmin.id,
        active_org={"org_id": str(org.id), "role": OrgRole.SUPERADMIN.value}
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Org-Id": str(org.id),
    }

    # ✅ Act
    url = f"/api/v1/org/admin/{user_org.id}/assign-superadmin"
    response = await async_client.put(url, headers=headers)

    # ✅ Assert
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == OrgRole.SUPERADMIN.value
    assert data["user"]["email"] == "member1@example.com"


@pytest.mark.anyio
async def test_assign_superadmin_forbidden_if_not_superadmin(
    async_client: AsyncClient,
    create_organization_fixture,
    create_test_user,
    create_user_org_link,
):
    # ✅ Arrange
    org = await create_organization_fixture(name="OrgX")
    normal_user = await create_test_user(email="normal@example.com")
    target_user = await create_test_user(email="member2@example.com")

    await create_user_org_link(user=normal_user, organization=org, role=OrgRole.INTERN, is_active=True)
    user_org = await create_user_org_link(user=target_user, organization=org, role=OrgRole.INTERN, is_active=True)

    token = await create_access_token(
        user_id=normal_user.id,
        active_org={"org_id": str(org.id), "role": OrgRole.INTERN.value}
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Org-Id": str(org.id),
    }

    # ✅ Act
    url = f"/api/v1/org/admin/{user_org.id}/assign-superadmin"
    response = await async_client.put(url, headers=headers)

    # ✅ Assert
    assert response.status_code == 403


@pytest.mark.anyio
async def test_assign_superadmin_user_not_found(
    async_client: AsyncClient,
    create_organization_fixture,
    create_test_user,
    create_user_org_link,
):
    # ✅ Arrange
    org = await create_organization_fixture(name="OrgY")
    superadmin = await create_test_user(email="superadmin2@example.com")

    await create_user_org_link(user=superadmin, organization=org, role=OrgRole.SUPERADMIN, is_active=True)

    token = await create_access_token(
        user_id=superadmin.id,
        active_org={"org_id": str(org.id), "role": OrgRole.SUPERADMIN.value}
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Org-Id": str(org.id),
    }

    # ✅ Act
    invalid_user_org_id = uuid4()
    url = f"/api/v1/org/admin/{invalid_user_org_id}/assign-superadmin"
    response = await async_client.put(url, headers=headers)

    # ✅ Assert
    assert response.status_code == 404

@pytest.mark.anyio
async def test_list_superadmins(
    async_client: AsyncClient,
    db_session: AsyncSession,
    create_test_user,
    create_organization_fixture,
    create_user_org_link,
):
    """
    ✅ Integration test: GET /api/v1/org/admin/superadmins
    Validates that only users with `SUPERADMIN` role are listed for a given org.
    """

    # ────────────────────────
    # Arrange
    # ────────────────────────
    org: Organization = await create_organization_fixture(name="TestOrg")

    # Create superadmin and member users
    superadmin_user: User = await create_test_user(email="superadmin@example.com", full_name="Super Admin")
    member_user: User = await create_test_user(email="member@example.com", full_name="Regular User")

    await create_user_org_link(user=superadmin_user, organization=org, role=OrgRole.SUPERADMIN, is_active=True)
    await create_user_org_link(user=member_user, organization=org, role=OrgRole.INTERN, is_active=True)

    # Generate token for the superadmin
    token = await create_access_token(
        user_id=str(superadmin_user.id),
        active_org={"org_id": str(org.id), "role": OrgRole.SUPERADMIN.value},
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Org-Id": str(org.id),
    }

    # Optional debug check (ensure link exists)
    result = await db_session.execute(
        select(UserOrganization).where(
            UserOrganization.user_id == superadmin_user.id,
            UserOrganization.organization_id == org.id
        )
    )
    assert result.scalar_one_or_none() is not None, "UserOrganization link for superadmin not found."

    # ────────────────────────
    # Act
    # ────────────────────────
    response = await async_client.get("/api/v1/org/admin/superadmins", headers=headers)

    # ────────────────────────
    # Assert
    # ────────────────────────
    assert response.status_code == 200, f"Unexpected: {response.status_code} - {response.text}"
    data = response.json()

    assert isinstance(data, list)
    assert any(user["email"] == "superadmin@example.com" for user in data), "Superadmin user not in response."