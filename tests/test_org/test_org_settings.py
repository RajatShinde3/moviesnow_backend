import pytest
from httpx import AsyncClient
from uuid import UUID

from app.schemas.enums import OrgRole
from app.core.security import create_access_token


# ───────────────────────────────────────────────
# 🔐 Utility: Create Authorization Header
# ───────────────────────────────────────────────

def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ───────────────────────────────────────────────
# 📄 GET /api/v1/org/settings/me – View Org Settings
# ───────────────────────────────────────────────

@pytest.mark.anyio
async def test_get_my_org_settings_success(
    async_client: AsyncClient,
    create_test_user,
    create_organization_fixture,
    create_user_org_link,
):
    """✅ Should return current org settings for user with VIEW_SETTINGS permission."""
    user = await create_test_user()
    org = await create_organization_fixture()
    await create_user_org_link(user, org, role=OrgRole.ADMIN)

    token = await create_access_token(
        user_id=user.id,
        mfa_authenticated=True,
        active_org={"org_id": str(org.id), "role": OrgRole.ADMIN},
    )

    response = await async_client.get("/api/v1/org/settings/me", headers=auth_header(token))
    assert response.status_code == 200

    data = response.json()
    assert UUID(data["id"]) == org.id
    assert data["name"] == org.name


@pytest.mark.anyio
async def test_get_my_org_settings_unauthenticated(async_client: AsyncClient):
    """❌ Should reject unauthenticated user."""
    response = await async_client.get("/api/v1/org/settings/me")
    assert response.status_code == 401


@pytest.mark.anyio
async def test_get_my_org_settings_mfa_missing(
    async_client: AsyncClient,
    create_test_user,
    create_organization_fixture,
    create_user_org_link,
):
    """❌ Should reject user without MFA."""
    user = await create_test_user()
    org = await create_organization_fixture()
    await create_user_org_link(user, org, role=OrgRole.ADMIN)

    token = await create_access_token(
        user_id=user.id,
        mfa_authenticated=False,  # 👈 MFA missing
        active_org={"org_id": str(org.id), "role": OrgRole.ADMIN},
    )

    response = await async_client.get("/api/v1/org/settings/me", headers=auth_header(token))
    assert response.status_code == 403
    assert "MFA" in response.text or "permission" in response.text


@pytest.mark.anyio
async def test_get_my_org_settings_forbidden(
    async_client: AsyncClient,
    create_test_user,
    create_organization_fixture,
    create_user_org_link,
):
    """❌ Should reject user without VIEW_SETTINGS permission (e.g., INTERN)."""
    user = await create_test_user()
    org = await create_organization_fixture()
    await create_user_org_link(user, org, role=OrgRole.INTERN)

    token = await create_access_token(
        user_id=user.id,
        mfa_authenticated=True,
        active_org={"org_id": str(org.id), "role": OrgRole.INTERN},
    )

    response = await async_client.get("/api/v1/org/settings/me", headers=auth_header(token))
    assert response.status_code == 403


# ───────────────────────────────────────────────────────
# ✏️ PUT /api/v1/org/settings/update – Update Org Settings
# ───────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_update_org_settings_success(
    async_client: AsyncClient,
    create_test_user,
    create_organization_fixture,
    create_user_org_link,
):
    """✅ Should update settings if user is OWNER and MFA is done."""
    user = await create_test_user()
    org = await create_organization_fixture()
    await create_user_org_link(user, org, role=OrgRole.OWNER)

    token = await create_access_token(
        user_id=user.id,
        mfa_authenticated=True,
        active_org={"org_id": str(org.id), "role": OrgRole.OWNER},
    )

    payload = {
        "name": "Updated Org Name",
        "contact_email": "contact@example.org",
    }

    response = await async_client.put(
        "/api/v1/org/settings/update",
        headers=auth_header(token),
        json=payload,
    )
    print("Response JSON:", response.json())

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == payload["name"]
    assert data["contact_email"] == payload["contact_email"]


@pytest.mark.anyio
async def test_update_org_settings_non_owner_forbidden(
    async_client: AsyncClient,
    create_test_user,
    create_organization_fixture,
    create_user_org_link,
):
    """❌ Should reject update if user is not OWNER."""
    user = await create_test_user()
    org = await create_organization_fixture()
    await create_user_org_link(user, org, role=OrgRole.MANAGER)

    token = await create_access_token(
        user_id=user.id,
        mfa_authenticated=True,
        active_org={"org_id": str(org.id), "role": OrgRole.MANAGER},
    )

    response = await async_client.put(
        "/api/v1/org/settings/update",
        headers=auth_header(token),
        json={"name": "Unauthorized Update"},
    )

    assert response.status_code == 403


@pytest.mark.anyio
async def test_update_org_settings_no_token(async_client: AsyncClient):
    """❌ Should reject anonymous update request."""
    response = await async_client.put(
        "/api/v1/org/settings/update",
        json={"name": "Anonymous Org"},
    )
    assert response.status_code == 401


@pytest.mark.anyio
async def test_update_org_settings_mfa_missing(
    async_client: AsyncClient,
    create_test_user,
    create_organization_fixture,
    create_user_org_link,
):
    """❌ Should reject update without MFA."""
    user = await create_test_user()
    org = await create_organization_fixture()
    await create_user_org_link(user, org, role=OrgRole.OWNER)

    token = await create_access_token(
        user_id=user.id,
        mfa_authenticated=False,  # 👈 No MFA
        active_org={"org_id": str(org.id), "role": OrgRole.OWNER},
    )

    response = await async_client.put(
        "/api/v1/org/settings/update",
        headers=auth_header(token),
        json={"name": "MFA Missing Org"},
    )

    assert response.status_code == 403


@pytest.mark.anyio
async def test_update_org_settings_invalid_email(
    async_client: AsyncClient,
    create_test_user,
    create_organization_fixture,
    create_user_org_link,
):
    """❌ Should fail validation for invalid contact email format."""
    user = await create_test_user()
    org = await create_organization_fixture()
    await create_user_org_link(user, org, role=OrgRole.OWNER)

    token = await create_access_token(
        user_id=user.id,
        mfa_authenticated=True,
        active_org={"org_id": str(org.id), "role": OrgRole.OWNER},
    )

    response = await async_client.put(
        "/api/v1/org/settings/update",
        headers=auth_header(token),
        json={"contact_email": "not-an-email"},
    )

    assert response.status_code == 422
