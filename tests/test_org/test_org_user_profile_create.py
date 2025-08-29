import pytest
from httpx import AsyncClient
from app.db.models.org_user_profile import OrgUserProfile
from app.schemas.enums import Visibility, OrgRole
from app.schemas.org_user_profile import OrgUserProfileCreate
from app.core.security import create_access_token

@pytest.mark.anyio
async def test_create_profile_success(async_client, org_with_users):
    data = await org_with_users(as_tuple=False)
    org = data.org
    token = data.token

    payload = {
        "full_name": "John Doe",
        "bio": "Engineer",
        "visibility": Visibility.PUBLIC.value,
    }

    response = await async_client.post(
        "/api/v1/org/user/profile",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Org-ID": str(org.id),
        },
        json=payload,
    )

    # ✅ DEBUG PRINT
    print("SUCCESS TEST RESPONSE", response.status_code, response.json())

    assert response.status_code == 201
    assert response.json()["full_name"] == "John Doe"


@pytest.mark.anyio
async def test_create_profile_already_exists(async_client: AsyncClient, db_session, org_with_users):
    data = await org_with_users(as_tuple=False)
    org = data.org
    owner = data.owner
    token = data.token

    # Create profile first
    profile = OrgUserProfile(
        user_id=owner.id,
        organization_id=org.id,
        visibility=Visibility.PRIVATE.value,
        full_name="Existing"
    )
    db_session.add(profile)
    await db_session.commit()

    payload = {
        "full_name": "Should Fail",
        "visibility": Visibility.PUBLIC.value
    }

    response = await async_client.post(
        "/api/v1/org/user/profile",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Org-ID": str(org.id)
        },
        json=payload
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Org user profile already exists"


@pytest.mark.anyio
async def test_create_profile_missing_org_context(async_client: AsyncClient, org_with_users):
    data = await org_with_users(as_tuple=False)
    token = data.token

    payload = {
        "full_name": "No Org Context",
        "visibility": Visibility.PUBLIC.value
    }

    response = await async_client.post(
        "/api/v1/org/user/profile",
        headers={
            "Authorization": f"Bearer {token}"
            # Missing X-Org-ID
        },
        json=payload
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Organization context is missing. Ensure X-Org-ID header is provided if required."


@pytest.mark.anyio
async def test_create_profile_unauthorized(async_client, org_with_users):
    data = await org_with_users(as_tuple=False)
    org = data.org

    payload = {
        "full_name": "No Auth",
        "visibility": Visibility.PUBLIC.value,
    }

    response = await async_client.post(
        "/api/v1/org/user/profile",
        headers={"X-Org-ID": str(org.id)},
        json=payload,
    )

    assert response.status_code in {401, 403, 400}  # Adjust based on dependency order

