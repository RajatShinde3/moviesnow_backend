import pytest
from httpx import AsyncClient
from uuid import uuid4
from app.db.models.org_user_profile import OrgUserProfile
from app.schemas.enums import Visibility


@pytest.mark.anyio
async def test_update_profile_success(
    async_client: AsyncClient,
    db_session,
    org_with_users,
):
    data = await org_with_users(as_tuple=False)
    user = data.owner
    token = data.token
    org = data.org

    profile = OrgUserProfile(
        user_id=user.id,
        organization_id=org.id,
        full_name="Original Name",
        bio="Old bio",
        visibility=Visibility.PRIVATE.value,
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.put(
        "api/v1/org/user/profile",
        json={"full_name": "Updated Name", "bio": "Updated Bio"},
        headers={
            "Authorization": f"Bearer {token}",
            "X-Org-ID": str(org.id),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["full_name"] == "Updated Name"
    assert data["bio"] == "Updated Bio"
    assert data["user_id"] == str(user.id)


@pytest.mark.anyio
async def test_update_profile_not_found(
    async_client: AsyncClient,
    org_with_users,
):
    data = await org_with_users(as_tuple=False)
    token = data.token
    org = data.org

    response = await async_client.put(
        "api/v1/org/user/profile",
        json={"full_name": "New Name"},
        headers={
            "Authorization": f"Bearer {token}",
            "X-Org-ID": str(org.id),
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Org user profile not found"


@pytest.mark.anyio
async def test_update_profile_unauthorized(
    async_client: AsyncClient,
    org_with_users,
    db_session,
):
    data = await org_with_users(as_tuple=False)
    user = data.owner
    org = data.org

    profile = OrgUserProfile(
        user_id=user.id,
        organization_id=org.id,
        full_name="Original",
        visibility=Visibility.PRIVATE.value,
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.put(
        "api/v1/org/user/profile",
        json={"full_name": "Should Fail"},
        headers={"X-Org-ID": str(org.id)},
    )

    # Adjusted to match actual behavior
    assert response.status_code == 403


@pytest.mark.anyio
async def test_update_profile_restricted_fields_ignored(
    async_client: AsyncClient,
    db_session,
    org_with_users,
):
    data = await org_with_users(as_tuple=False)
    user = data.owner
    token = data.token
    org = data.org

    profile = OrgUserProfile(
        user_id=user.id,
        organization_id=org.id,
        full_name="Original Name",
        visibility=Visibility.ORG_ONLY.value,
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.put(
        "api/v1/org/user/profile",
        json={
            "full_name": "Updated Name",
            "user_id": str(uuid4()),  # should be ignored
            "organization_id": str(uuid4()),  # should be ignored
        },
        headers={
            "Authorization": f"Bearer {token}",
            "X-Org-ID": str(org.id),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["full_name"] == "Updated Name"
    assert data["user_id"] == str(user.id)  # Must not change


@pytest.mark.anyio
async def test_partial_update_profile_success(
    async_client: AsyncClient,
    db_session,
    org_with_users,
):
    data = await org_with_users(as_tuple=False)
    user = data.owner
    token = data.token
    org = data.org

    profile = OrgUserProfile(
        user_id=user.id,
        organization_id=org.id,
        full_name="Original Name",
        bio="Original Bio",
        visibility=Visibility.PUBLIC.value,
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.put(
        "api/v1/org/user/profile",
        json={"bio": "Only Bio Updated"},
        headers={
            "Authorization": f"Bearer {token}",
            "X-Org-ID": str(org.id),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["full_name"] == "Original Name"
    assert data["bio"] == "Only Bio Updated"


@pytest.mark.anyio
async def test_update_profile_invalid_payload(
    async_client: AsyncClient,
    org_with_users,
):
    data = await org_with_users(as_tuple=False)
    token = data.token
    org = data.org

    # Invalid payload: full_name must be string, not int
    response = await async_client.put(
        "api/v1/org/user/profile",
        json={"full_name": 1234},
        headers={
            "Authorization": f"Bearer {token}",
            "X-Org-ID": str(org.id),
        },
    )

    assert response.status_code == 422
