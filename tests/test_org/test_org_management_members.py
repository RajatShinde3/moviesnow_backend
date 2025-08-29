import pytest
from httpx import AsyncClient
from uuid import uuid4
from app.core.security import create_access_token
from app.schemas.enums import OrgRole
from app.schemas.auth import MessageResponse


# ──────────────────────────────────────────────────────────────
# ✅ Tests: Remove Member from Organization
# ──────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_remove_org_member_success(async_client: AsyncClient, org_with_users, mocker):
    """
    ✅ Should successfully remove a non-OWNER member from the org.
    """
    owner, member, token = await org_with_users(owner_role=OrgRole.OWNER, member_role=OrgRole.ADMIN)

    # Mock audit logging
    mocker.patch("app.api.v1.routes.orgs.org_management.log_org_event")

    response = await async_client.post(
        "/api/v1/org/remove-member",
        headers={"Authorization": f"Bearer {token}"},
        json={"user_id": str(member.id)},
    )

    assert response.status_code == 200
    assert response.json() == MessageResponse(message="Member removed successfully.").dict()


@pytest.mark.anyio
async def test_remove_org_member_self_removal_fails(async_client: AsyncClient, org_with_users):
    """
    ❌ Should return 400 if user tries to remove themselves.
    """
    owner, _, token = await org_with_users(owner_role=OrgRole.OWNER, member_role=OrgRole.ADMIN)

    response = await async_client.post(
        "/api/v1/org/remove-member",
        headers={"Authorization": f"Bearer {token}"},
        json={"user_id": str(owner.id)},
    )

    assert response.status_code == 400
    assert "cannot remove yourself" in response.json()["detail"].lower()


@pytest.mark.anyio
async def test_remove_org_member_not_found(async_client: AsyncClient, org_with_users):
    """
    ❌ Should return 404 if the member is not found in the organization.
    """
    _, _, token = await org_with_users(owner_role=OrgRole.OWNER, member_role=OrgRole.ADMIN)

    response = await async_client.post(
        "/api/v1/org/remove-member",
        headers={"Authorization": f"Bearer {token}"},
        json={"user_id": str(uuid4())},  # Random user ID
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.anyio
async def test_remove_only_owner_fails(async_client, create_test_user, create_organization_fixture, create_user_org_link):
    """
    ❌ Should not allow removing the only OWNER of the org, even by another user.
    """
    org = await create_organization_fixture()

    # OWNER to be removed
    owner = await create_test_user()
    await create_user_org_link(user=owner, organization=org, role=OrgRole.OWNER)

    # ADMIN trying to remove the only OWNER
    actor = await create_test_user()
    await create_user_org_link(user=actor, organization=org, role=OrgRole.ADMIN)

    token = await create_access_token(
        user_id=str(actor.id),
        active_org={"org_id": str(org.id), "role": OrgRole.ADMIN.value},
    )

    response = await async_client.post(
        "/api/v1/org/remove-member",
        headers={"Authorization": f"Bearer {token}"},
        json={"user_id": str(owner.id)},
    )

    assert response.status_code == 400
    assert "only owner" in response.json()["detail"].lower()



# ──────────────────────────────────────────────────────────────
# ✅ Tests: Leave Organization (Self-deactivation)
# ──────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_leave_org_success(async_client: AsyncClient, user_with_org, mocker):
    """
    ✅ A non-OWNER user (e.g. ADMIN) should be able to leave the org successfully.
    """
    user, token = await user_with_org(role=OrgRole.ADMIN)

    # 👻 Mock the audit log to avoid DB logging noise
    mocker.patch("app.api.v1.routes.orgs.org_management.log_org_event")

    response = await async_client.put(
        "/api/v1/org/leave",
        headers={"Authorization": f"Bearer {token}"},
    )
    print("Response:", response.status_code, response.text)

    assert response.status_code == 200
    assert response.json()["message"] == "You have successfully left the organization."


@pytest.mark.anyio
async def test_leave_org_as_only_owner_fails(async_client: AsyncClient, user_with_org):
    """
    ❌ The only OWNER in the org should NOT be able to leave.
    """
    user, token = await user_with_org(role=OrgRole.OWNER, only_user=True)

    response = await async_client.put(
        "/api/v1/org/leave",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 400
    assert "only owner" in response.json()["detail"].lower()


@pytest.mark.anyio
async def test_leave_org_multiple_owners_allowed(
    async_client: AsyncClient,
    create_test_user,
    create_user_org_link,
    create_organization_fixture,
):
    """
    ✅ If there are multiple OWNERs, one of them should be able to leave.
    """
    org = await create_organization_fixture()

    # Both owners explicitly linked to the same org
    owner1 = await create_test_user()
    owner2 = await create_test_user()

    await create_user_org_link(user=owner1, organization=org, role=OrgRole.OWNER)
    await create_user_org_link(user=owner2, organization=org, role=OrgRole.OWNER)

    token = await create_access_token(
        user_id=str(owner1.id),
        active_org={"org_id": str(org.id), "role": OrgRole.OWNER.value}
    )

    response = await async_client.put(
        "/api/v1/org/leave",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "You have successfully left the organization."
