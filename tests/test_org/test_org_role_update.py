import pytest
from app.schemas.enums import OrgRole
from app.core.security import create_access_token
from httpx import AsyncClient
from uuid import UUID


@pytest.mark.anyio
async def test_update_user_role_success(async_client, create_test_user, create_user_org_link, create_organization_fixture):
    org = await create_organization_fixture()
    actor = await create_test_user()
    target = await create_test_user()

    # Actor is ADMIN
    await create_user_org_link(actor, org, role=OrgRole.ADMIN)
    target_link = await create_user_org_link(target, org, role=OrgRole.INTERN)

    token = await create_access_token(
        user_id=str(actor.id),
        active_org={"org_id": str(org.id), "role": OrgRole.ADMIN.value}
    )

    payload = {"role": OrgRole.INTERN.value}

    response = await async_client.put(
        f"/api/v1/org/member/{target.id}/role",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "User already has the requested role"


@pytest.mark.anyio
async def test_update_user_role_user_not_in_org(async_client, create_test_user, create_user_org_link, create_organization_fixture):
    org = await create_organization_fixture()
    actor = await create_test_user()
    stranger = await create_test_user()  # Not added to org

    await create_user_org_link(actor, org, role=OrgRole.ADMIN)

    token = await create_access_token(
        user_id=str(actor.id),
        active_org={"org_id": str(org.id), "role": OrgRole.ADMIN.value}
    )

    response = await async_client.put(
        f"/api/v1/org/member/{stranger.id}/role",
        json={"role": OrgRole.INTERN.value},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404
    assert "not a member of this organization" in response.json()["detail"].lower()



@pytest.mark.anyio
async def test_update_user_role_self_modification_fails(async_client, create_test_user, create_user_org_link, create_organization_fixture):
    org = await create_organization_fixture()
    actor = await create_test_user()

    await create_user_org_link(actor, org, role=OrgRole.ADMIN)

    token = await create_access_token(
        user_id=str(actor.id),
        active_org={"org_id": str(org.id), "role": OrgRole.ADMIN.value}
    )

    response = await async_client.put(
        f"/api/v1/org/member/{actor.id}/role",
        json={"role": OrgRole.INTERN.value},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 400
    assert "cannot change your own role" in response.json()["detail"].lower()


@pytest.mark.anyio
async def test_update_user_role_assign_superadmin_not_allowed(async_client, create_test_user, create_user_org_link, create_organization_fixture):
    org = await create_organization_fixture()
    actor = await create_test_user()
    target = await create_test_user()

    await create_user_org_link(actor, org, role=OrgRole.ADMIN)
    await create_user_org_link(target, org, role=OrgRole.INTERN)

    token = await create_access_token(
        user_id=str(actor.id),
        active_org={"org_id": str(org.id), "role": OrgRole.ADMIN.value}
    )

    response = await async_client.put(
        f"/api/v1/org/member/{target.id}/role",
        json={"role": OrgRole.SUPERADMIN.value},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert "only superadmin can assign or modify superadmin" in response.json()["detail"].lower()


@pytest.mark.anyio
async def test_update_user_role_already_same(async_client, create_test_user, create_user_org_link, create_organization_fixture):
    org = await create_organization_fixture()
    actor = await create_test_user()
    target = await create_test_user()

    await create_user_org_link(actor, org, role=OrgRole.ADMIN)
    await create_user_org_link(target, org, role=OrgRole.INTERN)

    token = await create_access_token(
        user_id=str(actor.id),
        active_org={"org_id": str(org.id), "role": OrgRole.ADMIN.value}
    )

    response = await async_client.put(
        f"/api/v1/org/member/{target.id}/role",
        json={"role": OrgRole.INTERN.value},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "User already has the requested role"


@pytest.mark.anyio
async def test_update_user_role_forbidden_without_admin_or_owner(async_client, create_test_user, create_user_org_link, create_organization_fixture):
    org = await create_organization_fixture()
    actor = await create_test_user()
    target = await create_test_user()

    await create_user_org_link(actor, org, role=OrgRole.INTERN)
    await create_user_org_link(target, org, role=OrgRole.INTERN)

    token = await create_access_token(
        user_id=str(actor.id),
        active_org={"org_id": str(org.id), "role": OrgRole.INTERN.value}
    )

    response = await async_client.put(
        f"/api/v1/org/member/{target.id}/role",
        json={"role": OrgRole.ADMIN.value},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert "access requires role" in response.json()["detail"].lower()



@pytest.mark.anyio
async def test_get_user_organizations_success(
    async_client: AsyncClient,
    create_test_user,
    create_organization_fixture,
    create_user_org_link,
):
    user = await create_test_user()
    org1 = await create_organization_fixture()
    org2 = await create_organization_fixture()

    await create_user_org_link(user, org1, role=OrgRole.ADMIN)
    await create_user_org_link(user, org2, role=OrgRole.INTERN)

    # ✅ Include MFA flag and active_org info
    token = await create_access_token(
        user_id=user.id,
        mfa_authenticated=True,
        active_org={"org_id": str(org1.id), "role": OrgRole.ADMIN},
    )

    response = await async_client.get(
        "/api/v1/org/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, dict)
    assert data["org_id"] == str(org1.id)
    assert data["role"] == "ADMIN"

@pytest.mark.anyio
async def test_get_user_organizations_empty_list(
    async_client: AsyncClient,
    create_test_user
):
    user = await create_test_user()

    # No organization assigned
    token = await create_access_token(user_id=user.id, mfa_authenticated=True)

    response = await async_client.get(
        "/api/v1/org/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Organization context required. Please switch organization."



@pytest.mark.anyio
async def test_get_user_organizations_unauthenticated(async_client: AsyncClient):
    response = await async_client.get("/api/v1/org/me")
    assert response.status_code == 403
    assert response.json()["detail"] == "Missing or invalid Authorization header"


@pytest.mark.anyio
async def test_get_user_organizations_mfa_missing(
    async_client: AsyncClient,
    create_test_user,
    create_organization_fixture,
    create_user_org_link,
):
    user = await create_test_user()
    org = await create_organization_fixture()

    # Link user to org so org context exists
    await create_user_org_link(user, org, role=OrgRole.ADMIN)

    # ✅ Token with active_org but no MFA
    token = await create_access_token(
        user_id=user.id,
        mfa_authenticated=False,  # or omit this arg
        active_org={"org_id": str(org.id), "role": OrgRole.ADMIN},
    )

    response = await async_client.get(
        "/api/v1/org/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["org_id"] == str(org.id)
    assert data["role"] == OrgRole.ADMIN
