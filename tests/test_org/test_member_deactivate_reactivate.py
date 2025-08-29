import pytest
from httpx import AsyncClient
from uuid import uuid4
from app.schemas.enums import OrgRole
from app.core.security import create_access_token
from app.schemas.auth import MessageResponse


@pytest.mark.anyio
async def test_deactivate_user_success(
    async_client: AsyncClient,
    create_test_user,
    create_user_org_link,
    create_organization_fixture,
):
    # ─────── TEST: Deactivate active user ───────
    org = await create_organization_fixture()
    actor = await create_test_user()
    target = await create_test_user()

    await create_user_org_link(user=actor, organization=org, role=OrgRole.ADMIN)
    target_link = await create_user_org_link(user=target, organization=org, role=OrgRole.INTERN)

    token = await create_access_token(
        user_id=str(actor.id),
        active_org={"org_id": str(org.id), "role": OrgRole.ADMIN.value}
    )

    response = await async_client.put(
        f"/api/v1/org/{target_link.id}/deactivate",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json() == MessageResponse(
        message="User organization account deactivated successfully."
    ).dict()


@pytest.mark.anyio
async def test_deactivate_user_already_deactivated(
    async_client,
    create_test_user,
    create_user_org_link,
    create_organization_fixture,
):
    # ─────── TEST: Deactivate already deactivated user ───────
    org = await create_organization_fixture()
    actor = await create_test_user()
    target = await create_test_user()

    await create_user_org_link(user=actor, organization=org, role=OrgRole.ADMIN)
    target_link = await create_user_org_link(
        user=target, organization=org, role=OrgRole.INTERN, is_active=False
    )

    token = await create_access_token(
        user_id=str(actor.id),
        active_org={"org_id": str(org.id), "role": OrgRole.ADMIN.value}
    )

    response = await async_client.put(
        f"/api/v1/org/{target_link.id}/deactivate",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 400
    assert "already deactivated" in response.json()["detail"].lower()


@pytest.mark.anyio
async def test_deactivate_owner_fails(
    async_client,
    create_test_user,
    create_user_org_link,
    create_organization_fixture,
):
    # ─────── TEST: Cannot deactivate OWNER ───────
    org = await create_organization_fixture()
    actor = await create_test_user()
    owner = await create_test_user()

    await create_user_org_link(user=actor, organization=org, role=OrgRole.ADMIN)
    owner_link = await create_user_org_link(user=owner, organization=org, role=OrgRole.OWNER)

    token = await create_access_token(
        user_id=str(actor.id),
        active_org={"org_id": str(org.id), "role": OrgRole.ADMIN.value}
    )

    response = await async_client.put(
        f"/api/v1/org/{owner_link.id}/deactivate",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert "cannot deactivate organization owner" in response.json()["detail"].lower()


@pytest.mark.anyio
async def test_deactivate_superadmin_by_non_superadmin_fails(
    async_client,
    create_test_user,
    create_user_org_link,
    create_organization_fixture,
):
    # ─────── TEST: Cannot deactivate SUPERADMIN if actor is not SUPERADMIN ───────
    org = await create_organization_fixture()
    actor = await create_test_user()
    superadmin = await create_test_user()

    await create_user_org_link(user=actor, organization=org, role=OrgRole.ADMIN)
    superadmin_link = await create_user_org_link(
        user=superadmin, organization=org, role=OrgRole.SUPERADMIN
    )

    token = await create_access_token(
        user_id=str(actor.id),
        active_org={"org_id": str(org.id), "role": OrgRole.ADMIN.value}
    )

    response = await async_client.put(
        f"/api/v1/org/{superadmin_link.id}/deactivate",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert "superadmin can modify or remove" in response.json()["detail"].lower(), \
        f"Unexpected detail message: {response.json()['detail']}"



@pytest.mark.anyio
async def test_deactivate_user_not_found(
    async_client,
    create_test_user,
    create_user_org_link,
    create_organization_fixture,
):
    # ─────── TEST: Deactivation fails for nonexistent user_org_id ───────
    org = await create_organization_fixture()
    actor = await create_test_user()

    await create_user_org_link(user=actor, organization=org, role=OrgRole.ADMIN)

    token = await create_access_token(
        user_id=str(actor.id),
        active_org={"org_id": str(org.id), "role": OrgRole.ADMIN.value}
    )

    fake_user_org_id = uuid4()

    response = await async_client.put(
        f"/api/v1/org/{fake_user_org_id}/deactivate",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()



# ─────── REACTIVATE TESTS ───────

@pytest.mark.anyio
async def test_reactivate_user_success(async_client: AsyncClient, create_test_user, create_user_org_link, create_organization_fixture):
    org = await create_organization_fixture()
    actor = await create_test_user()
    target = await create_test_user()

    await create_user_org_link(actor, org, role=OrgRole.ADMIN)
    target_link = await create_user_org_link(target, org, role=OrgRole.INTERN, is_active=False)

    token = await create_access_token(user_id=str(actor.id), active_org={"org_id": str(org.id), "role": OrgRole.ADMIN.value})

    response = await async_client.put(
        f"/api/v1/org/{target_link.id}/reactivate",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json() == MessageResponse(message="User organization account reactivated successfully.").dict()


@pytest.mark.anyio
async def test_reactivate_already_active_fails(async_client, create_test_user, create_user_org_link, create_organization_fixture):
    org = await create_organization_fixture()
    actor = await create_test_user()
    target = await create_test_user()

    await create_user_org_link(actor, org, role=OrgRole.ADMIN)
    target_link = await create_user_org_link(target, org, role=OrgRole.INTERN, is_active=True)

    token = await create_access_token(user_id=str(actor.id), active_org={"org_id": str(org.id), "role": OrgRole.ADMIN.value})

    response = await async_client.put(
        f"/api/v1/org/{target_link.id}/reactivate",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 400
    assert "already active" in response.json()["detail"].lower()


@pytest.mark.anyio
async def test_reactivate_superadmin_by_non_superadmin_fails(async_client, create_test_user, create_user_org_link, create_organization_fixture):
    org = await create_organization_fixture()
    actor = await create_test_user()
    superadmin = await create_test_user()

    await create_user_org_link(actor, org, role=OrgRole.ADMIN)
    superadmin_link = await create_user_org_link(superadmin, org, role=OrgRole.SUPERADMIN, is_active=False)

    token = await create_access_token(user_id=str(actor.id), active_org={"org_id": str(org.id), "role": OrgRole.ADMIN.value})

    response = await async_client.put(
        f"/api/v1/org/{superadmin_link.id}/reactivate",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert "only a superadmin can modify or restore another superadmin" in response.json()["detail"].lower()



@pytest.mark.anyio
async def test_reactivate_user_not_found(async_client, create_test_user, create_user_org_link, create_organization_fixture):
    org = await create_organization_fixture()
    actor = await create_test_user()

    await create_user_org_link(actor, org, role=OrgRole.ADMIN)

    fake_user_org_id = uuid4()
    token = await create_access_token(user_id=str(actor.id), active_org={"org_id": str(org.id), "role": OrgRole.ADMIN.value})

    response = await async_client.put(
        f"/api/v1/org/{fake_user_org_id}/reactivate",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()