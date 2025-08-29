import pytest
from httpx import AsyncClient
from uuid import UUID
from app.schemas.enums import OrgRole
from app.db.models.user_organization import UserOrganization
from app.schemas.organization import OrgMemberResponseNew

PROMOTE_URL = "/api/v1/org/admin/superadmins/{user_org_id}/promote"
DEMOTE_URL = "/api/v1/org/admin/superadmins/{user_org_id}/demote"

# ─────────────────────────────────────────────────────────────
# 🔼 Test: Promote a user to SUPERADMIN
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_promote_user_to_superadmin(
    async_client: AsyncClient,
    create_organization_fixture,
    create_test_user,
    create_user_org_link,
    get_auth_headers
):
    org = await create_organization_fixture(name="PromoOrg")
    actor = await create_test_user(email="actor@org.com")
    target = await create_test_user(email="target@org.com")

    await create_user_org_link(user=actor, organization=org, role=OrgRole.SUPERADMIN, is_active=True)
    user_org = await create_user_org_link(user=target, organization=org, role=OrgRole.INTERN, is_active=True)

    headers = await get_auth_headers(actor, org, OrgRole.SUPERADMIN)

    response = await async_client.post(PROMOTE_URL.format(user_org_id=user_org.id), headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["role"] == OrgRole.SUPERADMIN.value
    assert data["user_id"] == str(target.id)

# ─────────────────────────────────────────────────────────────
# 🛑 Test: Prevent promoting yourself
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_prevent_self_promotion(
    async_client,
    create_organization_fixture,
    create_test_user,
    create_user_org_link,
    get_auth_headers
):
    org = await create_organization_fixture()
    user = await create_test_user()
    user_org = await create_user_org_link(user=user, organization=org, role=OrgRole.SUPERADMIN, is_active=True)

    headers = await get_auth_headers(user, org, OrgRole.SUPERADMIN)
    response = await async_client.post(PROMOTE_URL.format(user_org_id=user_org.id), headers=headers)

    assert response.status_code == 400
    assert "You cannot promote yourself" in response.text

# ─────────────────────────────────────────────────────────────
# 🛑 Test: Prevent promoting an existing SUPERADMIN
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_prevent_promoting_existing_superadmin(
    async_client,
    create_organization_fixture,
    create_test_user,
    create_user_org_link,
    get_auth_headers
):
    org = await create_organization_fixture()
    actor = await create_test_user()
    target = await create_test_user()

    await create_user_org_link(actor, org, OrgRole.SUPERADMIN, is_active=True)
    user_org = await create_user_org_link(target, org, OrgRole.SUPERADMIN, is_active=True)

    headers = await get_auth_headers(actor, org, OrgRole.SUPERADMIN)
    response = await async_client.post(PROMOTE_URL.format(user_org_id=user_org.id), headers=headers)

    assert response.status_code == 400
    assert "already a SUPERADMIN" in response.text

# ─────────────────────────────────────────────────────────────
# ⬇️ Test: Demote a SUPERADMIN successfully
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_demote_superadmin_successfully(
    async_client,
    create_organization_fixture,
    create_test_user,
    create_user_org_link,
    get_auth_headers
):
    org = await create_organization_fixture()
    actor = await create_test_user()
    target = await create_test_user()

    await create_user_org_link(actor, org, OrgRole.SUPERADMIN, is_active=True)
    user_org = await create_user_org_link(target, org, OrgRole.SUPERADMIN, is_active=True)

    headers = await get_auth_headers(actor, org, OrgRole.SUPERADMIN)
    response = await async_client.post(DEMOTE_URL.format(user_org_id=user_org.id), headers=headers)

    assert response.status_code == 200
    assert response.json()["role"] != OrgRole.SUPERADMIN.value

# ─────────────────────────────────────────────────────────────
# 🛑 Test: Prevent self-demotion
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_prevent_self_demotion(
    async_client,
    create_organization_fixture,
    create_test_user,
    create_user_org_link,
    get_auth_headers
):
    org = await create_organization_fixture()
    user = await create_test_user()
    user_org = await create_user_org_link(user, org, OrgRole.SUPERADMIN, is_active=True)

    headers = await get_auth_headers(user, org, OrgRole.SUPERADMIN)
    response = await async_client.post(DEMOTE_URL.format(user_org_id=user_org.id), headers=headers)

    assert response.status_code == 400
    assert "You cannot demote yourself" in response.text

# ─────────────────────────────────────────────────────────────
# 🛑 Test: Prevent demotion by non-superadmin
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_prevent_demotion_by_non_superadmin(
    async_client,
    create_organization_fixture,
    create_test_user,
    create_user_org_link,
    get_auth_headers
):
    org = await create_organization_fixture()
    actor = await create_test_user()
    target = await create_test_user()

    await create_user_org_link(actor, org, OrgRole.MANAGER, is_active=True)
    user_org = await create_user_org_link(target, org, OrgRole.SUPERADMIN, is_active=True)

    headers = await get_auth_headers(actor, org, OrgRole.MANAGER)
    response = await async_client.post(DEMOTE_URL.format(user_org_id=user_org.id), headers=headers)

    assert response.status_code == 403 or response.status_code == 400
    assert "Only a SUPERADMIN can demote" in response.text or "permission" in response.text.lower()

# ─────────────────────────────────────────────────────────────
# 🛑 Test: Prevent demotion of last SUPERADMIN
# ─────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_prevent_last_superadmin_demotion(
    async_client,
    create_organization_fixture,
    create_test_user,
    create_user_org_link,
    get_auth_headers
):
    org = await create_organization_fixture()

    # Create superadmin A
    superadmin = await create_test_user()
    superadmin_org = await create_user_org_link(superadmin, org, OrgRole.SUPERADMIN, is_active=True)

    # Create actor SUPERADMIN B
    actor = await create_test_user()
    actor_org = await create_user_org_link(actor, org, OrgRole.SUPERADMIN, is_active=True)

    # Actor demotes superadmin A
    actor_headers = await get_auth_headers(actor, org, OrgRole.SUPERADMIN)
    response1 = await async_client.post(DEMOTE_URL.format(user_org_id=superadmin_org.id), headers=actor_headers)
    assert response1.status_code == 200

    # Now actor is the only remaining SUPERADMIN
    # They try to demote themselves
    response2 = await async_client.post(DEMOTE_URL.format(user_org_id=actor_org.id), headers=actor_headers)

    assert response2.status_code == 400
    assert response2.json()["detail"] == "You cannot demote yourself."
