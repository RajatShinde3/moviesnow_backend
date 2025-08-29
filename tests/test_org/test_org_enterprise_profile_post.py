import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas.enums import OrgRole


@pytest.fixture(autouse=True)
async def clean_enterprise_profiles(db_session: AsyncSession):
    from sqlalchemy import text
    yield
    await db_session.execute(text("DELETE FROM enterprise_profiles"))
    await db_session.commit()

@pytest.mark.anyio
async def test_create_enterprise_profile_success(
    async_client: AsyncClient,
    org_with_users,
):
    ctx = await org_with_users(as_tuple=False)  # Use namedtuple return

    payload = {
        "org_name": "Test Org",
        "contact_email": "contact@testorg.com",
        "contact_phone": "+1234567890",
        "overview": "We are testing things.",
    }

    response = await async_client.post(
        "/api/v1/org/enterprise/profile",
        json=payload,
        headers={"Authorization": f"Bearer {ctx.token}"},
    )

    assert response.status_code == 201
    data = response.json()

    assert data["org_name"] == payload["org_name"]
    assert data["contact_email"] == payload["contact_email"]
    assert data["contact_phone"] == payload["contact_phone"]
    assert data["organization_id"] == str(getattr(ctx.org, "organization_id", ctx.org.id))

    

@pytest.mark.anyio
async def test_create_enterprise_profile_forbidden_for_member(
    async_client: AsyncClient,
    org_with_users,
):
    ctx = await org_with_users(member_role=OrgRole.INTERN, as_tuple=False, use_member_token=True)

    payload = {
        "org_name": "Intern Org",
        "contact_email": "intern@testorg.com",
        "contact_phone": "+19876543210",
        "overview": "Intern trying to create a profile.",
    }

    response = await async_client.post(
        "/api/v1/org/enterprise/profile",
        json=payload,
        headers={"Authorization": f"Bearer {ctx.token}"},  # now intern token
    )

    assert response.status_code == 403


# 🚫 Test: Missing required field - contact_phone
@pytest.mark.anyio
async def test_create_enterprise_profile_missing_required_field(
    async_client: AsyncClient,
    org_with_users,
):
    owner_user, org, token = await org_with_users()

    payload = {
        "org_name": "Incomplete Org",
        "contact_email": "incomplete@example.com"
        # ❌ Missing contact_phone
    }

    response = await async_client.post(
        "/api/v1/org/enterprise/profile",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 422
    assert "contact_phone" in str(response.json()).lower()


@pytest.mark.anyio
async def test_create_enterprise_profile_duplicate_conflict(
    async_client: AsyncClient,
    org_with_users,
):
    owner_user, _, token = await org_with_users()

    payload = {
        "org_name": "Duplicate Org",
        "contact_email": "duplicate@org.com",
        "contact_phone": "+1111111111",
        "overview": "Duplicate entry test",
    }

    # ✅ First attempt
    res1 = await async_client.post(
        "/api/v1/org/enterprise/profile",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res1.status_code == 201

    # ❌ Second attempt
    res2 = await async_client.post(
        "/api/v1/org/enterprise/profile",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res2.status_code == 409  # this will pass once fixed




# 🚫 Test: Empty payload
@pytest.mark.anyio
async def test_create_enterprise_profile_empty_payload(
    async_client: AsyncClient,
    org_with_users,
):
    owner_user, org, token = await org_with_users()

    response = await async_client.post(
        "/api/v1/org/enterprise/profile",
        json={},  # ❌ No data
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 422
    assert "field required" in str(response.json()).lower()



