import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import User, Organization, UserOrganization
from app.schemas.enums import OrgRole
from sqlalchemy import select
from app.schemas.organization import OrgMemberSearchRequest
from unittest.mock import patch
import uuid

SEARCH_URL = "api/v1/org/member/search"
LIST_URL = "api/v1/org/member/"


@pytest.mark.anyio
async def test_search_members_basic(async_client: AsyncClient, user_with_org):
    user, token = await user_with_org(role=OrgRole.ADMIN)
    print("🧪 Created user:", user.email, "| ID:", user.id)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {"query": user.email[:5]}
    print("\n🔍 Payload:", payload)

    response = await async_client.post(SEARCH_URL, json=payload, headers=headers)
    print("📬 Status Code:", response.status_code)
    print("📦 Response JSON:", response.json())

    assert response.status_code == 200
    data = response.json()
    assert any(user.email in u["email"] for u in data)


@pytest.mark.anyio
async def test_search_members_by_role(async_client: AsyncClient, user_with_org):
    user, token = await user_with_org(role=OrgRole.ADMIN)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {"role": OrgRole.ADMIN.value}
    print("\n🔍 Payload:", payload)

    response = await async_client.post(SEARCH_URL, json=payload, headers=headers)
    print("📬 Status Code:", response.status_code)
    print("📦 Response JSON:", response.json())

    assert response.status_code == 200
    data = response.json()
    assert all(u["role"] == OrgRole.ADMIN.value for u in data)


@pytest.mark.anyio
async def test_search_excludes_inactive_by_default(
    async_client: AsyncClient,
    user_with_org,
    db_session: AsyncSession,
    create_test_user,
    create_user_org_link,
):
    user, token = await user_with_org(role=OrgRole.ADMIN)
    headers = {"Authorization": f"Bearer {token}"}

    extra_user = await create_test_user()

    org_id = (
        await db_session.execute(
            select(UserOrganization.organization_id).where(UserOrganization.user_id == user.id)
        )
    ).scalar_one()

    await create_user_org_link(extra_user, Organization(id=org_id), OrgRole.INTERN, is_active=False)
    print(f"\n🚫 Added inactive user {extra_user.email} to org")

    response = await async_client.post(SEARCH_URL, json={}, headers=headers)
    print("📬 Status Code:", response.status_code)
    print("📦 Response JSON:", response.json())

    assert response.status_code == 200
    data = response.json()
    assert all(u["is_active"] is True for u in data)


@pytest.mark.anyio
async def test_search_include_inactive_true(
    async_client: AsyncClient,
    user_with_org,
    db_session: AsyncSession,
    create_test_user,
    create_user_org_link,
):
    user, token = await user_with_org(role=OrgRole.ADMIN)
    headers = {"Authorization": f"Bearer {token}"}

    extra_user = await create_test_user()

    org_id = (
        await db_session.execute(
            select(UserOrganization.organization_id).where(UserOrganization.user_id == user.id)
        )
    ).scalar_one()

    await create_user_org_link(extra_user, Organization(id=org_id), OrgRole.INTERN, is_active=False)
    print(f"\n🚫 Deactivated user {extra_user.email}")

    payload = {"include_inactive": True}
    print("🔍 Payload:", payload)

    response = await async_client.post(SEARCH_URL, json=payload, headers=headers)
    print("📬 Status Code:", response.status_code)
    print("📦 Response JSON:", response.json())

    assert response.status_code == 200
    data = response.json()
    assert any(u["is_active"] is False for u in data)


@pytest.mark.anyio
async def test_list_members_basic(async_client: AsyncClient, user_with_org):
    user, token = await user_with_org(role=OrgRole.ADMIN)
    headers = {"Authorization": f"Bearer {token}"}

    response = await async_client.get(LIST_URL, headers=headers)
    print("\n👥 List Members - Status Code:", response.status_code)
    print("📦 Response JSON:", response.json())

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert any(u["email"] == user.email for u in data)


@pytest.mark.anyio
async def test_list_members_include_inactive(
    async_client: AsyncClient,
    user_with_org,
    db_session: AsyncSession,
    create_test_user,
    create_user_org_link,
):
    user, token = await user_with_org(role=OrgRole.ADMIN)
    headers = {"Authorization": f"Bearer {token}"}

    extra_user = await create_test_user()

    org_id = (
        await db_session.execute(
            select(UserOrganization.organization_id).where(UserOrganization.user_id == user.id)
        )
    ).scalar_one()

    await create_user_org_link(extra_user, Organization(id=org_id), OrgRole.INTERN, is_active=False)
    print(f"\n🚫 Deactivated user {extra_user.email}")

    response = await async_client.get(LIST_URL + "?include_inactive=true", headers=headers)
    print("📬 Status Code:", response.status_code)
    print("📦 Response JSON:", response.json())

    assert response.status_code == 200
    data = response.json()
    assert any(u["is_active"] is False for u in data)


@pytest.mark.anyio
async def test_list_members_pagination(
    async_client: AsyncClient,
    user_with_org,
    create_test_user,
    create_user_org_link,
    db_session: AsyncSession,
):
    user, token = await user_with_org(role=OrgRole.ADMIN)
    headers = {"Authorization": f"Bearer {token}"}

    org_id = (
        await db_session.execute(
            select(UserOrganization.organization_id).where(UserOrganization.user_id == user.id)
        )
    ).scalar_one()

    for _ in range(10):
        extra_user = await create_test_user()
        await create_user_org_link(extra_user, Organization(id=org_id), OrgRole.INTERN)

    response = await async_client.get(LIST_URL + "?limit=5&offset=0", headers=headers)
    print("📬 Status Code:", response.status_code)
    print("📦 Response JSON:", response.json())

    assert response.status_code == 200
    data = response.json()
    assert len(data) <= 5
