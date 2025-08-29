import pytest
from datetime import datetime, timedelta, timezone

from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.db.models import Organization, OrgCreationToken
from app.core.security import create_access_token

@pytest.mark.anyio
async def test_superuser_org_token_auto_approved(
    async_client: AsyncClient,
    create_test_user,
    db_session: AsyncSession,
):
    superuser = await create_test_user(is_superuser=True)
    token = await create_access_token(user_id=superuser.id)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "org_name": "New Super Org",
        "org_description": "For testing",
        "org_metadata": {"source": "test"}
    }

    response = await async_client.post("/api/v1/org/admin/request-create-token", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()

    assert data["org_name"] == "New Super Org"
    assert data["is_approved"] == True
    assert data["approved_at"] is not None



@pytest.mark.anyio
async def test_request_token_duplicate_org_name(
    async_client: AsyncClient,
    create_test_user,
    create_organization_fixture,
):
    user = await create_test_user()
    org = await create_organization_fixture(name="Existing Org")
    token = await create_access_token(user_id=user.id)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {"org_name": org.name}

    response = await async_client.post("/api/v1/org/admin/request-create-token", json=payload, headers=headers)
    assert response.status_code == 400
    assert "already exists" in response.json()["detail"].lower()


@pytest.mark.anyio
async def test_duplicate_pending_token_request(
    async_client: AsyncClient,
    create_test_user,
    org_token_factory,
):
    user = await create_test_user()
    await org_token_factory(user_id=user.id, org_name="Pending Org", is_used=False)

    token = await create_access_token(user_id=user.id)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {"org_name": "Pending Org"}

    response = await async_client.post("/api/v1/org/admin/request-create-token", json=payload, headers=headers)
    assert response.status_code == 400
    assert "already have a pending token" in response.json()["detail"].lower()


@pytest.mark.anyio
async def test_create_org_with_valid_token(
    async_client: AsyncClient,
    create_test_user,
    org_token_factory,
):
    user = await create_test_user()
    token_obj = await org_token_factory(
        user_id=user.id,
        org_name="Token Org",
        is_approved=True,
        is_used=False,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)
    )

    token = await create_access_token(user_id=user.id)
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"token": token_obj.token, "org_name": token_obj.org_name}

    response = await async_client.post("/api/v1/org/admin/create", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == token_obj.org_name


@pytest.mark.anyio
@pytest.mark.parametrize("is_used,is_approved,expired", [
    (True, True, False),
    (False, False, False),
    (False, True, True),
])
async def test_invalid_org_token_conditions(
    async_client: AsyncClient,
    create_test_user,
    org_token_factory,
    is_used,
    is_approved,
    expired,
):
    user = await create_test_user()
    expires_at = datetime.now(timezone.utc) - timedelta(minutes=5) if expired else datetime.now(timezone.utc) + timedelta(minutes=5)

    token_obj = await org_token_factory(
        user_id=user.id,
        org_name="Invalid Org",
        is_approved=is_approved,
        is_used=is_used,
        expires_at=expires_at
    )

    token = await create_access_token(user_id=user.id)
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"token": token_obj.token, "org_name": token_obj.org_name}

    response = await async_client.post("/api/v1/org/admin/create", json=payload, headers=headers)
    assert response.status_code == 400
    assert "invalid" in response.json()["detail"].lower()


@pytest.mark.anyio
async def test_create_org_name_collision(
    async_client: AsyncClient,
    create_test_user,
    create_organization_fixture,
    org_token_factory,
):
    user = await create_test_user()
    await create_organization_fixture(name="Clash Org")

    token_obj = await org_token_factory(
        user_id=user.id,
        org_name="Clash Org",
        is_approved=True,
        is_used=False,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
    )

    token = await create_access_token(user_id=user.id)
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"token": token_obj.token, "org_name": token_obj.org_name}

    response = await async_client.post("/api/v1/org/admin/create", json=payload, headers=headers)
    assert response.status_code == 400
    assert "already exists" in response.json()["detail"].lower()


@pytest.mark.anyio
async def test_admin_can_approve_org_creation_token(async_client, db_session, create_test_user):
    admin = await create_test_user(is_superuser=True, email=settings.ADMIN_EMAIL)
    admin_token = await create_access_token(user_id=admin.id)
    headers = {"Authorization": f"Bearer {admin_token}"}

    user = await create_test_user()
    test_token = OrgCreationToken(
        token=uuid4().hex,
        user_id=user.id,
        org_name="TokenApprovalTest",
        org_description="Test token approval flow",
        org_metadata={"from": "test"},
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
    )
    db_session.add(test_token)
    await db_session.commit()

    url = f"/api/v1/org/admin/{test_token.id}/approve"
    response = await async_client.post(url, headers=headers)

    assert response.status_code == 200
    assert response.json()["detail"] == "Token approved successfully."

    await db_session.refresh(test_token)
    assert test_token.is_approved is True
    assert test_token.approved_by == admin.id
    assert test_token.approved_at is not None



@pytest.mark.anyio
async def test_admin_can_list_pending_org_tokens(async_client, db_session, create_test_user):
    admin = await create_test_user(is_superuser=True, email=settings.ADMIN_EMAIL)
    token = await create_access_token(user_id=admin.id)
    headers = {"Authorization": f"Bearer {token}"}

    user1 = await create_test_user()
    user2 = await create_test_user()

    tokens = [
        OrgCreationToken(
            token=uuid4().hex,
            user_id=user1.id,
            org_name="PendingOrgA",
            org_description="To be listed",
            org_metadata={},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            is_approved=False,
            is_used=False,
        ),
        OrgCreationToken(
            token=uuid4().hex,
            user_id=user2.id,
            org_name="PendingOrgB",
            org_description="To be listed",
            org_metadata={},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            is_approved=False,
            is_used=False,
        ),
    ]

    db_session.add_all(tokens)
    await db_session.commit()


    response = await async_client.get("/api/v1/org/admin/pending", headers=headers)
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) >= 2
    for token_data in data:
        assert token_data["is_approved"] is False
        assert token_data["is_used"] is False
        assert datetime.fromisoformat(token_data["expires_at"]) > datetime.now(timezone.utc)


@pytest.mark.anyio
async def test_non_admin_cannot_approve_token(async_client, db_session, create_test_user):
    user = await create_test_user(is_superuser=False, email="user@example.com")
    token = await create_access_token(user_id=user.id)
    headers = {"Authorization": f"Bearer {token}"}

    url = f"/api/v1/org/admin/some-random-id/approve"
    response = await async_client.post(url, headers=headers)
    assert response.status_code == 403
    