import pytest
from httpx import AsyncClient
from datetime import datetime, timedelta, timezone

from app.db.models.user import User
from app.db.models.org_creation_token import OrgCreationToken
from app.core.security import create_access_token

# ───────────────────────────────────────────────
# 🔐 Utility: Create Authorization Header
# ───────────────────────────────────────────────

def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}



@pytest.mark.anyio
async def test_list_only_current_user_tokens(
    async_client: AsyncClient,
    create_test_user,
    org_token_factory,
):
    """
    ✅ Should return only tokens created by the current user.
    """
    user_1 = await create_test_user()
    user_2 = await create_test_user()

    # Tokens for user_1
    await org_token_factory(user_id=user_1.id, org_name="Org A", is_used=True)
    await org_token_factory(user_id=user_1.id, org_name="Org B")


    # Token for another user
    await org_token_factory(user_id=user_2.id, org_name="Other Org")

    token = await create_access_token(user_id=user_1.id)

    response = await async_client.get(
        "/api/v1/org/token/creation-token",
        headers=auth_header(token),
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 2
    org_names = [item["org_name"] for item in data]
    assert set(org_names) == {"Org A", "Org B"}


@pytest.mark.anyio
async def test_no_tokens_returns_empty_list(
    async_client: AsyncClient,
    create_test_user,
):
    """
    ✅ Should return an empty list if user has no tokens.
    """
    user = await create_test_user()
    token = await create_access_token(user_id=user.id)

    response = await async_client.get(
        "/api/v1/org/token/creation-token",
        headers=auth_header(token),
    )

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.anyio
async def test_admin_cannot_see_others_tokens(
    async_client: AsyncClient,
    create_test_user,
    org_token_factory,
):
    """
    🚫 Admin should not see other users' tokens (current logic).
    """
    admin = await create_test_user(is_superuser=True)
    other = await create_test_user()

    await org_token_factory(user_id=other.id, org_name="Hidden Org")

    token = await create_access_token(user_id=admin.id)

    response = await async_client.get(
        "/api/v1/org/token/creation-token",
        headers=auth_header(token),
    )

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.anyio
async def test_expired_token_is_still_listed(
    async_client: AsyncClient,
    create_test_user,
    org_token_factory,
):
    """
    ✅ Even expired tokens should still be listed (not filtered by date).
    """
    user = await create_test_user()
    await org_token_factory(
        user_id=user.id,
        org_name="Expired Org",
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),  # expired token
    )

    token = await create_access_token(user_id=user.id)

    response = await async_client.get(
        "/api/v1/org/token/creation-token",
        headers=auth_header(token),
    )

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["org_name"] == "Expired Org"
