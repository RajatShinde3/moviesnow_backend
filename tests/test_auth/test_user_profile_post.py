import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.profile import Profile
from app.schemas.enums import Visibility

pytestmark = pytest.mark.anyio


async def _get_profile(db_session: AsyncSession, user_id):
    """Helper to fetch a profile for a given user_id."""
    result = await db_session.execute(
        Profile.__table__.select().where(Profile.user_id == user_id)
    )
    row = result.first()
    return row


async def test_create_profile_success_public(
    async_client: AsyncClient,
    db_session: AsyncSession,
    user_with_headers,  # ✅ use new fixture
):
    """
    ✅ Should create a profile with PUBLIC visibility for the current user.
    """
    user, headers = await user_with_headers()

    payload = {
        "full_name": "Test Public",
        "visibility": Visibility.PUBLIC.value,
    }

    response = await async_client.post("/api/v1/user/profile", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["full_name"] == "Test Public"
    assert data["visibility"] == Visibility.PUBLIC.value

    # Verify in DB
    profile = await _get_profile(db_session, user.id)
    assert profile is not None


async def test_create_profile_org_only_requires_org_context(
    async_client: AsyncClient,
    user_with_headers,  # ✅ use new fixture
):
    """
    🚫 Ensure a normal user (no org context) cannot set visibility=ORG_ONLY.
    """
    user, headers = await user_with_headers()

    payload = {
        "full_name": "No Org Context",
        "visibility": Visibility.ORG_ONLY.value,  # must be string, not enum instance
    }

    response = await async_client.post("/api/v1/user/profile", json=payload, headers=headers)
    print(response.text)
    assert response.status_code == 400
    assert response.json()["detail"] == "Cannot set visibility to 'org_only' without organization context."


async def test_create_profile_org_only_with_org_context(
    async_client: AsyncClient,
    org_user_with_token,  # unchanged, already returns headers
):
    """
    ✅ Ensure an org-linked user (active org set) can create an ORG_ONLY profile.
    """
    user, headers, org = await org_user_with_token(set_active_org=True)

    payload = {
        "full_name": "Org Visible",
        "visibility": Visibility.ORG_ONLY.value,  # sending as string for Pydantic validation
    }

    response = await async_client.post("/api/v1/user/profile", json=payload, headers=headers)

    assert response.status_code == 201
    data = response.json()
    print(data)
    assert data["full_name"] == "Org Visible"
    assert data["visibility"] == Visibility.ORG_ONLY.value
    assert data["user_id"] == str(user.id)


async def test_create_profile_duplicate_fails(
    async_client: AsyncClient,
    user_with_headers,  # ✅ now directly gets headers
    db_session: AsyncSession,
):
    """
    ❌ Creating a second profile for the same user should return 400.
    """
    user, headers = await user_with_headers()

    # Create first profile
    payload = {"full_name": "First", "visibility": Visibility.PUBLIC.value}
    await async_client.post("/api/v1/user/profile", json=payload, headers=headers)

    # Attempt second profile
    payload = {"full_name": "Second", "visibility": Visibility.PUBLIC.value}
    response = await async_client.post("/api/v1/user/profile", json=payload, headers=headers)

    assert response.status_code == 400
    assert "Profile already exists" in response.text
