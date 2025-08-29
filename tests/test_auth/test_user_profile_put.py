import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import Visibility
from app.crud import user_profile
from app.schemas.user_profile import UserProfileCreate


def _normalize_headers(user_with_token_result):
    """
    Normalize fixture return value into (user, headers) format.

    Handles:
    - (user, token)
    - (user, headers)
    - (user, token, org)
    """
    if len(user_with_token_result) == 2:
        user, token_or_headers = user_with_token_result
        if isinstance(token_or_headers, str):
            headers = {"Authorization": f"Bearer {token_or_headers}"}
        else:
            headers = token_or_headers
        return user, headers

    elif len(user_with_token_result) >= 3:
        user, token_or_headers, _org = user_with_token_result
        if isinstance(token_or_headers, str):
            headers = {"Authorization": f"Bearer {token_or_headers}"}
        else:
            headers = token_or_headers
        return user, headers

    raise ValueError("Unexpected return format from user_with_token fixture")


@pytest.mark.anyio
async def test_update_profile_success(async_client: AsyncClient, user_with_token, db_session: AsyncSession):
    """
    ✅ Successfully updates an existing profile.
    """
    user, headers = _normalize_headers(await user_with_token())

    # Create initial profile
    await user_profile.create_user_profile(
        db=db_session,
        user_id=user.id,
        profile_in=UserProfileCreate(
            full_name="Old Name",
            visibility=Visibility.PUBLIC
        )
    )

    payload = {"full_name": "New Name"}
    response = await async_client.put("/api/v1/user/profile", json=payload, headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["full_name"] == "New Name"


@pytest.mark.anyio
async def test_update_profile_not_found(async_client: AsyncClient, user_with_token):
    """
    ❌ Updating a profile that does not exist should return 404.
    """
    user, headers = _normalize_headers(await user_with_token())

    payload = {"full_name": "Should Fail"}
    response = await async_client.put("/api/v1/user/profile", json=payload, headers=headers)

    assert response.status_code == 404
    assert "not found" in response.text.lower()


@pytest.mark.anyio
async def test_update_profile_invalid_visibility(async_client: AsyncClient, user_with_token, db_session: AsyncSession):
    """
    ❌ Invalid visibility value should return 422.
    """
    user, headers = _normalize_headers(await user_with_token())

    # Create profile
    await user_profile.create_user_profile(
        db=db_session,
        user_id=user.id,
        profile_in=UserProfileCreate(
            full_name="Test User",
            visibility=Visibility.PUBLIC
        )
    )

    payload = {"visibility": "INVALID"}
    response = await async_client.put("/api/v1/user/profile", json=payload, headers=headers)

    assert response.status_code == 422


@pytest.mark.anyio
async def test_update_profile_org_only_without_org_context(async_client: AsyncClient, user_with_token, db_session: AsyncSession):
    """
    ❌ Cannot set ORG_ONLY visibility without active org context.
    """
    user, headers = _normalize_headers(await user_with_token())

    # Create profile
    await user_profile.create_user_profile(
        db=db_session,
        user_id=user.id,
        profile_in=UserProfileCreate(
            full_name="Test User",
            visibility=Visibility.PUBLIC
        )
    )

    payload = {"visibility": Visibility.ORG_ONLY.value}
    response = await async_client.put("/api/v1/user/profile", json=payload, headers=headers)

    assert response.status_code == 400
    assert "without organization context" in response.text.lower()
