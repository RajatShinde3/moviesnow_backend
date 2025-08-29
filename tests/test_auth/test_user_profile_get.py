import pytest
from httpx import AsyncClient
from uuid import uuid4
from app.db.models.profile import Profile
from app.schemas.enums import Visibility, OrgRole
from typing import Awaitable, Callable, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import User, Organization


import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Callable, Awaitable, Tuple
from uuid import uuid4, UUID
from app.db.models.profile import Profile
from app.schemas.enums import Visibility

@pytest.mark.anyio
async def test_get_my_profile_success(
    async_client: AsyncClient,
    db_session: AsyncSession,
    user_with_token: Callable[..., Awaitable[Tuple[User, str]]],
):
    user, token = await user_with_token()

    # Create a profile for the user
    profile = Profile(
        user_id=user.id,
        full_name="Test User",
        headline="Python Developer",
        bio="Loves writing clean code.",
        location="Remote",
        website="https://example.com",
        github="https://github.com/testuser",
        linkedin="https://linkedin.com/in/testuser",
        skills=["Python", "FastAPI"],
        interests=["Backend", "Open Source"],
        visibility="public"
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.get(
        "/api/v1/user/profile",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == str(user.id)
    assert data["full_name"] == "Test User"
    assert "Python" in data["skills"]


@pytest.mark.anyio
async def test_get_my_profile_not_found(
    async_client: AsyncClient,
    user_with_token: Callable[..., Awaitable[Tuple[User, str]]],
):
    user, token = await user_with_token()

    # No profile created for this user
    response = await async_client.get(
        "/api/v1/user/profile",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Profile not found"


@pytest.mark.anyio
async def test_get_my_profile_unauthenticated(async_client: AsyncClient):
    response = await async_client.get("/api/v1/user/profile")

    assert response.status_code == 403  # Unauthorized



@pytest.mark.anyio
async def test_get_user_profile_org_only_unauthenticated(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_user_with_token
):
    target_user, _, _ = await org_user_with_token()

    profile = Profile(
        user_id=target_user.id,
        full_name="Org Only Unauth",
        visibility=Visibility.ORG_ONLY.value
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.get(f"/api/v1/user/profile/{target_user.id}")
    assert response.status_code == 403


@pytest.mark.anyio
async def test_get_user_profile_private_other_user(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_user_with_token
):
    viewer, viewer_headers, _ = await org_user_with_token()
    target_user, _, _ = await org_user_with_token()

    profile = Profile(
        user_id=target_user.id,
        full_name="Private Other",
        visibility=Visibility.PRIVATE.value
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.get(
        f"/api/v1/user/profile/{target_user.id}",
        headers=viewer_headers
    )

    assert response.status_code == 403

@pytest.mark.anyio
async def test_get_user_profile_public(
    async_client: AsyncClient,
    db_session: AsyncSession,
    user_with_token: Callable[..., Awaitable[Tuple[User, str]]]
):
    viewer, viewer_token = await user_with_token()
    target_user, _ = await user_with_token()

    # Create public profile for target user
    profile = Profile(
        user_id=target_user.id,
        full_name="Public User",
        visibility=Visibility.PUBLIC.value
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.get(
        f"/api/v1/user/profile/{target_user.id}",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )

    assert response.status_code == 200
    assert response.json()["full_name"] == "Public User"


@pytest.mark.anyio
async def test_get_user_profile_private_self(
    async_client: AsyncClient,
    db_session: AsyncSession,
    user_with_token: Callable[..., Awaitable[Tuple[User, str]]]
):
    user, token = await user_with_token()

    profile = Profile(
        user_id=user.id,
        full_name="Private User",
        visibility=Visibility.PRIVATE.value
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.get(
        f"/api/v1/user/profile/{user.id}",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    assert response.json()["full_name"] == "Private User"


@pytest.mark.anyio
async def test_get_user_profile_private_other_forbidden(
    async_client: AsyncClient,
    db_session: AsyncSession,
    user_with_token: Callable[..., Awaitable[Tuple[User, str]]]
):
    viewer, viewer_token = await user_with_token()
    target_user, _ = await user_with_token()

    profile = Profile(
        user_id=target_user.id,
        full_name="Private User",
        visibility=Visibility.PRIVATE.value
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.get(
        f"/api/v1/user/profile/{target_user.id}",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "This profile is private"




@pytest.mark.anyio
async def test_get_user_profile_org_only_different_org_forbidden(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_user_with_token: Callable[..., Awaitable[Tuple[User, str, UUID]]]
):
    viewer, viewer_token, org1 = await org_user_with_token()
    target_user, _, org2 = await org_user_with_token()

    assert org1 != org2  # Sanity check

    profile = Profile(
        user_id=target_user.id,
        full_name="Another Org",
        visibility=Visibility.ORG_ONLY.value
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.get(
        f"/api/v1/user/profile/{target_user.id}",
        headers={"Authorization": f"Bearer {viewer_token}"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token."


@pytest.mark.anyio
async def test_get_user_profile_not_found(
    async_client: AsyncClient,
    user_with_token: Callable[..., Awaitable[Tuple[User, str]]]
):
    _, token = await user_with_token()
    fake_id = uuid4()

    response = await async_client.get(
        f"/api/v1/user/profile/{fake_id}",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Profile not found"
