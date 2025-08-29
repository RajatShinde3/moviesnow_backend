import pytest
from httpx import AsyncClient
from uuid import uuid4

from app.db.models.org_user_profile import OrgUserProfile
from app.schemas.enums import Visibility


@pytest.mark.anyio
async def test_public_profile_visible(
    async_client: AsyncClient,
    db_session,
    org_with_users,
):
    data = await org_with_users(as_tuple=False)
    owner = data.owner

    profile = OrgUserProfile(
        user_id=owner.id,
        organization_id=data.org.id,
        visibility=Visibility.PUBLIC.value,
        full_name="Visible User",
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.get(
        f"/api/v1/org/user/public/profile/{owner.id}",
        headers={"X-Org-ID": str(data.org.id)},
    )

    assert response.status_code == 200
    res = response.json()
    assert res["user_id"] == str(owner.id)
    assert res["visibility"] == Visibility.PUBLIC.value
    assert res["full_name"] == "Visible User"


@pytest.mark.anyio
async def test_public_profile_private_visibility(
    async_client: AsyncClient,
    db_session,
    org_with_users,
):
    data = await org_with_users(as_tuple=False)
    owner = data.owner

    profile = OrgUserProfile(
        user_id=owner.id,
        organization_id=data.org.id,
        visibility=Visibility.PRIVATE.value,
        full_name="Private User",
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.get(
        f"/api/v1/org/user/public/profile/{owner.id}",
        headers={"X-Org-ID": str(data.org.id)},
    )

    assert response.status_code == 404


@pytest.mark.anyio
async def test_public_profile_not_found(
    async_client: AsyncClient,
    org_with_users,
):
    data = await org_with_users(as_tuple=False)
    fake_user_id = uuid4()

    response = await async_client.get(
        f"/api/v1/org/user/public/profile/{fake_user_id}",
        headers={"X-Org-ID": str(data.org.id)},
    )

    assert response.status_code == 404


@pytest.mark.anyio
async def test_public_profile_org_header_missing(
    async_client: AsyncClient,
    org_with_users,
):
    data = await org_with_users(as_tuple=False)
    owner = data.owner

    response = await async_client.get(f"/api/v1/org/user/public/profile/{owner.id}")

    assert response.status_code == 400
    assert response.json()["detail"] == "Organization context is missing. Ensure X-Org-ID header is provided if required."
