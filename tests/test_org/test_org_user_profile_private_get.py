# tests/test_org/test_org_user_profile_private_get.py

import pytest
from httpx import AsyncClient
from uuid import uuid4
from app.db.models.org_user_profile import OrgUserProfile
from app.schemas.enums import Visibility


@pytest.mark.anyio
async def test_get_own_profile_private_visible(
    async_client: AsyncClient,
    db_session,
    org_with_users,
):
    data = await org_with_users(as_tuple=False)
    owner = data.owner
    token = data.token

    profile = OrgUserProfile(
        user_id=owner.id,
        organization_id=data.org.id,
        visibility=Visibility.PRIVATE.value,
        full_name="Owner Profile",
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.get(
        f"api/v1/org/user/profile/{owner.id}",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Org-ID": str(data.org.id),
        },
    )
    assert response.status_code == 200
    assert response.json()["user_id"] == str(owner.id)


@pytest.mark.anyio
async def test_get_other_profile_org_only_visible(
    async_client: AsyncClient,
    db_session,
    org_with_users,
):
    data = await org_with_users(as_tuple=False)
    owner = data.owner
    member_token = data.member_token

    profile = OrgUserProfile(
        user_id=owner.id,
        organization_id=data.org.id,
        visibility=Visibility.ORG_ONLY.value,
        full_name="Owner Visible to Org",
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.get(
        f"api/v1/org/user/profile/{owner.id}",
        headers={
            "Authorization": f"Bearer {member_token}",
            "X-Org-ID": str(data.org.id),
        },
    )
    assert response.status_code == 200
    assert response.json()["user_id"] == str(owner.id)


@pytest.mark.anyio
async def test_get_other_profile_private_invisible(
    async_client: AsyncClient,
    db_session,
    org_with_users,
):
    data = await org_with_users(as_tuple=False)
    owner = data.owner
    member_token = data.member_token

    profile = OrgUserProfile(
        user_id=owner.id,
        organization_id=data.org.id,
        visibility=Visibility.PRIVATE.value,
    )
    db_session.add(profile)
    await db_session.commit()

    response = await async_client.get(
        f"api/v1/org/user/profile/{owner.id}",
        headers={
            "Authorization": f"Bearer {member_token}",
            "X-Org-ID": str(data.org.id),
        },
    )
    assert response.status_code == 403


@pytest.mark.anyio
async def test_get_profile_not_found(
    async_client: AsyncClient,
    org_with_users,
):
    data = await org_with_users(as_tuple=False)
    token = data.token
    fake_user_id = uuid4()

    response = await async_client.get(
        f"api/v1/org/user/profile/{fake_user_id}",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Org-ID": str(uuid4()),  # simulate access denial with unrelated org
        },
    )
    assert response.status_code == 404
