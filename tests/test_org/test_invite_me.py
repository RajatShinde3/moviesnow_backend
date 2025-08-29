import pytest
from httpx import AsyncClient
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from app.schemas.enums import OrgRole, InviteStatus
from app.db.models import OrgInvite


@pytest.mark.anyio
async def test_check_my_invite_success(
    async_client: AsyncClient,
    db_session,
    create_user_normal,
    org_user_with_token,
):
    """✅ Should return a message if user has a valid invite."""
    # Set up org and admin
    _, admin_user, org = await org_user_with_token()

    # Create normal user
    user = await create_user_normal()

    # Create invite
    invite = OrgInvite(
        token=str(uuid4()),
        invited_email=user.email,
        invited_role=OrgRole.INTERN,
        organization_id=org.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=2),
    )
    db_session.add(invite)
    await db_session.commit()

    # Call endpoint
    headers = {"Authorization": f"Bearer {user.token}"}
    res = await async_client.get("/api/v1/org/invite/me", headers=headers)

    assert res.status_code == 200
    assert "pending invite" in res.json()["message"]


@pytest.mark.anyio
async def test_check_my_invite_none(
    async_client: AsyncClient,
    create_user_normal,
):
    """🚫 Should return 404 if user has no valid invite."""
    user = await create_user_normal()
    headers = {"Authorization": f"Bearer {user.token}"}

    res = await async_client.get("/api/v1/org/invite/me", headers=headers)
    assert res.status_code == 404
    assert res.json()["detail"] == "No valid invite found"


@pytest.mark.anyio
async def test_get_invite_by_token_success(
    async_client: AsyncClient,
    db_session,
    org_user_with_token,
):
    """✅ Should fetch invite and return org/inviter info."""
    inviter, _, org = await org_user_with_token()

    invite = OrgInvite(
        token=str(uuid4()),
        invited_email="test@example.com",
        invited_role=OrgRole.ADMIN,
        organization_id=org.id,
        inviter_id=inviter.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=2),
    )
    db_session.add(invite)
    await db_session.commit()

    res = await async_client.get(f"/api/v1/org/invite/{invite.token}")
    assert res.status_code == 200
    body = res.json()
    assert body["organization_id"] == str(org.id)
    assert body["inviter_email"] == inviter.email
    assert body["invited_email"] == invite.invited_email
    assert body["invited_role"] == invite.invited_role


@pytest.mark.anyio
async def test_get_invite_by_token_invalid_token(async_client: AsyncClient):
    """🚫 Should return 404 for invalid token."""
    res = await async_client.get(f"/api/v1/org/invite/{uuid4()}")
    assert res.status_code == 404
    assert res.json()["detail"] == "Invite token is invalid or expired."


@pytest.mark.anyio
async def test_get_invite_by_token_expired(
    async_client: AsyncClient,
    db_session,
    org_user_with_token,
):
    """🚫 Should return 404 for expired invite."""
    inviter, _, org = await org_user_with_token()

    invite = OrgInvite(
        token=str(uuid4()),
        invited_email="expired@example.com",
        invited_role=OrgRole.ADMIN,
        organization_id=org.id,
        inviter_id=inviter.id,
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    db_session.add(invite)
    await db_session.commit()

    res = await async_client.get(f"/api/v1/org/invite/{invite.token}")
    assert res.status_code == 404
    assert res.json()["detail"] == "Invite token is invalid or expired."


@pytest.mark.anyio
async def test_get_invite_by_token_revoked(
    async_client: AsyncClient,
    db_session,
    org_user_with_token,
):
    """🚫 Should return 404 for revoked invite."""
    inviter, _, org = await org_user_with_token()

    invite = OrgInvite(
        token=str(uuid4()),
        invited_email="revoked@example.com",
        invited_role=OrgRole.ADMIN,
        organization_id=org.id,
        inviter_id=inviter.id,
        is_revoked=True,
        expires_at=datetime.now(timezone.utc) + timedelta(days=2),
    )
    db_session.add(invite)
    await db_session.commit()

    res = await async_client.get(f"/api/v1/org/invite/{invite.token}")
    assert res.status_code == 404
    assert res.json()["detail"] == "Invite token is invalid or expired."
