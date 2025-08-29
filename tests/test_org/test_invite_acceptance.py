# tests/test_org/test_invite_accept.py

import pytest
from httpx import AsyncClient
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from app.schemas.enums import OrgRole, InviteStatus
from app.db.models import OrgInvite


@pytest.mark.anyio
async def test_accept_invite_success(
    async_client: AsyncClient,
    db_session,
    org_user_with_token,
    create_user_normal
):
    """
    ✅ Test: Successfully accept a valid invite and join the organization.

    Steps:
    - Create an organization and admin user.
    - Create a normal user (invitee).
    - Create an invite for the normal user.
    - Simulate invite acceptance.
    - Assert correct DB state and API response.
    """
    # 🎯 Setup: create org with admin user
    _, _, org = await org_user_with_token(role=OrgRole.ADMIN)

    # 👤 Create the invitee user
    new_user = await create_user_normal()

    # 📨 Create a pending invite for the invitee
    invite = OrgInvite(
        token=str(uuid4()),
        invited_email=new_user.email,
        invited_role=OrgRole.INTERN,
        organization_id=org.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=2),
    )
    db_session.add(invite)
    await db_session.commit()
    await db_session.refresh(invite)

    # 🛂 Simulate invite acceptance by authenticated invitee
    invitee_headers = {"Authorization": f"Bearer {new_user.token}"}
    response = await async_client.post(
        "/api/v1/org/invite/accept",
        headers=invitee_headers,
        json={"token": invite.token},
    )

    # ✅ Assert: successful response
    assert response.status_code == 200
    assert response.json()["message"] == "Organization invitation accepted successfully"

    # 🔄 Refresh invite from DB after API call
    updated_invite = await db_session.get(OrgInvite, invite.id)
    await db_session.refresh(updated_invite)

    # 🔍 Assert: invite status updated in DB
    assert updated_invite.status == InviteStatus.ACCEPTED
    assert updated_invite.accepted_at is not None


@pytest.mark.anyio
async def test_accept_invite_invalid_token(async_client: AsyncClient, create_user_normal):
    """Invalid token should fail with 400."""
    user = await create_user_normal()
    headers = {"Authorization": f"Bearer {user.token}"}

    response = await async_client.post(
        "/api/v1/org/invite/accept",
        headers=headers,
        json={"token": "invalid-token"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid invitation token."


@pytest.mark.anyio
async def test_accept_invite_expired(async_client: AsyncClient, db_session, org_user_with_token, create_user_normal):
    """Expired invite token should fail with 400."""
    _, _, org = await org_user_with_token()
    new_user = await create_user_normal()

    expired_invite = OrgInvite(
        token=str(uuid4()),
        invited_email=new_user.email,
        invited_role=OrgRole.INTERN,
        organization_id=org.id,
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    db_session.add(expired_invite)
    await db_session.commit()
    await db_session.refresh(expired_invite)

    headers = {"Authorization": f"Bearer {new_user.token}"}
    res = await async_client.post(
        "/api/v1/org/invite/accept",
        headers=headers,
        json={"token": expired_invite.token},
    )

    assert res.status_code == 400
    assert res.json()["detail"] == "This invite has expired."


@pytest.mark.anyio
async def test_accept_invite_already_member(async_client: AsyncClient, db_session, org_user_with_token):
    """Accepting an invite when already a member should fail with 400."""
    user, headers, org = await org_user_with_token()

    invite = OrgInvite(
        token=str(uuid4()),
        invited_email=user.email,
        invited_role=OrgRole.INTERN,
        organization_id=org.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )
    db_session.add(invite)
    await db_session.commit()
    await db_session.refresh(invite)

    res = await async_client.post(
        "/api/v1/org/invite/accept",
        headers=headers,
        json={"token": invite.token},
    )

    assert res.status_code == 400
    assert res.json()["detail"] == "You are already a member of this organization."


# --------------------------
# Invite history (admin-only)
# --------------------------

@pytest.mark.anyio
async def test_invite_history_success(async_client: AsyncClient, db_session, org_user_with_token):
    """Admin can fetch invite history for the org."""
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    # Add a couple of invites
    for i in range(2):
        invite = OrgInvite(
            token=str(uuid4()),
            invited_email=f"user{i}@test.com",
            invited_role=OrgRole.INTERN,
            organization_id=org.id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
        db_session.add(invite)
    await db_session.commit()

    res = await async_client.get("/api/v1/org/invite/history", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 2
    for item in data:
        assert "invited_email" in item
        assert "role" in item
        assert "sent_at" in item
        assert "expires_at" in item


@pytest.mark.anyio
async def test_invite_history_empty(async_client: AsyncClient, org_user_with_token):
    """Empty list when no invites exist."""
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    res = await async_client.get("/api/v1/org/invite/history", headers=headers)
    assert res.status_code == 200
    assert res.json() == []


