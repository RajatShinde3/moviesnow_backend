import pytest
from app.db.models.org_invite import OrgInvite
from app.schemas.enums import OrgRole, InviteStatus
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from sqlalchemy import select


@pytest.mark.anyio
async def test_list_pending_invites_success(async_client, org_user_with_token, db_session):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)  # 👈 important

    invite = OrgInvite(
        organization_id=org.id,
        invited_email="list@example.com",
        invited_role=OrgRole.INTERN,
        token="token-list",
        inviter_id=user.id,
        status=InviteStatus.PENDING,
        is_revoked=False,
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
    )
    db_session.add(invite)
    await db_session.commit()

    response = await async_client.get("/api/v1/org/invites/pending", headers=headers)
    assert response.status_code == 200



@pytest.mark.anyio
async def test_list_pending_invites_empty(async_client, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN)  # 👈 same here
    response = await async_client.get("/api/v1/org/invites/pending", headers=headers)
    assert response.status_code == 200


@pytest.mark.anyio
async def test_list_pending_invites_excludes_revoked_or_expired(async_client, org_user_with_token, db_session):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    expired_invite = OrgInvite(
        organization_id=org.id,
        invited_email="expired@example.com",
        invited_role=OrgRole.INTERN,
        token="expired-token",
        inviter_id=user.id,
        status=InviteStatus.PENDING,
        is_revoked=False,
        created_at=datetime.now(timezone.utc) - timedelta(days=5),
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )

    revoked_invite = OrgInvite(
        organization_id=org.id,
        invited_email="revoked@example.com",
        invited_role=OrgRole.INTERN,
        token="revoked-token",
        inviter_id=user.id,
        status=InviteStatus.PENDING,
        is_revoked=True,
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )

    db_session.add_all([expired_invite, revoked_invite])
    await db_session.commit()

    response = await async_client.get("/api/v1/org/invites/pending", headers=headers)
    assert response.status_code == 200
    assert all(i["invited_email"] not in ["expired@example.com", "revoked@example.com"] for i in response.json())


@pytest.mark.anyio
async def test_revoke_invite_success(async_client, org_user_with_token, db_session):
    """
    ✅ Test that an admin can successfully revoke an invite
    and the `is_revoked` flag is set to True in the DB.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    invite = OrgInvite(
        organization_id=org.id,
        invited_email="revoke@example.com",
        invited_role=OrgRole.INTERN,
        token="revoke-token",
        inviter_id=user.id,
        status=InviteStatus.PENDING,
        is_revoked=False,
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )
    db_session.add(invite)
    await db_session.commit()

    # ✅ Call the endpoint
    response = await async_client.post(
        "/api/v1/org/invite/revoke",
        headers=headers,
        json={"invited_email": "revoke@example.com", "role": OrgRole.INTERN.value},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Invitation revoked successfully"

    # ✅ Force refresh from DB
    result = await db_session.execute(select(OrgInvite).where(OrgInvite.id == invite.id))
    updated = result.scalar_one()

    print(f"\nInvite status: {updated.status}, is_revoked: {updated.is_revoked}")

    # ✅ Final assertions
    assert updated.is_revoked is True
    assert updated.status == InviteStatus.REVOKED


@pytest.mark.anyio
async def test_revoke_invite_not_found(async_client, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN)

    response = await async_client.post(
        "/api/v1/org/invite/revoke",
        headers=headers,
        json={"invited_email": "nonexistent@example.com", "role": OrgRole.INTERN.value},
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "No matching active invite found"


@pytest.mark.anyio
async def test_revoke_invite_already_expired(async_client, org_user_with_token, db_session):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    invite = OrgInvite(
        organization_id=org.id,
        invited_email="expired-revoke@example.com",
        invited_role=OrgRole.INTERN,
        token="expired-revoke-token",
        inviter_id=user.id,
        status=InviteStatus.PENDING,
        is_revoked=False,
        created_at=datetime.now(timezone.utc) - timedelta(days=5),
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    db_session.add(invite)
    await db_session.commit()

    response = await async_client.post(
        "/api/v1/org/invite/revoke",
        headers=headers,
        json={"invited_email": "expired-revoke@example.com", "role": OrgRole.INTERN.value},
    )
    assert response.status_code == 404


@patch("app.api.v1.routes.orgs.org_invite.log_org_event")
@pytest.mark.anyio
async def test_revoke_invite_logs_audit_event(mock_log_event, async_client, org_user_with_token, db_session):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    invite = OrgInvite(
        organization_id=org.id,
        invited_email="auditlog@example.com",
        invited_role=OrgRole.INTERN,
        token="audit-token",
        inviter_id=user.id,
        status=InviteStatus.PENDING,
        is_revoked=False,
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db_session.add(invite)
    await db_session.commit()

    response = await async_client.post(
        "/api/v1/org/invite/revoke",
        headers=headers,
        json={"invited_email": "auditlog@example.com", "role": OrgRole.INTERN.value},
    )

    assert response.status_code == 200

    # ✅ Ensure log_org_event was called once
    mock_log_event.assert_called_once()