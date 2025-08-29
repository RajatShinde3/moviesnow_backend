import pytest
from httpx import AsyncClient
from datetime import datetime, timedelta, timezone
from sqlalchemy import insert
from app.db.models.org_invite import OrgInvite
from app.schemas.enums import OrgRole, InviteStatus
from app.core.roles import guard_superadmin_protection
from app.core.exception import SuperadminProtectionException
from app.services.token_service import generate_org_invite_token

INVITE_EMAIL = "invitee@example.com"

def test_guard_superadmin_protection_raises():
    with pytest.raises(SuperadminProtectionException):
        guard_superadmin_protection(actor_role=OrgRole.ADMIN, target_role=OrgRole.SUPERADMIN)


def test_guard_superadmin_protection_allows_superadmin():
    try:
        guard_superadmin_protection(actor_role=OrgRole.SUPERADMIN, target_role=OrgRole.SUPERADMIN)
    except Exception:
        pytest.fail("guard_superadmin_protection raised unexpectedly")



@pytest.mark.anyio
async def test_invite_user_success(async_client: AsyncClient, org_user_with_token):
    user, headers, _ = await org_user_with_token(role=OrgRole.ADMIN)

    response = await async_client.post(
        "/api/v1/org/invite",
        json={"invited_email": INVITE_EMAIL, "role": OrgRole.INTERN.value},
        headers=headers,
    )

    assert response.status_code == 201
    assert response.json() == {"message": "Invitation sent"}


@pytest.mark.anyio
async def test_invite_user_duplicate_fails(async_client: AsyncClient, org_user_with_token):
    user, headers, _ = await org_user_with_token(role=OrgRole.ADMIN)

    # First invite
    await async_client.post(
        "/api/v1/org/invite",
        json={"invited_email": INVITE_EMAIL, "role": OrgRole.INTERN.value},
        headers=headers,
    )

    # Second invite should fail
    response = await async_client.post(
        "/api/v1/org/invite",
        json={"invited_email": INVITE_EMAIL, "role": OrgRole.INTERN.value},
        headers=headers,
    )

    assert response.status_code == 400
    assert "already exists" in response.json()["detail"]



@pytest.mark.anyio
async def test_resend_invite_success(async_client: AsyncClient, org_user_with_token, db_session, mocker):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    # ✅ Generate a real JWT token
    token = generate_org_invite_token(
        email=INVITE_EMAIL,
        org_id=str(org),
        role=OrgRole.INTERN,
    )

    # Insert a valid pending invite manually
    invite = OrgInvite(
        organization_id=str(org.id),
        invited_email=INVITE_EMAIL,
        invited_role=OrgRole.INTERN,
        inviter_id=user.id,
        token=token,
        status=InviteStatus.PENDING,
        is_revoked=False,
        expires_at=datetime.now(timezone.utc) + timedelta(days=3),
    )
    db_session.add(invite)
    await db_session.commit()



    response = await async_client.post(
        "/api/v1/org/invite/resend",
        json={
            "invited_email": INVITE_EMAIL,
            "role": OrgRole.INTERN.value,
        },
        headers=headers,
    )

    assert response.status_code == 201
    assert response.json()["message"] == "Invitation resent successfully"

@pytest.mark.anyio
async def test_resend_invite_not_found(async_client: AsyncClient, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN)

    response = await async_client.post(
        "/api/v1/org/invite/resend",
        json={
            "invited_email": "nonexistent@example.com",
            "role": OrgRole.INTERN.value,
        },
        headers=headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "No valid pending invite found"


@pytest.mark.anyio
async def test_invite_superadmin_blocked_for_non_superadmin(async_client, org_user_with_token):
    user, headers, _ = await org_user_with_token(role=OrgRole.ADMIN)  # Non-superadmin user

    response = await async_client.post(
        "/api/v1/org/invite",
        json={
            "invited_email": "future-superadmin@example.com",
            "role": OrgRole.SUPERADMIN.value,
        },
        headers=headers,
    )

    assert response.status_code == 403
    assert "superadmin" in response.json()["detail"].lower()


@pytest.mark.anyio
async def test_invite_superadmin_by_superadmin_success(async_client, org_user_with_token, db_session):
    user, headers, _ = await org_user_with_token(role=OrgRole.SUPERADMIN)

    response = await async_client.post(
        "/api/v1/org/invite",
        json={
            "invited_email": "superadmin2@example.com",
            "role": OrgRole.SUPERADMIN.value,
        },
        headers=headers,
    )

    assert response.status_code == 201
    assert response.json()["message"] == "Invitation sent"



