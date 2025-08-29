# tests/test_auth/test_account_deletion.py

import pytest
from datetime import datetime, timedelta, timezone
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from app.db.models.user import User
from app.db.models.otp import OTP
from app.services.auth.password_reset_service import generate_otp


# =====================================================================================
# /request-deletion-otp
# =====================================================================================

@pytest.mark.anyio
@patch("app.api.v1.auth.account_deletion.send_password_reset_otp")
async def test_request_deletion_otp_success(
    mock_send_email,
    async_client: AsyncClient,
    user_with_token,
    db_session: AsyncSession,
):
    """
    ✅ Non-MFA user can request deletion OTP.
    - Route stores plaintext code (compat) and emails it.
    - Audit is awaited in the route (no BackgroundTasks).
    """
    user, token = await user_with_token(mfa_enabled=False)
    headers = {"Authorization": f"Bearer {token}"}

    res = await async_client.post("/api/v1/auth/request-deletion-otp", headers=headers)
    assert res.status_code == 200
    assert "OTP has been sent" in res.json()["message"]

    # Email helper was called (route calls it directly)
    mock_send_email.assert_called_once()

    # OTP persisted
    row = await db_session.execute(
        OTP.__table__.select().where(
            OTP.user_id == user.id,
            OTP.purpose == "delete_account",
            OTP.used == False,
        )
    )
    assert row.first() is not None


@pytest.mark.anyio
async def test_request_deletion_otp_mfa_enabled(
    async_client: AsyncClient,
    user_with_token,
    db_session: AsyncSession,
):
    """
    ℹ️ MFA users are told to use authenticator; no OTP is created.
    """
    user, token = await user_with_token(mfa_enabled=True)
    headers = {"Authorization": f"Bearer {token}"}

    res = await async_client.post("/api/v1/auth/request-deletion-otp", headers=headers)
    assert res.status_code == 200
    assert "MFA is enabled" in res.json()["message"]

    row = await db_session.execute(
        OTP.__table__.select().where(
            OTP.user_id == user.id,
            OTP.purpose == "delete_account",
        )
    )
    assert row.first() is None


@pytest.mark.anyio
@patch("app.api.v1.auth.account_deletion.redis_utils.enforce_rate_limit",
       side_effect=HTTPException(status_code=429, detail="Please wait before requesting another OTP."))
async def test_request_deletion_otp_rate_limited(
    mock_rate_limit,
    async_client: AsyncClient,
    user_with_token,
):
    """
    ❌ Rate limit bubbles up as 429 from the route.
    """
    user, token = await user_with_token(mfa_enabled=False)
    headers = {"Authorization": f"Bearer {token}"}

    res = await async_client.post("/api/v1/auth/request-deletion-otp", headers=headers)
    assert res.status_code == 429
    assert "please wait" in res.json()["detail"].lower()


# =====================================================================================
# /delete-user
# =====================================================================================

@pytest.mark.anyio
async def test_delete_user_with_valid_otp(
    async_client: AsyncClient,
    user_with_token,
    db_session: AsyncSession,
):
    """
    ✅ Valid OTP → soft delete succeeds.
    - Service accepts plaintext or hashed OTP (compat logic).
    - Route does not pass BackgroundTasks, so no reactivation email is sent.
    """
    user, token = await user_with_token(mfa_enabled=False)
    headers = {"Authorization": f"Bearer {token}"}

    otp_code = generate_otp()
    db_session.add(OTP(
        user_id=user.id,
        code=otp_code,  # plaintext path is accepted by service (legacy compat)
        purpose="delete_account",
        used=False,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    ))
    await db_session.commit()

    res = await async_client.request(
        "DELETE", "/api/v1/auth/delete-user",
        headers=headers,
        json={"code": otp_code}
    )
    assert res.status_code == 200
    assert "reactivate" in res.json()["message"].lower()

    # Confirm user soft-deleted
    refreshed = await db_session.get(User, user.id)
    assert refreshed.is_active is False
    assert refreshed.scheduled_deletion_at is not None
    assert refreshed.reactivation_token is not None


@pytest.mark.anyio
async def test_delete_user_with_invalid_otp(
    async_client: AsyncClient,
    user_with_token,
):
    """
    ❌ Wrong OTP → 401.
    """
    user, token = await user_with_token(mfa_enabled=False)
    headers = {"Authorization": f"Bearer {token}"}

    res = await async_client.request(
        "DELETE", "/api/v1/auth/delete-user",
        headers=headers,
        json={"code": "000000"}
    )
    assert res.status_code == 401
    assert "invalid" in res.json()["detail"].lower()


@pytest.mark.anyio
async def test_delete_user_with_expired_otp(
    async_client: AsyncClient,
    user_with_token,
    db_session: AsyncSession,
):
    """
    ❌ Expired OTP → 401.
    """
    user, token = await user_with_token(mfa_enabled=False)
    headers = {"Authorization": f"Bearer {token}"}

    code = generate_otp()
    db_session.add(OTP(
        user_id=user.id,
        code=code,
        purpose="delete_account",
        used=False,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    ))
    await db_session.commit()

    res = await async_client.request(
        "DELETE", "/api/v1/auth/delete-user",
        headers=headers,
        json={"code": code}
    )
    assert res.status_code == 401
    assert "expired" in res.json()["detail"].lower()


@pytest.mark.anyio
async def test_delete_user_with_used_otp(
    async_client: AsyncClient,
    user_with_token,
    db_session: AsyncSession,
):
    """
    ❌ Reused OTP → 401.
    """
    user, token = await user_with_token(mfa_enabled=False)
    headers = {"Authorization": f"Bearer {token}"}

    code = generate_otp()
    db_session.add(OTP(
        user_id=user.id,
        code=code,
        purpose="delete_account",
        used=True,   # already used
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    ))
    await db_session.commit()

    res = await async_client.request(
        "DELETE", "/api/v1/auth/delete-user",
        headers=headers,
        json={"code": code}
    )
    assert res.status_code == 401
    assert "invalid" in res.json()["detail"].lower()


@pytest.mark.anyio
@patch("app.services.auth.account_service._decode_mfa_pending_token", return_value=True)
@patch("app.services.auth.account_service.verify_totp", return_value=True)
async def test_delete_user_with_valid_mfa(
    mock_totp,
    mock_mfa,
    async_client: AsyncClient,
    mfa_user_with_token,
):
    """
    ✅ MFA path → success (no OTP required).
    - Service returns success message.
    - No reactivation email, since route does not pass BackgroundTasks.
    """
    user, token = await mfa_user_with_token()
    headers = {"Authorization": f"Bearer {token}"}

    res = await async_client.request(
        "DELETE", "/api/v1/auth/delete-user",
        headers=headers,
        json={"mfa_token": "mfa", "code": "123456"}
    )
    assert res.status_code == 200
    assert "reactivate" in res.json()["message"].lower()


@pytest.mark.anyio
async def test_delete_user_missing_mfa_token(
    async_client: AsyncClient,
    mfa_user_with_token,
):
    """
    ❌ MFA user must provide both token and code.
    """
    user, token = await mfa_user_with_token()
    headers = {"Authorization": f"Bearer {token}"}

    res = await async_client.request(
        "DELETE", "/api/v1/auth/delete-user",
        headers=headers,
        json={"code": "123456"}  # missing mfa_token
    )
    assert res.status_code == 400
    assert "mfa token" in res.json()["detail"].lower()


@pytest.mark.anyio
@patch("app.api.v1.auth.account_deletion.redis_utils.enforce_rate_limit",
       side_effect=HTTPException(status_code=429, detail="Too many attempts"))
async def test_delete_user_rate_limited(
    mock_rate_limit,
    async_client: AsyncClient,
    user_with_token,
):
    """
    ❌ Delete attempts are rate-limited in the route.
    """
    user, token = await user_with_token(mfa_enabled=False)
    headers = {"Authorization": f"Bearer {token}"}

    res = await async_client.request(
        "DELETE", "/api/v1/auth/delete-user",
        headers=headers,
        json={"code": "123456"}  # minimal valid payload shape
    )
    assert res.status_code == 429
    assert "too many attempts" in res.json()["detail"].lower()


@pytest.mark.anyio
async def test_delete_user_unauthenticated(async_client: AsyncClient):
    """
    ❌ Must be authenticated to delete account.
    """
    res = await async_client.request(
        "DELETE", "/api/v1/auth/delete-user",
        json={"code": "123456"}
    )
    assert res.status_code in (401, 403)  # depends on your auth dependency’s failure code
