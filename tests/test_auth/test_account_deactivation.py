# tests/test_auth/test_account_deactivation.py

import pytest
from httpx import AsyncClient
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, AsyncMock

from fastapi import HTTPException
from app.db.models.otp import OTP
from app.services.auth.password_reset_service import generate_otp
from app.utils.mfa_utils import generate_totp
from app.core.security import generate_mfa_token


# ─────────────────────────────────────────────────────────────
# /api/v1/auth/request-deactivation-otp
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
@patch("app.api.v1.routers.auth.account_deactivation.log_audit_event", new_callable=AsyncMock)
async def test_request_deactivation_otp_success(
    mock_log_audit,
    async_client: AsyncClient,
    user_with_token,
    db_session
):
    """
    ✅ Should send a deactivation OTP to non-MFA user, persist OTP, and audit SUCCESS.
    """
    user, token = await user_with_token(mfa_enabled=False)
    headers = {"Authorization": f"Bearer {token}"}

    # Trigger request
    resp = await async_client.post("/api/v1/auth/request-deactivation-otp", headers=headers)
    assert resp.status_code == 200
    assert "otp has been sent" in resp.json()["message"].lower()

    # Audit scheduled
    mock_log_audit.assert_called()
    kwargs = mock_log_audit.call_args.kwargs
    assert kwargs["action"].value == "REQUEST_DEACTIVATION_OTP"
    assert kwargs["status"] == "SUCCESS"

    # OTP persisted (purpose = deactivate_account)
    result = await db_session.execute(
        OTP.__table__.select().where(
            OTP.user_id == user.id,
            OTP.purpose == "deactivate_account"
        )
    )
    assert result.first() is not None


@pytest.mark.anyio
@patch("app.api.v1.routers.auth.account_deactivation.redis_utils.enforce_rate_limit", side_effect=HTTPException(429, "Rate limit exceeded"))
async def test_request_deactivation_otp_rate_limited(
    mock_rate_limit,
    async_client: AsyncClient,
    user_with_token,
    db_session
):
    """
    ❌ If Redis rate limiter raises HTTPException(429), endpoint should return 429 and not create an OTP.
    """
    user, token = await user_with_token(mfa_enabled=False)
    headers = {"Authorization": f"Bearer {token}"}

    resp = await async_client.post("/api/v1/auth/request-deactivation-otp", headers=headers)
    assert resp.status_code == 429
    assert "rate limit exceeded" in resp.text.lower()

    # Ensure no OTP persisted
    result = await db_session.execute(
        OTP.__table__.select().where(
            OTP.user_id == user.id,
            OTP.purpose == "deactivate_account"
        )
    )
    assert result.first() is None


@pytest.mark.anyio
@patch("app.api.v1.routers.auth.account_deactivation.redis_utils.enforce_rate_limit", side_effect=Exception("Redis error"))
@patch("app.api.v1.routers.auth.account_deactivation.BackgroundTasks.add_task")
async def test_request_deactivation_otp_failure_logs_audit(
    mock_add_task,
    mock_rate_limit,
    async_client: AsyncClient,
    user_with_token
):
    """
    ❌ If unexpected error occurs (e.g., Redis down), route returns 500 and schedules FAILURE audit.
    """
    user, token = await user_with_token(mfa_enabled=False)
    headers = {"Authorization": f"Bearer {token}"}

    resp = await async_client.post("/api/v1/auth/request-deactivation-otp", headers=headers)
    assert resp.status_code == 500
    assert "failed to send deactivation otp" in resp.text.lower()

    # Audit scheduled with FAILURE
    mock_add_task.assert_called()
    # First positional arg is the callable (log_audit_event)
    assert mock_add_task.call_args[0][0].__name__ == "log_audit_event"
    # kwargs should include status="FAILURE"
    assert mock_add_task.call_args.kwargs["status"] == "FAILURE"


@pytest.mark.anyio
async def test_request_deactivation_otp_skips_if_mfa_enabled(
    async_client: AsyncClient,
    user_with_token,
    db_session
):
    """
    🔕 If user has MFA enabled, the endpoint returns a message (no OTP is created).
    """
    user, token = await user_with_token(mfa_enabled=True)
    headers = {"Authorization": f"Bearer {token}"}

    resp = await async_client.post("/api/v1/auth/request-deactivation-otp", headers=headers)
    assert resp.status_code == 200
    assert "use your authenticator app" in resp.json()["message"].lower()

    # No OTP created
    result = await db_session.execute(
        OTP.__table__.select().where(
            OTP.user_id == user.id,
            OTP.purpose == "deactivate_account"
        )
    )
    assert result.first() is None


@pytest.mark.anyio
async def test_request_deactivation_otp_cleans_previous_unused(
    async_client: AsyncClient,
    user_with_token,
    db_session
):
    """
    🧹 Previous unused OTPs are deleted before inserting a new one (so exactly one remains).
    """
    user, token = await user_with_token(mfa_enabled=False)
    headers = {"Authorization": f"Bearer {token}"}

    # Seed an existing unused OTP
    old = OTP(
        user_id=user.id,
        code="123456",
        purpose="deactivate_account",
        used=False,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    db_session.add(old)
    await db_session.commit()

    # Request new OTP
    resp = await async_client.post("/api/v1/auth/request-deactivation-otp", headers=headers)
    assert resp.status_code == 200

    # Only one unused OTP should remain
    result = await db_session.execute(
        OTP.__table__.select().where(
            OTP.user_id == user.id,
            OTP.purpose == "deactivate_account",
            OTP.used == False
        )
    )
    rows = result.fetchall()
    assert len(rows) == 1


# ─────────────────────────────────────────────────────────────
# /api/v1/auth/deactivate-user
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
@patch("app.api.v1.routers.auth.account_deactivation.log_audit_event", new_callable=AsyncMock)
async def test_deactivate_user_with_otp_success(
    mock_log_audit,
    async_client: AsyncClient,
    user_with_token,
    db_session
):
    """
    ✅ Non-MFA user can deactivate with a valid OTP (plaintext stored or HMAC).
    """
    user, token = await user_with_token(mfa_enabled=False)
    headers = {"Authorization": f"Bearer {token}"}
    code = generate_otp()

    # Store plaintext OTP (service accepts plaintext OR HMAC digest)
    otp = OTP(
        user_id=user.id,
        code=code,
        purpose="deactivate_account",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        used=False,
    )
    db_session.add(otp)
    await db_session.commit()

    resp = await async_client.put("/api/v1/auth/deactivate-user", headers=headers, json={"code": code})
    assert resp.status_code == 200
    assert "deactivated" in resp.json()["message"].lower()
    mock_log_audit.assert_called()


@pytest.mark.anyio
@patch("app.api.v1.routers.auth.account_deactivation.log_audit_event", new_callable=AsyncMock)
async def test_deactivate_user_with_totp_success(
    mock_log_audit,
    async_client: AsyncClient,
    mfa_user_with_token
):
    """
    ✅ MFA-enabled user deactivates with valid mfa_token + TOTP.
    """
    from app.core.config import settings
    from jose import jwt

    user, token = await mfa_user_with_token()
    headers = {"Authorization": f"Bearer {token}"}

    totp_code = generate_totp(user.totp_secret).now()
    mfa_token = generate_mfa_token(str(user.id))

    # sanity check token decodes
    decoded = jwt.decode(
        mfa_token,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithms=[settings.JWT_ALGORITHM]
    )
    assert decoded.get("mfa_pending") is True

    resp = await async_client.put(
        "/api/v1/auth/deactivate-user",
        headers=headers,
        json={"code": totp_code, "mfa_token": mfa_token},
    )
    assert resp.status_code == 200
    assert "deactivated" in resp.json()["message"].lower()
    mock_log_audit.assert_called()


@pytest.mark.anyio
async def test_deactivate_user_invalid_otp(
    async_client: AsyncClient,
    user_with_token
):
    """
    ❌ Non-MFA user submitting an invalid/unknown OTP gets 401.
    """
    user, token = await user_with_token(mfa_enabled=False)
    headers = {"Authorization": f"Bearer {token}"}

    resp = await async_client.put("/api/v1/auth/deactivate-user", headers=headers, json={"code": "999999"})
    assert resp.status_code == 401
    assert "invalid" in resp.json()["detail"].lower()


@pytest.mark.anyio
async def test_deactivate_user_with_used_otp(
    async_client: AsyncClient,
    user_with_token,
    db_session
):
    """
    ❌ Used OTP (even if unexpired) is rejected with 401.
    """
    user, token = await user_with_token(mfa_enabled=False)
    code = generate_otp()

    otp = OTP(
        user_id=user.id,
        code=code,
        purpose="deactivate_account",
        used=True,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    db_session.add(otp)
    await db_session.commit()

    headers = {"Authorization": f"Bearer {token}"}
    resp = await async_client.put("/api/v1/auth/deactivate-user", headers=headers, json={"code": code})
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower() or "invalid" in resp.json()["detail"].lower()


@pytest.mark.anyio
async def test_deactivate_user_with_expired_otp(
    async_client: AsyncClient,
    user_with_token,
    db_session
):
    """
    ❌ Expired OTP is rejected with 401.
    """
    user, token = await user_with_token(mfa_enabled=False)
    code = generate_otp()

    expired = OTP(
        user_id=user.id,
        code=code,
        purpose="deactivate_account",
        used=False,
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    db_session.add(expired)
    await db_session.commit()

    headers = {"Authorization": f"Bearer {token}"}
    resp = await async_client.put("/api/v1/auth/deactivate-user", headers=headers, json={"code": code})
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower() or "invalid" in resp.json()["detail"].lower()


@pytest.mark.anyio
async def test_deactivate_already_deactivated_user(
    async_client: AsyncClient,
    user_with_token,
    db_session
):
    """
    ℹ️ If the user is already deactivated, service returns a neutral 200 with message.
    """
    user, token = await user_with_token(mfa_enabled=False)
    user.is_active = False
    await db_session.commit()

    headers = {"Authorization": f"Bearer {token}"}
    resp = await async_client.put("/api/v1/auth/deactivate-user", headers=headers, json={"code": "000000"})
    assert resp.status_code == 200
    assert "already deactivated" in resp.json()["message"].lower()


@pytest.mark.anyio
@patch("app.api.v1.routers.auth.account_deactivation.redis_utils.enforce_rate_limit", side_effect=HTTPException(429, "Rate limit exceeded"))
async def test_deactivation_rate_limit_exceeded(
    mock_rate_limit,
    async_client: AsyncClient,
    user_with_token,
    db_session
):
    """
    ❌ If rate limit triggers for OTP verification, expect 429.
    """
    user, token = await user_with_token(mfa_enabled=False)
    headers = {"Authorization": f"Bearer {token}"}

    # seed a valid OTP so we only test the limiter path
    otp = OTP(
        user_id=user.id,
        code="123456",
        purpose="deactivate_account",
        used=False,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    db_session.add(otp)
    await db_session.commit()

    resp = await async_client.put("/api/v1/auth/deactivate-user", headers=headers, json={"code": "123456"})
    assert resp.status_code == 429
    assert "rate limit exceeded" in resp.text.lower()


@pytest.mark.anyio
@patch("app.api.v1.routers.auth.account_deactivation.deactivate_user", side_effect=Exception("DB crash"))
@patch("app.api.v1.routers.auth.account_deactivation.BackgroundTasks.add_task")
async def test_deactivate_user_db_crash(
    mock_add_task,
    mock_deactivate_user,
    async_client: AsyncClient,
    user_with_token
):
    """
    ❌ Generic exception in service should produce 500 and schedule FAILURE audit.
    """
    user, token = await user_with_token(mfa_enabled=False)
    headers = {"Authorization": f"Bearer {token}"}

    resp = await async_client.put("/api/v1/auth/deactivate-user", headers=headers, json={"code": "123456"})
    assert resp.status_code == 500
    assert "an unexpected error occurred" in resp.text.lower()

    mock_add_task.assert_called()
    assert mock_add_task.call_args.kwargs["status"] == "FAILURE"


@pytest.mark.anyio
async def test_deactivate_user_missing_input_for_mfa_user(
    async_client: AsyncClient,
    user_with_token
):
    """
    ❌ For MFA users, missing code/mfa_token payload should fail validation (422).
    """
    user, token = await user_with_token(mfa_enabled=True)
    headers = {"Authorization": f"Bearer {token}"}

    resp = await async_client.put("/api/v1/auth/deactivate-user", headers=headers, json={})
    assert resp.status_code == 422
    assert "field required" in resp.text.lower()


@pytest.mark.anyio
async def test_deactivate_user_invalid_mfa_token(
    async_client: AsyncClient,
    mfa_user_with_token
):
    """
    ❌ Invalid MFA bearer token should be rejected (401).
    """
    user, token = await mfa_user_with_token()
    headers = {"Authorization": f"Bearer {token}"}
    bad_token = "not-a-valid-mfa-token"
    good_totp = generate_totp(user.totp_secret).now()

    resp = await async_client.put(
        "/api/v1/auth/deactivate-user",
        headers=headers,
        json={"code": good_totp, "mfa_token": bad_token},
    )
    assert resp.status_code == 401
    detail = resp.json()["detail"].lower()
    assert any(s in detail for s in ("mfa token", "step-up"))



@pytest.mark.anyio
async def test_deactivate_user_invalid_mfa_code(
    async_client: AsyncClient,
    mfa_user_with_token
):
    """
    ❌ Valid MFA token but wrong TOTP code → 401.
    """
    user, token = await mfa_user_with_token()
    headers = {"Authorization": f"Bearer {token}"}
    mfa_token = generate_mfa_token(str(user.id))

    resp = await async_client.put(
        "/api/v1/auth/deactivate-user",
        headers=headers,
        json={"code": "000000", "mfa_token": mfa_token},  # wrong code
    )
    assert resp.status_code == 401
    assert "invalid mfa code" in resp.json()["detail"].lower()
