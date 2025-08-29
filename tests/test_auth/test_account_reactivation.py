# tests/test_auth/test_account_reactivation.py

import pytest
from datetime import datetime, timedelta, timezone
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import AsyncMock, patch

from app.db.models.user import User
from app.db.models.otp import OTP
from app.services.audit_log_service import AuditEvent


# ---------------------------------------------------------------------------
# /request-reactivation
# ---------------------------------------------------------------------------

@pytest.mark.anyio
@patch("app.api.v1.routers.auth.reactivation.send_password_reset_otp", new_callable=AsyncMock)
@patch("app.api.v1.routers.auth.reactivation.log_audit_event", new_callable=AsyncMock)
async def test_request_otp_for_inactive_user(
    mock_log_audit: AsyncMock,
    mock_send_email: AsyncMock,
    async_client: AsyncClient,
    db_session: AsyncSession,
    create_test_user,
):
    """
    ✅ Inactive user can request a reactivation OTP; OTP is persisted and audit is logged.
    """
    user = await create_test_user(is_active=False)

    res = await async_client.post("/api/v1/auth/request-reactivation", json={"email": user.email})
    assert res.status_code == 200
    assert res.json()["message"] == "If your account is eligible, a reactivation code has been sent."

    # Email task was executed (background task awaits async callable)
    mock_send_email.assert_awaited()

    # OTP persisted (digest or plaintext depending on migration window)
    row = await db_session.execute(
        OTP.__table__.select().where(
            OTP.user_id == user.id,
            OTP.purpose == "account_reactivation"
        )
    )
    otp = row.fetchone()
    assert otp is not None and (otp.used is False or otp.used is None)

    # Audit scheduled/executed
    mock_log_audit.assert_awaited()
    kwargs = mock_log_audit.call_args.kwargs
    assert kwargs.get("action") == AuditEvent.REQUEST_REACTIVATION_OTP
    assert kwargs.get("status") == "SUCCESS"


@pytest.mark.anyio
async def test_request_reactivation_user_not_found(async_client: AsyncClient):
    """
    ℹ️ Hardened route is enumeration-safe → returns neutral 200.
    """
    res = await async_client.post("/api/v1/auth/request-reactivation", json={"email": "invalid@example.com"})
    assert res.status_code == 200
    assert res.json()["message"] == "If your account is eligible, a reactivation code has been sent."


@pytest.mark.anyio
@patch("app.api.v1.routers.auth.reactivation.send_password_reset_otp", new_callable=AsyncMock)
async def test_request_reactivation_user_active(
    mock_send_email: AsyncMock,
    async_client: AsyncClient,
    create_test_user,
):
    """
    ℹ️ Already-active also returns neutral 200 (no enumeration); no email is sent.
    """
    user = await create_test_user(is_active=True)
    res = await async_client.post("/api/v1/auth/request-reactivation", json={"email": user.email})
    assert res.status_code == 200
    assert res.json()["message"] == "If your account is eligible, a reactivation code has been sent."
    mock_send_email.assert_not_called()


# ---------------------------------------------------------------------------
# /reactivate
# ---------------------------------------------------------------------------

@pytest.mark.anyio
@patch("app.api.v1.routers.auth.reactivation.log_audit_event", new_callable=AsyncMock)
async def test_reactivate_successfully(
    mock_log_audit: AsyncMock,
    async_client: AsyncClient,
    db_session: AsyncSession,
    create_test_user,
):
    """
    ✅ Valid OTP reactivates user, marks OTP used, and logs audit SUCCESS.
    """
    user = await create_test_user(is_active=False)
    otp = OTP(
        user_id=user.id,
        code="123456",  # legacy plaintext still accepted by route for migration
        purpose="account_reactivation",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        used=False,
    )
    db_session.add(otp)
    await db_session.commit()

    res = await async_client.post("/api/v1/auth/reactivate", json={"email": user.email, "otp": "123456"})
    assert res.status_code == 200
    assert res.json()["message"] == "Your account has been successfully reactivated."

    refreshed_user = await db_session.get(User, user.id)
    assert refreshed_user.is_active is True

    refreshed_otp = await db_session.get(OTP, otp.id)
    assert refreshed_otp.used is True

    mock_log_audit.assert_awaited()
    kwargs = mock_log_audit.call_args.kwargs
    assert kwargs.get("action") == AuditEvent.REACTIVATE_ACCOUNT
    assert kwargs.get("status") == "SUCCESS"


@pytest.mark.anyio
async def test_reactivate_invalid_otp(async_client: AsyncClient, create_test_user):
    """
    ❌ Wrong code returns 401 Invalid/Expired.
    """
    user = await create_test_user(is_active=False)
    res = await async_client.post("/api/v1/auth/reactivate", json={"email": user.email, "otp": "wrong1"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid or expired OTP."


@pytest.mark.anyio
async def test_reactivate_expired_otp(async_client: AsyncClient, db_session: AsyncSession, create_test_user):
    """
    ❌ Expired code returns 401.
    """
    user = await create_test_user(is_active=False)
    expired_otp = OTP(
        user_id=user.id,
        code="654321",
        purpose="account_reactivation",
        used=False,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    db_session.add(expired_otp)
    await db_session.commit()

    res = await async_client.post("/api/v1/auth/reactivate", json={"email": user.email, "otp": "654321"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid or expired OTP."


@pytest.mark.anyio
async def test_reactivate_already_active(async_client: AsyncClient, create_test_user):
    """
    ℹ️ Already active returns neutral 200 (nothing to do).
    """
    user = await create_test_user(is_active=True)
    res = await async_client.post("/api/v1/auth/reactivate", json={"email": user.email, "otp": "123456"})
    assert res.status_code == 200
    assert res.json()["message"] == "Your account is already active."


@pytest.mark.anyio
async def test_reactivation_fails_after_deletion_period(
    async_client: AsyncClient,
    db_session: AsyncSession,
    create_test_user,
):
    """
    ❌ When scheduled_deletion_at has passed, reactivation returns 403.
    """
    user = await create_test_user(
        is_active=False,
        scheduled_deletion_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    otp = OTP(
        user_id=user.id,
        code="999999",
        purpose="account_reactivation",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        used=False,
    )
    db_session.add(otp)
    await db_session.commit()

    res = await async_client.post("/api/v1/auth/reactivate", json={"email": user.email, "otp": "999999"})
    assert res.status_code == 403
    assert "reactivation period has expired" in res.json()["detail"].lower()


@pytest.mark.anyio
async def test_reactivate_with_used_otp(async_client: AsyncClient, db_session: AsyncSession, create_test_user):
    """
    ❌ Used code can’t be used again (401).
    """
    user = await create_test_user(is_active=False)
    otp = OTP(
        user_id=user.id,
        code="222222",
        purpose="account_reactivation",
        used=True,  # already used
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    db_session.add(otp)
    await db_session.commit()

    res = await async_client.post("/api/v1.auth/reactivate", json={"email": user.email, "otp": "222222"})
    # If your route is /api/v1/auth/reactivate, keep that; typo guard:
    if res.status_code == 404:
        res = await async_client.post("/api/v1/auth/reactivate", json={"email": user.email, "otp": "222222"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid or expired OTP."


@pytest.mark.anyio
async def test_reactivation_clears_reactivation_token(
    async_client: AsyncClient,
    db_session: AsyncSession,
    create_test_user,
):
    """
    ✅ Success clears reactivation_token on the user.
    """
    user = await create_test_user(is_active=False)
    user.reactivation_token = "some-token"
    db_session.add(user)
    await db_session.commit()

    otp = OTP(
        user_id=user.id,
        code="333333",
        purpose="account_reactivation",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        used=False,
    )
    db_session.add(otp)
    await db_session.commit()

    res = await async_client.post("/api/v1/auth/reactivate", json={"email": user.email, "otp": "333333"})
    assert res.status_code == 200

    refreshed = await db_session.get(User, user.id)
    assert refreshed.reactivation_token is None


@pytest.mark.anyio
@patch("app.api.v1.routers.auth.reactivation.log_audit_event", new_callable=AsyncMock, side_effect=Exception("Simulated log failure"))
async def test_audit_log_failure_handled(
    mock_log_audit: AsyncMock,
    async_client: AsyncClient,
    db_session: AsyncSession,
    create_test_user,
):
    """
    🧪 Failures inside the async audit task must not break the response.
    """
    user = await create_test_user(is_active=False)

    otp = OTP(
        user_id=user.id,
        code="111111",
        purpose="account_reactivation",
        used=False,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    db_session.add(otp)
    await db_session.commit()

    res = await async_client.post("/api/v1/auth/reactivate", json={"email": user.email, "otp": "111111"})
    assert res.status_code == 200
    assert res.json()["message"] == "Your account has been successfully reactivated."
