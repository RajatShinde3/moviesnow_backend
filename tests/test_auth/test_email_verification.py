# tests/test_auth/test_email_verification.py

import pytest
from httpx import AsyncClient
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from unittest.mock import AsyncMock, patch

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.user import User
from app.core.config import settings
from app.services.auth.email_verification_service import _token_digest


# -----------------------------
# /verify-email
# -----------------------------

@pytest.mark.anyio
async def test_verify_email_success(async_client: AsyncClient, db_session: AsyncSession, create_test_user):
    # Arrange: create user with digest-style verification token still within TTL
    token = uuid4().hex
    user = await create_test_user(is_verified=False)
    user.verification_token = _token_digest(token, user_id=str(user.id))
    user.verification_token_created_at = datetime.now(timezone.utc)
    await db_session.commit()

    # Act
    resp = await async_client.get(f"/api/v1/auth/verify-email?token={token}")

    # Assert
    assert resp.status_code == 200
    assert "Email verified successfully" in resp.text

    refreshed = await db_session.get(User, user.id)
    assert refreshed.is_verified is True
    assert refreshed.verification_token is None
    assert refreshed.verification_token_created_at is None


@pytest.mark.anyio
async def test_verify_email_already_verified(async_client: AsyncClient, db_session: AsyncSession, create_test_user):
    # Arrange: verified users are not scanned; endpoint returns neutral error
    token = uuid4().hex
    user = await create_test_user(is_verified=True)
    # even if token fields are set, service won’t match verified users
    user.verification_token = _token_digest(token, user_id=str(user.id))
    user.verification_token_created_at = datetime.now(timezone.utc)
    await db_session.commit()

    # Act
    resp = await async_client.get(f"/api/v1/auth/verify-email?token={token}")

    # Assert: neutral message (no “already verified” leak here)
    assert resp.status_code == 400
    assert "invalid or expired token" in resp.text.lower()


@pytest.mark.anyio
async def test_verify_email_invalid_token(async_client: AsyncClient):
    # Token is syntactically OK but won’t match any digest
    resp = await async_client.get("/api/v1/auth/verify-email?token=not-a-real-token")
    assert resp.status_code == 400
    assert "invalid or expired token" in resp.text.lower()


@pytest.mark.anyio
async def test_verify_email_expired_token(async_client: AsyncClient, db_session: AsyncSession, create_test_user):
    # Arrange: created well beyond TTL (default: 48h)
    token = uuid4().hex
    user = await create_test_user(is_verified=False)
    user.verification_token = _token_digest(token, user_id=str(user.id))
    user.verification_token_created_at = datetime.now(timezone.utc) - timedelta(days=8)
    await db_session.commit()

    # Act
    resp = await async_client.get(f"/api/v1/auth/verify-email?token={token}")

    # Assert
    assert resp.status_code == 400
    assert "invalid or expired token" in resp.text.lower()


# -----------------------------
# /resend-verification
# -----------------------------

@pytest.mark.anyio
@patch("app.services.auth.email_verification_service.enforce_rate_limit", new_callable=AsyncMock)
@patch("app.services.auth.email_verification_service.send_verification_email", new_callable=AsyncMock)
async def test_resend_verification_success(
    mock_send_email: AsyncMock,
    mock_rl: AsyncMock,
    async_client: AsyncClient,
    db_session: AsyncSession,
    create_test_user,
):
    # Arrange: unverified user
    user = await create_test_user(is_verified=False)

    # Act
    resp = await async_client.post("/api/v1/auth/resend-verification", json={"email": user.email})

    # Assert: neutral message + email queued
    assert resp.status_code == 200
    assert resp.json()["message"] == "If your email is registered, a verification link has been sent."
    mock_send_email.assert_awaited()

    # Verify digest got (re)generated
    refreshed = await db_session.get(User, user.id)
    assert refreshed.verification_token is not None
    assert refreshed.verification_token_created_at is not None


@pytest.mark.anyio
@patch("app.services.auth.email_verification_service.enforce_rate_limit", new_callable=AsyncMock)
@patch("app.services.auth.email_verification_service.send_verification_email", new_callable=AsyncMock)
async def test_resend_verification_already_verified(
    mock_send_email: AsyncMock,
    mock_rl: AsyncMock,
    async_client: AsyncClient,
    create_test_user,
):
    # Arrange: verified user
    user = await create_test_user(is_verified=True)

    # Act
    resp = await async_client.post("/api/v1/auth/resend-verification", json={"email": user.email})

    # Assert: explicit message (safe to reveal); no email sent
    assert resp.status_code == 200
    assert "already verified" in resp.json()["message"].lower()
    mock_send_email.assert_not_awaited()


@pytest.mark.anyio
@patch("app.services.auth.email_verification_service.enforce_rate_limit", new_callable=AsyncMock)
@patch("app.services.auth.email_verification_service.send_verification_email", new_callable=AsyncMock)
async def test_resend_verification_user_not_found(
    mock_send_email: AsyncMock,
    mock_rl: AsyncMock,
    async_client: AsyncClient,
):
    # Act
    resp = await async_client.post("/api/v1/auth/resend-verification", json={"email": "unknown@example.com"})

    # Assert: neutral response (no enumeration) and no email sent
    assert resp.status_code == 200
    assert "verification link has been sent" in resp.text.lower() or "if your email is registered" in resp.text.lower()
    mock_send_email.assert_not_awaited()
