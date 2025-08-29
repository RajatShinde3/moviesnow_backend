# tests/test_auth/test_password_reset.py

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.models.user import User
from app.db.models.otp import OTP
from app.core.security import verify_password


# ────────────────────────────────────────────────────────────────────────────────
# /api/v1/auth/request-reset
# ────────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_request_reset_valid_email(async_client: AsyncClient, create_test_user, db_session: AsyncSession):
    """
    Known user → 200 + neutral message. OTP row is created (digest stored),
    and the plaintext OTP is "emailed" (we capture it via patch).
    """
    user = await create_test_user(is_verified=True)

    sent = {}
    def _capture(email: str, otp: str):
        sent["email"] = email
        sent["otp"] = otp

    with patch("app.services.auth.password_reset_service.send_password_reset_otp", side_effect=_capture):
        resp = await async_client.post("/api/v1/auth/request-reset", json={"email": user.email})

    assert resp.status_code == 200
    msg = resp.json().get("message", "")
    assert "password reset OTP" in msg or "OTP" in msg

    # OTP persisted (digest) for this user
    result = await db_session.execute(
        select(OTP).where(OTP.user_id == user.id, OTP.purpose == "password_reset").order_by(OTP.created_at.desc())
    )
    row = result.scalars().first()
    assert row is not None
    # And the email helper got a plaintext OTP
    assert sent.get("email") == user.email
    assert sent.get("otp") and sent["otp"].isdigit() and len(sent["otp"]) in (6, 7)


@pytest.mark.anyio
async def test_request_reset_unknown_email_is_neutral(async_client: AsyncClient):
    """
    Unknown email → still 200 neutral message (no enumeration).
    """
    resp = await async_client.post("/api/v1/auth/request-reset", json={"email": "nobody@example.com"})
    assert resp.status_code == 200
    msg = resp.json().get("message", "")
    assert "password reset OTP" in msg or "OTP" in msg


@pytest.mark.anyio
async def test_request_reset_daily_cap_429(async_client: AsyncClient, create_test_user, db_session: AsyncSession):
    """
    When MAX_DAILY_OTP is exceeded, service returns 429
    with 'Please wait before requesting another OTP.' (we seed rows instead of looping).
    """
    user = await create_test_user(is_verified=True)

    now = datetime.now(timezone.utc)
    # Seed 20 rows (within last 24h) to hit the daily cap
    bulk = [
        OTP(
            user_id=user.id,
            purpose="password_reset",
            code="seeded-digest",
            used=False,
            expires_at=now + timedelta(minutes=10),
            created_at=now - timedelta(hours=1),
        )
        for _ in range(20)
    ]
    db_session.add_all(bulk)
    await db_session.commit()

    resp = await async_client.post("/api/v1/auth/request-reset", json={"email": user.email})
    assert resp.status_code == 429
    assert "Please wait before requesting another OTP" in resp.json().get("detail", "")


# ────────────────────────────────────────────────────────────────────────────────
# /api/v1/auth/confirm-reset
# ────────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_confirm_reset_success(async_client: AsyncClient, create_test_user, db_session: AsyncSession):
    """
    Valid email + correct OTP + new_password → 200 and password actually changed.
    We capture the plaintext OTP from the send hook.
    """
    user = await create_test_user(is_verified=True)

    captured = {}
    def _capture(email: str, otp: str):
        captured["otp"] = otp

    # Issue OTP first
    with patch("app.services.auth.password_reset_service.send_password_reset_otp", side_effect=_capture):
        r = await async_client.post("/api/v1/auth/request-reset", json={"email": user.email})
        assert r.status_code == 200

    # Use the captured OTP to confirm
    new_password = "NewPass@1234"
    payload = {"email": user.email, "otp": captured["otp"], "new_password": new_password}
    resp = await async_client.post("/api/v1/auth/confirm-reset", json=payload)

    assert resp.status_code == 200
    assert "Password reset successful" in resp.json().get("message", "")

    # Verify password updated
    fresh_hash = (await db_session.execute(select(User.hashed_password).where(User.id == user.id))).scalar_one()
    assert verify_password(new_password, fresh_hash)


@pytest.mark.anyio
async def test_confirm_reset_invalid_otp(async_client: AsyncClient, create_test_user):
    """
    Wrong code → 400 'Invalid or expired OTP'.
    """
    user = await create_test_user(is_verified=True)
    payload = {"email": user.email, "otp": "000000", "new_password": "Another@Pass1"}
    resp = await async_client.post("/api/v1/auth/confirm-reset", json=payload)

    assert resp.status_code == 400
    assert "Invalid or expired OTP" in resp.json().get("detail", "")


@pytest.mark.anyio
async def test_confirm_reset_unknown_email_is_400(async_client: AsyncClient):
    """
    Unknown email + any code → 400 'Invalid or expired OTP' (neutral).
    """
    payload = {"email": "nobody@example.com", "otp": "123456", "new_password": "Whatever@123"}
    resp = await async_client.post("/api/v1/auth/confirm-reset", json=payload)

    assert resp.status_code == 400
    assert "Invalid or expired OTP" in resp.json().get("detail", "")
