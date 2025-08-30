# tests/test_auth/test_mfa_core.py

import pytest
from httpx import AsyncClient
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
import pyotp
import uuid
from app.db.models import User

BASE = "/api/v1/auth/mfa"  # change to "/api/v1/mfa" if that's how you mounted

def _unique_email(tag: str = "mfa2") -> str:
    return f"{tag}-{uuid.uuid4().hex[:10]}@example.com"

def _with_ip(headers: dict, ip: str) -> dict:
    h = dict(headers)
    h["X-Forwarded-For"] = ip
    return h

@pytest.mark.anyio
async def test_enable_returns_secret_and_qr_and_sets_pending_secret(
    async_client: AsyncClient,
    db_session: AsyncSession,
    user_with_headers,
):
    """
    ✅ Enable route provisions a secret & QR and persists pending secret (mfa_enabled stays False).
    """
    user, headers = await user_with_headers(email="mfa1@example.com", password="Secret123!")

    resp = await async_client.post(f"{BASE}/enable", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "qr_code_url" in data and data["qr_code_url"].startswith("otpauth://")
    assert "secret" in data and data["secret"]

    # DB: totp_secret set, mfa_enabled still False
    refreshed = await db_session.get(User, user.id)
    await db_session.refresh(refreshed)
    assert refreshed.totp_secret is not None
    assert refreshed.mfa_enabled is False

@pytest.mark.anyio
async def test_verify_happy_path_enables_mfa(
    async_client: AsyncClient,
    db_session: AsyncSession,
    user_with_headers,
):
    """
    ✅ Verify with a correct TOTP code flips mfa_enabled=True.
    """
    user, headers = await user_with_headers(email=_unique_email("mfa2"), password="Secret123!")

    # Create a secret (use unique IP so per-IP limits never collide across tests)
    en = await async_client.post(f"{BASE}/enable", headers=_with_ip(headers, "203.0.113.20"))
    assert en.status_code == 200, en.text
    secret = en.json()["secret"]

    # Compute a valid code and verify
    code = pyotp.TOTP(secret).now()
    vr = await async_client.post(f"{BASE}/verify", headers=headers, json={"code": code})
    assert vr.status_code == 200, vr.text
    payload = vr.json()
    assert payload["message"].lower().startswith("mfa enabled")

    # DB: user is now fully enabled
    refreshed = await db_session.get(User, user.id)
    await db_session.refresh(refreshed)
    assert refreshed.mfa_enabled is True


@pytest.mark.anyio
async def test_verify_invalid_code_401(async_client: AsyncClient, user_with_headers):
    """
    ❌ Verify with a wrong code → 401.
    """
    _, headers = await user_with_headers(email="mfa3@example.com", password="Secret123!")

    en = await async_client.post(f"{BASE}/enable", headers=headers)
    assert en.status_code == 200

    vr = await async_client.post(f"{BASE}/verify", headers=headers, json={"code": "000000"})
    assert vr.status_code == 401
    assert "invalid" in vr.json()["detail"].lower()


@pytest.mark.anyio
async def test_enable_when_already_enabled_400(async_client: AsyncClient, user_with_headers):
    """
    ❌ Calling /enable after MFA is already enabled should 400.
    """
    _, headers = await user_with_headers(email="mfa4@example.com", password="Secret123!")

    en = await async_client.post(f"{BASE}/enable", headers=headers)
    secret = en.json()["secret"]
    code = pyotp.TOTP(secret).now()
    vr = await async_client.post(f"{BASE}/verify", headers=headers, json={"code": code})
    assert vr.status_code == 200

    # Try enabling again
    resp = await async_client.post(f"{BASE}/enable", headers=headers)
    assert resp.status_code == 400
    assert "already enabled" in resp.json()["detail"].lower()


@pytest.mark.anyio
async def test_verify_when_not_setup_400(
    async_client: AsyncClient,
    db_session: AsyncSession,
    user_with_headers,
):
    """
    ❌ /verify without having run /enable (no secret) → 400.
    """
    # Create a user explicitly with no secret
    user, headers = await user_with_headers(
        email="mfa-nosetup@example.com",
        password="Secret123!",
        mfa_enabled=False,
        totp_secret=None,
    )

    resp = await async_client.post(f"{BASE}/verify", headers=headers, json={"code": "123456"})
    assert resp.status_code == 400
    assert "not set up" in resp.json()["detail"].lower()

    # DB sanity
    refreshed = await db_session.get(User, user.id)
    await db_session.refresh(refreshed)
    assert refreshed.totp_secret is None
    assert refreshed.mfa_enabled is False


@pytest.mark.anyio
async def test_disable_with_password_happy_path(
    async_client: AsyncClient,
    db_session: AsyncSession,
    user_with_headers,
):
    """
    ✅ With correct password, /disable clears secret and sets mfa_enabled=False.
    """
    user, headers = await user_with_headers(email="mfa-disable@example.com", password="Secret123!")

    # enable → verify
    en = await async_client.post(f"{BASE}/enable", headers=headers)
    secret = en.json()["secret"]
    code = pyotp.TOTP(secret).now()
    await async_client.post(f"{BASE}/verify", headers=headers, json={"code": code})

    # now disable
    resp = await async_client.post(f"{BASE}/disable", headers=headers, json={"password": "Secret123!"})
    assert resp.status_code == 200

    # DB confirms changes
    refreshed = await db_session.get(User, user.id)
    await db_session.refresh(refreshed)
    assert refreshed.mfa_enabled is False
    assert refreshed.totp_secret is None


@pytest.mark.anyio
async def test_disable_with_wrong_password_403(async_client: AsyncClient, user_with_headers):
    """
    ❌ Wrong password on /disable → 403.
    """
    _, headers = await user_with_headers(email="mfa-disable2@example.com", password="Secret123!")

    en = await async_client.post(f"{BASE}/enable", headers=headers)
    secret = en.json()["secret"]
    code = pyotp.TOTP(secret).now()
    await async_client.post(f"{BASE}/verify", headers=headers, json={"code": code})

    resp = await async_client.post(f"{BASE}/disable", headers=headers, json={"password": "bad-pass"})
    assert resp.status_code == 403
