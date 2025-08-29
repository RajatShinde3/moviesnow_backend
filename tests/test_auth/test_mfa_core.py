# tests/test_auth/test_mfa_core.py

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
import pyotp

from app.db.models import User

BASE = "/api/v1/auth/mfa" 


@pytest.mark.anyio
async def test_enable_returns_secret_and_qr_and_sets_pending_secret(
    async_client: AsyncClient,
    db_session: AsyncSession,
    user_with_token,
):
    """
    ✅ /mfa/enable provisions a secret & QR and persists pending secret (mfa_enabled stays False).
    """
    user, token = await user_with_token(password="Secret123!", mfa_enabled=False, totp_secret=None)
    headers = {"Authorization": f"Bearer {token}"}

    resp = await async_client.post(f"{BASE}/enable", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "qr_code_url" in data and data["qr_code_url"].startswith("otpauth://")
    assert "secret" in data and data["secret"]

    refreshed = await db_session.get(User, user.id)
    await db_session.refresh(refreshed)
    assert refreshed.totp_secret is not None
    assert refreshed.mfa_enabled is False


@pytest.mark.anyio
async def test_verify_happy_path_enables_mfa(
    async_client: AsyncClient,
    db_session: AsyncSession,
    user_with_token,
):
    """
    ✅ /mfa/verify with a correct TOTP flips mfa_enabled=True.
    """
    user, token = await user_with_token(password="Secret123!", mfa_enabled=False, totp_secret=None)
    headers = {"Authorization": f"Bearer {token}"}

    en = await async_client.post(f"{BASE}/enable", headers=headers)
    assert en.status_code == 200
    secret = en.json()["secret"]

    code = pyotp.TOTP(secret).now()
    vr = await async_client.post(f"{BASE}/verify", headers=headers, json={"code": code})
    assert vr.status_code == 200
    assert vr.json()["message"].lower().startswith("mfa enabled")

    refreshed = await db_session.get(User, user.id)
    await db_session.refresh(refreshed)
    assert refreshed.mfa_enabled is True


@pytest.mark.anyio
async def test_verify_invalid_code_401(async_client: AsyncClient, user_with_token):
    """
    ❌ Wrong TOTP → 401.
    """
    _, token = await user_with_token(password="Secret123!", mfa_enabled=False, totp_secret=None)
    headers = {"Authorization": f"Bearer {token}"}

    en = await async_client.post(f"{BASE}/enable", headers=headers)
    assert en.status_code == 200

    vr = await async_client.post(f"{BASE}/verify", headers=headers, json={"code": "000000"})
    assert vr.status_code == 401
    assert "invalid" in vr.json()["detail"].lower()


@pytest.mark.anyio
async def test_enable_when_already_enabled_400(async_client: AsyncClient, user_with_token):
    """
    ❌ Calling /enable after MFA is already enabled → 400.
    """
    _, token = await user_with_token(password="Secret123!", mfa_enabled=False, totp_secret=None)
    headers = {"Authorization": f"Bearer {token}"}

    en = await async_client.post(f"{BASE}/enable", headers=headers)
    secret = en.json()["secret"]
    code = pyotp.TOTP(secret).now()
    vr = await async_client.post(f"{BASE}/verify", headers=headers, json={"code": code})
    assert vr.status_code == 200

    resp = await async_client.post(f"{BASE}/enable", headers=headers)
    assert resp.status_code == 400
    assert "already enabled" in resp.json()["detail"].lower()


@pytest.mark.anyio
async def test_verify_when_not_setup_400(async_client: AsyncClient, db_session: AsyncSession, user_with_token):
    """
    ❌ /verify without prior /enable (no secret) → 400.
    """
    user, token = await user_with_token(password="Secret123!", mfa_enabled=False, totp_secret=None)
    headers = {"Authorization": f"Bearer {token}"}

    resp = await async_client.post(f"{BASE}/verify", headers=headers, json={"code": "123456"})
    assert resp.status_code == 400
    assert "not set up" in resp.json()["detail"].lower()

    refreshed = await db_session.get(User, user.id)
    await db_session.refresh(refreshed)
    assert refreshed.totp_secret is None
    assert refreshed.mfa_enabled is False


@pytest.mark.anyio
async def test_disable_with_password_happy_path(async_client: AsyncClient, db_session: AsyncSession, user_with_token):
    """
    ✅ Correct password on /mfa/disable clears secret and sets mfa_enabled=False.
    """
    user, token = await user_with_token(password="Secret123!", mfa_enabled=False, totp_secret=None)
    headers = {"Authorization": f"Bearer {token}"}

    en = await async_client.post(f"{BASE}/enable", headers=headers)
    secret = en.json()["secret"]
    code = pyotp.TOTP(secret).now()
    await async_client.post(f"{BASE}/verify", headers=headers, json={"code": code})

    resp = await async_client.post(f"{BASE}/disable", headers=headers, json={"password": "Secret123!"})
    assert resp.status_code == 200

    refreshed = await db_session.get(User, user.id)
    await db_session.refresh(refreshed)
    assert refreshed.mfa_enabled is False
    assert refreshed.totp_secret is None


@pytest.mark.anyio
async def test_disable_with_wrong_password_403(async_client: AsyncClient, user_with_token):
    """
    ❌ Wrong password on /mfa/disable → 403.
    """
    _, token = await user_with_token(password="Secret123!", mfa_enabled=False, totp_secret=None)
    headers = {"Authorization": f"Bearer {token}"}

    en = await async_client.post(f"{BASE}/enable", headers=headers)
    secret = en.json()["secret"]
    code = pyotp.TOTP(secret).now()
    await async_client.post(f"{BASE}/verify", headers=headers, json={"code": code})

    resp = await async_client.post(f"{BASE}/disable", headers=headers, json={"password": "bad-pass"})
    assert resp.status_code == 403
