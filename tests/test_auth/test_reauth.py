# tests/test_auth/test_reauth.py

import pytest
from httpx import AsyncClient
import pyotp
from jose import jwt

BASE_REAUTH = "/api/v1/auth/reauth"
BASE_MFA = "/api/v1/auth/mfa"


@pytest.mark.anyio
async def test_reauth_password_happy_path(async_client: AsyncClient, user_with_headers):
    """
    ✅ Step-up with correct password returns a reauth token.
    Requires an authenticated ACCESS bearer.
    """
    _, headers = await user_with_headers(email="reauth1@example.com", password="Secret123!")
    resp = await async_client.post(f"{BASE_REAUTH}/password", headers=headers, json={"password": "Secret123!"})
    assert resp.status_code == 200
    body = resp.json()
    assert "reauth_token" in body and body["expires_in"] > 0


@pytest.mark.anyio
async def test_reauth_password_wrong_password(async_client: AsyncClient, user_with_headers):
    """
    ❌ Wrong password → 401 (or 403 depending on your security policy).
    Still requires an ACCESS bearer.
    """
    _, headers = await user_with_headers(email="reauth2@example.com", password="Secret123!")
    resp = await async_client.post(f"{BASE_REAUTH}/password", headers=headers, json={"password": "bad"})
    assert resp.status_code in (401, 403)


@pytest.mark.anyio
async def test_reauth_mfa_happy_path(async_client: AsyncClient, user_with_headers):
    """
    ✅ Step-up with TOTP when MFA is enabled returns a reauth token.
    All calls are under the same ACCESS bearer.
    """
    _, headers = await user_with_headers(email="reauth3@example.com", password="Secret123!")

    # Enroll MFA
    en = await async_client.post(f"{BASE_MFA}/enable", headers=headers)
    assert en.status_code == 200
    secret = en.json()["secret"]
    code = pyotp.TOTP(secret).now()
    ver = await async_client.post(f"{BASE_MFA}/verify", headers=headers, json={"code": code})
    assert ver.status_code == 200

    # Step-up via TOTP
    new_code = pyotp.TOTP(secret).now()
    resp = await async_client.post(f"{BASE_REAUTH}/mfa", headers=headers, json={"code": new_code})
    assert resp.status_code == 200
    data = resp.json()
    assert "reauth_token" in data and data["expires_in"] > 0


@pytest.mark.anyio
async def test_reauth_mfa_without_enrollment_400(async_client: AsyncClient, user_with_headers):
    """
    ❌ /reauth/mfa when MFA is not enabled → 400.
    Requires an ACCESS bearer.
    """
    _, headers = await user_with_headers(email="reauth4@example.com", password="Secret123!")
    resp = await async_client.post(f"{BASE_REAUTH}/mfa", headers=headers, json={"code": "123456"})
    assert resp.status_code == 400


@pytest.mark.anyio
async def test_reauth_verify_requires_reauth_bearer(async_client: AsyncClient, user_with_headers):
    """
    ✅ /reauth/verify only works if the Authorization bearer is a fresh REAUTH token.
    We mint a reauth via /reauth/password and then call /reauth/verify with that token.
    Adds debug prints to help diagnose 401s.
    """
    _, headers = await user_with_headers(email="reauth5@example.com", password="Secret123!")

    # Mint a reauth via password step-up (ACCESS bearer in headers)
    pw = await async_client.post(f"{BASE_REAUTH}/password", headers=headers, json={"password": "Secret123!"})
    print("[DEBUG] /reauth/password status:", pw.status_code, "body:", pw.text)
    assert pw.status_code == 200
    token = pw.json()["reauth_token"]

    # Debug: show token prefix and decoded (unverified) claims
    print("[DEBUG] minted reauth token (prefix):", token[:32], "... len:", len(token))
    try:
        claims = jwt.get_unverified_claims(token)
        print("[DEBUG] reauth claims:", claims)
    except Exception as e:
        print("[DEBUG] failed to decode reauth token:", repr(e))

    # Hit /reauth/verify using the REAUTH token as the bearer
    resp = await async_client.post(f"{BASE_REAUTH}/verify", headers={"Authorization": f"Bearer {token}"})
    print("[DEBUG] /reauth/verify status:", resp.status_code)
    try:
        print("[DEBUG] /reauth/verify JSON:", resp.json())
    except Exception:
        print("[DEBUG] /reauth/verify text:", resp.text)

    assert resp.status_code == 200
    v = resp.json()
    assert v["ok"] is True and v["token_type"] == "reauth" and v["expires_in"] > 0
