# tests/test_auth/test_reauth.py

import pytest
from httpx import AsyncClient
from unittest.mock import patch
import pyotp
from fastapi import HTTPException

BASE_REAUTH = "/api/v1/auth/reauth"
BASE_MFA = "/api/v1/auth/mfa"

def _with_ip(headers: dict, ip: str) -> dict:
    h = dict(headers)
    h["X-Forwarded-For"] = ip
    return h

# ─────────────────────────────────────────────────────────────
# /reauth/password
# ─────────────────────────────────────────────────────────────

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
    ❌ Wrong password → 401 (or 403 depending on policy).
    Still requires an ACCESS bearer.
    """
    _, headers = await user_with_headers(email="reauth2@example.com", password="Secret123!")
    resp = await async_client.post(f"{BASE_REAUTH}/password", headers=headers, json={"password": "bad"})
    assert resp.status_code in (401, 403)


@pytest.mark.anyio
async def test_reauth_password_requires_access_bearer(async_client: AsyncClient, user_with_headers):
    """
    ❌ /reauth/password must be called with an ACCESS token:
       - No Authorization → 401
       - REAUTH bearer → 401 (endpoint explicitly requires access)
    """
    # No bearer
    resp = await async_client.post(f"{BASE_REAUTH}/password", json={"password": "Secret123!"})
    assert resp.status_code == 403

    # Make a user and mint a REAUTH token via password, then try using REAUTH bearer against the same endpoint
    _, headers = await user_with_headers(email="reauth2b@example.com", password="Secret123!")
    pw = await async_client.post(f"{BASE_REAUTH}/password", headers=headers, json={"password": "Secret123!"})
    assert pw.status_code == 200
    reauth = pw.json()["reauth_token"]

    # Using reauth bearer for /reauth/password should fail (needs access)
    resp2 = await async_client.post(f"{BASE_REAUTH}/password", headers={"Authorization": f"Bearer {reauth}"}, json={"password": "Secret123!"})
    assert resp2.status_code == 401


@pytest.mark.anyio
@patch("app.api.v1.auth.reauth._check_and_bump_fail_counters", side_effect=HTTPException(status_code=429, detail="Too many attempts"))
async def test_reauth_password_rate_limited(mock_limiter, async_client: AsyncClient, user_with_headers):
    """
    ❌ If anti-bruteforce limiter trips, expect 429.
    """
    _, headers = await user_with_headers(email="reauth1rl@example.com", password="Secret123!")
    resp = await async_client.post(f"{BASE_REAUTH}/password", headers=headers, json={"password": "Secret123!"})
    assert resp.status_code == 429


# ─────────────────────────────────────────────────────────────
# /reauth/mfa
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_reauth_mfa_happy_path(async_client: AsyncClient, user_with_headers):
    """
    ✅ Step-up with TOTP when MFA is enabled returns a reauth token.
    All calls are under the same ACCESS bearer.
    """
    _, headers = await user_with_headers(email="reauth3@example.com", password="Secret123!")

    # Enroll MFA
    en = await async_client.post(
        f"{BASE_MFA}/enable",
        headers=_with_ip(headers, "203.0.113.50"),
    )

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
async def test_reauth_mfa_invalid_code_401(async_client: AsyncClient, user_with_headers):
    """
    ❌ Wrong TOTP code → 401.
    """
    _, headers = await user_with_headers(email="reauth4b@example.com", password="Secret123!")
    # enable MFA
    en = await async_client.post(
        f"{BASE_MFA}/enable",
        headers=_with_ip(headers, "203.0.173.50"),
    )

    assert en.status_code == 200
    secret = en.json()["secret"]
    code = pyotp.TOTP(secret).now()
    ver = await async_client.post(f"{BASE_MFA}/verify", headers=headers, json={"code": code})
    assert ver.status_code == 200

    # now attempt with an incorrect code
    resp = await async_client.post(f"{BASE_REAUTH}/mfa", headers=headers, json={"code": "000000"})
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_reauth_mfa_requires_access_bearer(async_client: AsyncClient, user_with_headers):
    """
    ❌ /reauth/mfa must be called with an ACCESS token:
       - No Authorization → 401
       - REAUTH bearer → 401 (endpoint explicitly requires access)
    """
    # No bearer
    resp = await async_client.post(f"{BASE_REAUTH}/mfa", json={"code": "123456"})
    assert resp.status_code == 403

    # Get access headers and enroll MFA
    _, headers = await user_with_headers(email="reauth4c@example.com", password="Secret123!")
    en = await async_client.post(
        f"{BASE_MFA}/enable",
        headers=_with_ip(headers, "203.0.250.50"),
    )

    secret = en.json()["secret"]
    code = pyotp.TOTP(secret).now()
    await async_client.post(f"{BASE_MFA}/verify", headers=headers, json={"code": code})

    # Mint a reauth via password
    pw = await async_client.post(f"{BASE_REAUTH}/password", headers=headers, json={"password": "Secret123!"})
    assert pw.status_code == 200
    reauth = pw.json()["reauth_token"]

    # Using reauth bearer against /reauth/mfa should fail (needs access)
    resp2 = await async_client.post(f"{BASE_REAUTH}/mfa", headers={"Authorization": f"Bearer {reauth}"}, json={"code": pyotp.TOTP(secret).now()})
    assert resp2.status_code == 401


@pytest.mark.anyio
@patch("app.api.v1.auth.reauth._check_and_bump_fail_counters", side_effect=HTTPException(status_code=429, detail="Too many attempts"))
async def test_reauth_mfa_rate_limited(mock_limiter, async_client: AsyncClient, user_with_headers):
    """
    ❌ If anti-bruteforce limiter trips during MFA step-up, expect 429.
    """
    _, headers = await user_with_headers(email="reauth3rl@example.com", password="Secret123!")
    # Enroll MFA
    en = await async_client.post(
        f"{BASE_MFA}/enable",
        headers=_with_ip(headers, "203.0.128.50"),
    )

    assert en.status_code == 200
    secret = en.json()["secret"]
    code = pyotp.TOTP(secret).now()
    ver = await async_client.post(f"{BASE_MFA}/verify", headers=headers, json={"code": code})
    assert ver.status_code == 200

    # Now try reauth/mfa – patched limiter throws
    resp = await async_client.post(f"{BASE_REAUTH}/mfa", headers=headers, json={"code": pyotp.TOTP(secret).now()})
    assert resp.status_code == 429


# ─────────────────────────────────────────────────────────────
# /reauth/verify
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_reauth_verify_requires_reauth_bearer(async_client: AsyncClient, user_with_headers):
    """
    ✅ /reauth/verify only works if the Authorization bearer is a fresh REAUTH token.
    """
    _, headers = await user_with_headers(email="reauth5@example.com", password="Secret123!")

    # Mint a reauth via password step-up (ACCESS bearer in headers)
    pw = await async_client.post(f"{BASE_REAUTH}/password", headers=headers, json={"password": "Secret123!"})
    assert pw.status_code == 200
    token = pw.json()["reauth_token"]

    # Hit /reauth/verify using the REAUTH token as the bearer
    resp = await async_client.post(f"{BASE_REAUTH}/verify", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    v = resp.json()
    assert v["ok"] is True and v["token_type"] == "reauth" and v["expires_in"] > 0


@pytest.mark.anyio
async def test_reauth_verify_with_access_bearer_401(async_client: AsyncClient, user_with_headers):
    """
    ❌ /reauth/verify with an ACCESS bearer should be rejected (expects reauth token).
    """
    _, headers = await user_with_headers(email="reauth6@example.com", password="Secret123!")
    resp = await async_client.post(f"{BASE_REAUTH}/verify", headers=headers)
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_reauth_verify_missing_bearer_401(async_client: AsyncClient):
    """
    ❌ /reauth/verify without Authorization header → 401.
    """
    resp = await async_client.post(f"{BASE_REAUTH}/verify")
    assert resp.status_code == 401
