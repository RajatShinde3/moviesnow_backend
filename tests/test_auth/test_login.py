import pytest
import pyotp

from httpx import AsyncClient
from app.core.security import generate_totp


def ip_header(octet: int) -> dict:
    # each test uses its own synthetic client IP
    return {"X-Forwarded-For": f"10.0.0.{octet}"}


# ─────────────────────────────────────────────────────────────
# /login  (no MFA)
# ─────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_login_success_no_mfa(async_client: AsyncClient, create_test_user):
    email = "nomfa@example.com"
    password = "Password123!"

    await create_test_user(
        email=email,
        password=password,
        is_active=True,
        is_verified=True,
        mfa_enabled=False,
    )

    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
        headers=ip_header(10),
    )
    assert resp.status_code == 200, f"Unexpected {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "access_token" in data and "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.anyio
async def test_login_wrong_password(async_client: AsyncClient, create_test_user):
    email = "wrongpass@example.com"
    await create_test_user(
        email=email,
        password="Correct1!",
        is_active=True,
        is_verified=True,
        mfa_enabled=False,
    )

    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "nope"},
        headers=ip_header(11),
    )
    assert resp.status_code == 401
    assert "invalid email or password" in resp.text.lower()


@pytest.mark.anyio
async def test_login_unverified_email(async_client: AsyncClient, create_test_user):
    email = "unverified@example.com"
    await create_test_user(
        email=email,
        password="Password123!",
        is_active=True,
        is_verified=False,
        mfa_enabled=False,
    )

    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "Password123!"},
        headers=ip_header(12),
    )
    assert resp.status_code == 403
    assert "email not verified" in resp.text.lower()


@pytest.mark.anyio
async def test_login_deactivated(async_client: AsyncClient, create_test_user):
    email = "inactive@example.com"
    await create_test_user(
        email=email,
        password="Password123!",
        is_active=False,
        is_verified=True,
        mfa_enabled=False,
    )

    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "Password123!"},
        headers=ip_header(13),
    )
    assert resp.status_code == 403
    assert "account is deactivated" in resp.text.lower()


# ─────────────────────────────────────────────────────────────
# /login  (MFA challenge)
# ─────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_login_with_mfa_challenge(async_client: AsyncClient, create_test_user):
    email = "mfauser@example.com"
    password = "Password123!"
    totp_secret = pyotp.random_base32()

    await create_test_user(
        email=email,
        password=password,
        is_active=True,
        is_verified=True,
        mfa_enabled=True,
        totp_secret=totp_secret,
    )

    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
        headers=ip_header(14),
    )
    assert resp.status_code == 200, f"Unexpected {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "mfa_token" in data and isinstance(data["mfa_token"], str)


# ─────────────────────────────────────────────────────────────
# /mfa-login
# ─────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_mfa_login_success(async_client: AsyncClient, create_test_user):
    # Create MFA-enabled user
    totp_secret = pyotp.random_base32()
    user = await create_test_user(
        email="mfa2@example.com",
        password="Password123!",
        is_active=True,
        is_verified=True,
        mfa_enabled=True,
        totp_secret=totp_secret,
    )

    headers = ip_header(20)

    # Step 1: /login → get mfa_token
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": "Password123!"},
        headers=headers,
    )
    assert login_resp.status_code == 200, login_resp.text
    mfa_token = login_resp.json()["mfa_token"]

    # Step 2: generate current TOTP with the same helper used in services
    otp = generate_totp(totp_secret).now()

    # Step 3: /mfa-login → should return tokens
    mfa_resp = await async_client.post(
        "/api/v1/auth/mfa-login",
        json={"mfa_token": mfa_token, "totp_code": otp},
        headers=headers,  # same IP for this flow
    )
    assert mfa_resp.status_code == 200, mfa_resp.text
    data = mfa_resp.json()
    assert "access_token" in data and "refresh_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.anyio
async def test_mfa_login_invalid_otp(async_client: AsyncClient, create_test_user):
    totp_secret = pyotp.random_base32()
    user = await create_test_user(
        email="mfafail@example.com",
        password="Password123!",
        is_active=True,
        is_verified=True,
        mfa_enabled=True,
        totp_secret=totp_secret,
    )

    headers = ip_header(21)

    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": "Password123!"},
        headers=headers,
    )
    assert login_resp.status_code == 200
    mfa_token = login_resp.json()["mfa_token"]

    mfa_resp = await async_client.post(
        "/api/v1/auth/mfa-login",
        json={"mfa_token": mfa_token, "totp_code": "000000"},
        headers=headers,
    )
    assert mfa_resp.status_code == 401
    assert "invalid mfa code" in mfa_resp.text.lower()


@pytest.mark.anyio
async def test_mfa_login_invalid_token(async_client: AsyncClient, create_test_user):
    # User exists & has MFA enabled, but we'll send a bogus token
    await create_test_user(
        email="mfabadtoken@example.com",
        password="Password123!",
        is_active=True,
        is_verified=True,
        mfa_enabled=True,
        totp_secret=pyotp.random_base32(),
    )

    resp = await async_client.post(
        "/api/v1/auth/mfa-login",
        json={"mfa_token": "not-a-real-jwt", "totp_code": "123456"},
        headers=ip_header(22),
    )
    assert resp.status_code == 401
    assert "invalid mfa token" in resp.text.lower()
