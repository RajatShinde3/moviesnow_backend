import pytest
import pyotp
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_totp
from app.db.models.user import User
from tests.utils.factory import create_user
from app.core.security import create_access_token


# ─────────────────────────────
# 🔐 Helpers
# ─────────────────────────────
async def _bearer(user: User) -> dict:
    token = await create_access_token(user_id=user.id)
    return {"Authorization": f"Bearer {token}"}


# ─────────────────────────────
# 🚫 Requires auth checks
# (HTTPBearer returns 403 when no header is provided)
# ─────────────────────────────
@pytest.mark.anyio
async def test_enable_mfa_requires_auth(async_client: AsyncClient):
    resp = await async_client.post("/api/v1/auth/mfa/enable")
    assert resp.status_code == 403  # HTTPBearer → 403 when missing


@pytest.mark.anyio
async def test_verify_mfa_requires_auth(async_client: AsyncClient):
    resp = await async_client.post("/api/v1/auth/mfa/verify", json={"code": "000000"})
    assert resp.status_code == 403  # HTTPBearer → 403 when missing


@pytest.mark.anyio
async def test_disable_mfa_requires_auth(async_client: AsyncClient):
    resp = await async_client.post("/api/v1/auth/mfa/disable", json={"password": "irrelevant"})
    assert resp.status_code == 403  # HTTPBearer → 403 when missing


# ─────────────────────────────
# ✅ Enable MFA
# ─────────────────────────────
@pytest.mark.anyio
async def test_enable_mfa_success(async_client: AsyncClient, db_session: AsyncSession):
    user = await create_user(db_session, is_verified=True)
    headers = await _bearer(user)

    resp = await async_client.post("/api/v1/auth/mfa/enable", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "qr_code_url" in data
    assert "secret" in data


@pytest.mark.anyio
async def test_enable_mfa_already_enabled(async_client: AsyncClient, db_session: AsyncSession):
    user = await create_user(db_session, is_verified=True)
    user.mfa_enabled = True
    await db_session.commit()
    headers = await _bearer(user)

    resp = await async_client.post("/api/v1/auth/mfa/enable", headers=headers)
    assert resp.status_code == 400
    assert resp.json()["detail"] == "MFA is already enabled."


# ─────────────────────────────
# ✅ Verify MFA
# ─────────────────────────────
@pytest.mark.anyio
async def test_verify_mfa_success(async_client: AsyncClient, db_session: AsyncSession, create_test_user):
    user = await create_test_user(is_verified=True)
    headers = await _bearer(user)

    # enable to get secret
    enable_resp = await async_client.post("/api/v1/auth/mfa/enable", headers=headers)
    assert enable_resp.status_code == 200, enable_resp.text
    secret = enable_resp.json()["secret"]

    code = generate_totp(secret).now()

    verify_resp = await async_client.post(
        "/api/v1/auth/mfa/verify",
        json={"code": code},
        headers=headers,
    )
    assert verify_resp.status_code == 200, verify_resp.text
    data = verify_resp.json()
    assert data["message"] == "MFA enabled successfully."
    assert "mfa_token" in data


@pytest.mark.anyio
async def test_verify_mfa_invalid_code(async_client: AsyncClient, create_test_user):
    user = await create_test_user(is_verified=True)
    headers = await _bearer(user)

    # enable first so a secret exists
    enable_resp = await async_client.post("/api/v1/auth/mfa/enable", headers=headers)
    assert enable_resp.status_code == 200

    resp = await async_client.post(
        "/api/v1/auth/mfa/verify",
        json={"code": "123456"},  # bogus
        headers=headers,
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid MFA code."


# ─────────────────────────────
# 🚫 Disable MFA
# ─────────────────────────────
@pytest.mark.anyio
async def test_disable_mfa_success(async_client: AsyncClient, db_session: AsyncSession, create_test_user):
    password = "Password123!"
    user = await create_test_user(is_verified=True, password=password)
    headers = await _bearer(user)

    # enable → verify to turn it on
    enable_resp = await async_client.post("/api/v1/auth/mfa/enable", headers=headers)
    assert enable_resp.status_code == 200
    secret = enable_resp.json()["secret"]
    code = generate_totp(secret).now()
    verify_resp = await async_client.post("/api/v1/auth/mfa/verify", json={"code": code}, headers=headers)
    assert verify_resp.status_code == 200

    # now disable
    resp = await async_client.post(
        "/api/v1/auth/mfa/disable",
        json={"password": password},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["message"] == "MFA disabled successfully"


@pytest.mark.anyio
async def test_disable_mfa_invalid_password(async_client: AsyncClient, db_session: AsyncSession, create_test_user):
    password = "Password123!"
    user = await create_test_user(is_verified=True, password=password)
    headers = await _bearer(user)

    # enable → verify to turn it on
    enable_resp = await async_client.post("/api/v1/auth/mfa/enable", headers=headers)
    assert enable_resp.status_code == 200
    secret = enable_resp.json()["secret"]
    code = generate_totp(secret).now()
    verify_resp = await async_client.post("/api/v1/auth/mfa/verify", json={"code": code}, headers=headers)
    assert verify_resp.status_code == 200

    # wrong password
    resp = await async_client.post(
        "/api/v1/auth/mfa/disable",
        json={"password": "wrongpassword"},
        headers=headers,
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Invalid password"
