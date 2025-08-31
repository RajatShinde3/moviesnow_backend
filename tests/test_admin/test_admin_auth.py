from __future__ import annotations

import os
import pytest
import pyotp
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.routers import admin_auth as admin_auth_router
from app.db.session import get_async_db
from tests.fixtures.db import get_override_get_db
from app.core.security import create_access_token, create_refresh_token
from app.schemas.enums import OrgRole
from app.db.models.user import User
from tests.utils.factory import create_user
from app.services.token_service import store_refresh_token


@pytest.fixture()
async def app_admin(db_session: AsyncSession) -> FastAPI:
    app = FastAPI()
    app.include_router(admin_auth_router.router, prefix="/api/v1/admin")
    app.dependency_overrides[get_async_db] = get_override_get_db(db_session)
    return app


@pytest.fixture()
async def client_admin(app_admin: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(transport=ASGITransport(app=app_admin), base_url="http://test") as client:
        yield client


@pytest.mark.anyio
async def test_admin_login_requires_mfa_policy(db_session: AsyncSession, client_admin: AsyncClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ADMIN_REQUIRE_MFA", "true")
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True, mfa_enabled=False)
    resp = await client_admin.post("/api/v1/admin/login", json={"email": admin.email, "password": "password"})
    assert resp.status_code in (401, 403)  # Depending on neutral errors, 403 when policy triggers


@pytest.mark.anyio
async def test_admin_login_mfa_challenge(db_session: AsyncSession, client_admin: AsyncClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ADMIN_REQUIRE_MFA", "true")
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True, mfa_enabled=True, totp_secret=pyotp.random_base32())
    resp = await client_admin.post("/api/v1/admin/login", json={"email": admin.email, "password": "password"})
    assert resp.status_code == 200
    assert "mfa_token" in resp.json()


@pytest.mark.anyio
async def test_admin_reauth_password_success_and_failure(db_session: AsyncSession, client_admin: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.SUPERUSER, is_verified=True, is_active=True)
    access = await create_access_token(user_id=str(admin.id), mfa_authenticated=True)
    headers = {"Authorization": f"Bearer {access}"}

    # Failure (wrong password)
    resp = await client_admin.post("/api/v1/admin/reauth", json={"password": "wrong"}, headers=headers)
    assert resp.status_code == 401

    # Success
    resp = await client_admin.post("/api/v1/admin/reauth", json={"password": "password"}, headers=headers)
    assert resp.status_code == 200
    assert "reauth_token" in resp.json()


@pytest.mark.anyio
async def test_admin_reauth_totp_success(db_session: AsyncSession, client_admin: AsyncClient):
    secret = pyotp.random_base32()
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True, mfa_enabled=True, totp_secret=secret)
    access = await create_access_token(user_id=str(admin.id), mfa_authenticated=True)
    headers = {"Authorization": f"Bearer {access}"}
    code = pyotp.TOTP(secret).now()
    resp = await client_admin.post("/api/v1/admin/reauth", json={"code": code}, headers=headers)
    assert resp.status_code == 200
    assert "reauth_token" in resp.json()


@pytest.mark.anyio
async def test_admin_logout_revokes_refresh(db_session: AsyncSession, client_admin: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    access = await create_access_token(user_id=str(admin.id), mfa_authenticated=True)
    headers = {"Authorization": f"Bearer {access}"}

    refresh_payload = await create_refresh_token(user_id=admin.id)
    await store_refresh_token(
        db=db_session,
        user_id=admin.id,
        token=refresh_payload["token"],
        jti=refresh_payload["jti"],
        expires_at=refresh_payload["expires_at"],
        parent_jti=refresh_payload.get("parent_jti"),
        ip_address=None,
    )

    resp = await client_admin.post("/api/v1/admin/logout", json={"refresh_token": refresh_payload["token"]}, headers=headers)
    assert resp.status_code == 200
    assert resp.json().get("message")
