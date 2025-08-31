from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI
from typing import AsyncGenerator
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.routers import admin_sessions as admin_sessions_router
from app.db.session import get_async_db
from tests.fixtures.db import get_override_get_db
from app.core.security import create_access_token, create_refresh_token
from app.schemas.enums import OrgRole
from app.db.models.user import User
from tests.utils.factory import create_user
from app.services.token_service import store_refresh_token


@pytest.fixture()
async def app_admin_sessions(db_session: AsyncSession) -> FastAPI:
    app = FastAPI()
    app.include_router(admin_sessions_router.router, prefix="/api/v1/admin")
    app.dependency_overrides[get_async_db] = get_override_get_db(db_session)
    return app


@pytest.fixture()
async def client_admin_sessions(app_admin_sessions: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(transport=ASGITransport(app=app_admin_sessions), base_url="http://test") as client:
        yield client


async def _access_headers_for(user: User, *, session_id: str | None = None) -> dict[str, str]:
    token = await create_access_token(user_id=str(user.id), mfa_authenticated=True, session_id=session_id)
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.anyio
async def test_admin_refresh_rotate(db_session: AsyncSession, client_admin_sessions: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    refresh = await create_refresh_token(user_id=admin.id)
    await store_refresh_token(
        db=db_session,
        user_id=admin.id,
        token=refresh["token"],
        jti=refresh["jti"],
        expires_at=refresh["expires_at"],
        parent_jti=refresh.get("parent_jti"),
        ip_address=None,
    )
    resp = await client_admin_sessions.post("/api/v1/admin/refresh", json={"refresh_token": refresh["token"]})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data.get("access_token") and data.get("refresh_token")


@pytest.mark.anyio
async def test_admin_sessions_list_and_revoke(db_session: AsyncSession, client_admin_sessions: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.SUPERUSER, is_verified=True, is_active=True)
    # Seed 2 refresh tokens for the admin
    r1 = await create_refresh_token(user_id=admin.id)
    await store_refresh_token(db=db_session, user_id=admin.id, token=r1["token"], jti=r1["jti"], expires_at=r1["expires_at"], parent_jti=r1.get("parent_jti"), ip_address=None)
    r2 = await create_refresh_token(user_id=admin.id)
    await store_refresh_token(db=db_session, user_id=admin.id, token=r2["token"], jti=r2["jti"], expires_at=r2["expires_at"], parent_jti=r2.get("parent_jti"), ip_address=None)

    headers = await _access_headers_for(admin, session_id=r1["jti"])  # mark r1 as current
    # List
    resp = await client_admin_sessions.get("/api/v1/admin/sessions?limit=10&offset=0", headers=headers)
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    assert len(items) >= 2

    # Revoke r2 by jti
    resp = await client_admin_sessions.post("/api/v1/admin/sessions/revoke", json={"jti": r2["jti"]}, headers=headers)
    assert resp.status_code == 200
    assert resp.json().get("revoked") == 1


@pytest.mark.anyio
async def test_admin_revoke_others_and_all(db_session: AsyncSession, client_admin_sessions: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    # Seed 3 sessions
    r_keep = await create_refresh_token(user_id=admin.id)
    await store_refresh_token(db=db_session, user_id=admin.id, token=r_keep["token"], jti=r_keep["jti"], expires_at=r_keep["expires_at"], parent_jti=r_keep.get("parent_jti"), ip_address=None)
    for _ in range(2):
        r = await create_refresh_token(user_id=admin.id)
        await store_refresh_token(db=db_session, user_id=admin.id, token=r["token"], jti=r["jti"], expires_at=r["expires_at"], parent_jti=r.get("parent_jti"), ip_address=None)

    headers = await _access_headers_for(admin, session_id=r_keep["jti"])  # mark as current
    # Revoke others
    resp = await client_admin_sessions.post("/api/v1/admin/sessions/revoke-others", headers=headers)
    assert resp.status_code == 200

    # Global sign-out
    resp = await client_admin_sessions.post("/api/v1/admin/sessions/revoke-all", headers=headers)
    assert resp.status_code == 200
    assert resp.json().get("revoked") == "all"

