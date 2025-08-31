from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI
from typing import AsyncGenerator
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.routers.orgs import management as mgmt_router
from app.db.session import get_async_db
from tests.fixtures.db import get_override_get_db
from app.core.security import create_access_token
from app.schemas.enums import OrgRole
from app.db.models.user import User
from tests.utils.factory import create_user


@pytest.fixture()
async def app_org(db_session: AsyncSession) -> FastAPI:
    app = FastAPI()
    app.include_router(mgmt_router.router, prefix="/api/v1/users")
    app.dependency_overrides[get_async_db] = get_override_get_db(db_session)
    return app


@pytest.fixture()
async def client_org(app_org: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(transport=ASGITransport(app=app_org), base_url="http://test") as client:
        yield client


async def _auth_headers_for(user: User, *, mfa: bool = True) -> dict[str, str]:
    token = await create_access_token(user_id=str(user.id), mfa_authenticated=mfa)
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.anyio
async def test_update_role_success_by_superuser(db_session: AsyncSession, client_org: AsyncClient):
    actor = await create_user(session=db_session, role=OrgRole.SUPERUSER, is_verified=True, is_active=True)
    target = await create_user(session=db_session, role=OrgRole.USER, is_verified=True, is_active=True)

    headers = await _auth_headers_for(actor)
    resp = await client_org.put(f"/api/v1/users/{target.id}/role", json={"role": "ADMIN"}, headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["message"].lower().startswith("user role updated") or data["message"].lower().startswith("user already")


@pytest.mark.anyio
async def test_update_role_forbidden_superuser_assign_by_admin(db_session: AsyncSession, client_org: AsyncClient):
    actor = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    target = await create_user(session=db_session, role=OrgRole.USER, is_verified=True, is_active=True)

    headers = await _auth_headers_for(actor)
    resp = await client_org.put(f"/api/v1/users/{target.id}/role", json={"role": "SUPERUSER"}, headers=headers)
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_update_role_self_change_denied(db_session: AsyncSession, client_org: AsyncClient):
    actor = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    headers = await _auth_headers_for(actor)
    resp = await client_org.put(f"/api/v1/users/{actor.id}/role", json={"role": "USER"}, headers=headers)
    assert resp.status_code == 400


@pytest.mark.anyio
async def test_deactivate_and_reactivate_user(db_session: AsyncSession, client_org: AsyncClient):
    actor = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    target = await create_user(session=db_session, role=OrgRole.USER, is_verified=True, is_active=True)
    headers = await _auth_headers_for(actor)

    # Deactivate
    resp = await client_org.put(f"/api/v1/users/{target.id}/deactivate", headers=headers)
    assert resp.status_code == 200
    # Reactivate
    resp = await client_org.put(f"/api/v1/users/{target.id}/reactivate", headers=headers)
    assert resp.status_code == 200
