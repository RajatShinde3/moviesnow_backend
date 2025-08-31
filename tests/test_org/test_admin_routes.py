from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI
from typing import AsyncGenerator
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.routers.orgs import admin as admin_router
from app.db.session import get_async_db
from tests.fixtures.db import get_override_get_db
from app.core.security import create_access_token
from app.schemas.enums import OrgRole
from app.db.models.user import User
from tests.utils.factory import create_user


@pytest.fixture()
async def app_org_admin(db_session: AsyncSession) -> FastAPI:
    app = FastAPI()
    app.include_router(admin_router.router, prefix="/api/v1/users")
    app.dependency_overrides[get_async_db] = get_override_get_db(db_session)
    return app


@pytest.fixture()
async def client_org_admin(app_org_admin: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(transport=ASGITransport(app=app_org_admin), base_url="http://test") as client:
        yield client


async def _auth_headers_for(user: User, *, mfa: bool = True) -> dict[str, str]:
    token = await create_access_token(user_id=str(user.id), mfa_authenticated=mfa)
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.anyio
async def test_assign_admin_success_and_idempotent(db_session: AsyncSession, client_org_admin: AsyncClient):
    actor = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    target = await create_user(session=db_session, role=OrgRole.USER, is_verified=True, is_active=True)
    headers = await _auth_headers_for(actor)
    key = uuid4().hex

    # First call assigns ADMIN
    resp = await client_org_admin.put(f"/api/v1/users/{target.id}/assign-ADMIN", headers={**headers, "Idempotency-Key": key})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data.get("role") == "OrgRole.ADMIN" or data.get("role") == "ADMIN"  # serialization may vary

    # Second call hits idempotency cache
    resp2 = await client_org_admin.put(f"/api/v1/users/{target.id}/assign-ADMIN", headers={**headers, "Idempotency-Key": key})
    assert resp2.status_code == 200


@pytest.mark.anyio
async def test_revoke_admin_success(db_session: AsyncSession, client_org_admin: AsyncClient):
    actor = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    target = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    headers = await _auth_headers_for(actor)

    resp = await client_org_admin.put(f"/api/v1/users/{target.id}/revoke-ADMIN", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("role") == "OrgRole.USER" or data.get("role") == "USER"


@pytest.mark.anyio
async def test_list_admins_pagination(db_session: AsyncSession, client_org_admin: AsyncClient):
    actor = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    headers = await _auth_headers_for(actor)
    # Seed a couple ADMIN users
    for _ in range(3):
        await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)

    resp = await client_org_admin.get("/api/v1/users/admins?limit=2&offset=0", headers=headers)
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    assert len(items) <= 2
