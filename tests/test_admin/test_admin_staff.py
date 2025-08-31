from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.routers import admin_staff as admin_staff_router
from app.api.v1.routers import admin_auth as admin_auth_router
from app.db.session import get_async_db
from tests.fixtures.db import get_override_get_db
from app.core.security import create_access_token
from app.schemas.enums import OrgRole
from app.db.models.user import User
from tests.utils.factory import create_user


@pytest.fixture()
async def app_admin_staff(db_session: AsyncSession) -> FastAPI:
    app = FastAPI()
    app.include_router(admin_staff_router.router, prefix="/api/v1/admin")
    app.include_router(admin_auth_router.router, prefix="/api/v1/admin")  # for /reauth
    app.dependency_overrides[get_async_db] = get_override_get_db(db_session)
    return app


@pytest.fixture()
async def client_admin_staff(app_admin_staff: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(transport=ASGITransport(app=app_admin_staff), base_url="http://test") as client:
        yield client


async def _auth_headers_for(user: User) -> dict[str, str]:
    token = await create_access_token(user_id=str(user.id), mfa_authenticated=True)
    return {"Authorization": f"Bearer {token}"}


async def _reauth_token(client: AsyncClient, admin_user: User) -> str:
    headers = await _auth_headers_for(admin_user)
    # Use password path for reauth
    r = await client.post("/api/v1/admin/reauth", json={"password": "password"}, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()["reauth_token"]


@pytest.mark.anyio
async def test_staff_list_filters(db_session: AsyncSession, client_admin_staff: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    su = await create_user(session=db_session, role=OrgRole.SUPERUSER, email="boss@example.com", is_verified=True, is_active=True)
    await create_user(session=db_session, role=OrgRole.USER, is_verified=True, is_active=True)

    headers = await _auth_headers_for(admin)
    # All staff
    resp = await client_admin_staff.get("/api/v1/admin/staff", headers=headers)
    assert resp.status_code == 200
    all_items = resp.json()
    assert any(i["id"] == str(su.id) for i in all_items)
    # Filter by role
    resp = await client_admin_staff.get("/api/v1/admin/staff?role=SUPERUSER", headers=headers)
    assert resp.status_code == 200
    items = resp.json()
    assert all(i["role"] == "UserRole.SUPERUSER" or i["role"] == "SUPERUSER" for i in items)
    # Filter by email contains
    resp = await client_admin_staff.get("/api/v1/admin/staff?email=boss", headers=headers)
    assert resp.status_code == 200
    items = resp.json()
    assert any(i["email"] == "boss@example.com" for i in items)


@pytest.mark.anyio
async def test_staff_superusers_cached(db_session: AsyncSession, client_admin_staff: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    await create_user(session=db_session, role=OrgRole.SUPERUSER, is_verified=True, is_active=True)
    headers = await _auth_headers_for(admin)
    resp1 = await client_admin_staff.get("/api/v1/admin/staff/superusers", headers=headers)
    assert resp1.status_code == 200
    resp2 = await client_admin_staff.get("/api/v1/admin/staff/superusers", headers=headers)
    assert resp2.status_code == 200


@pytest.mark.anyio
async def test_staff_admins_list(db_session: AsyncSession, client_admin_staff: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    headers = await _auth_headers_for(admin)
    resp = await client_admin_staff.get("/api/v1/admin/staff/admins?limit=2&offset=0", headers=headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.anyio
async def test_promote_demote_and_admin_grant_remove(db_session: AsyncSession, client_admin_staff: AsyncClient):
    actor = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    target = await create_user(session=db_session, role=OrgRole.USER, is_verified=True, is_active=True)
    headers = await _auth_headers_for(actor)
    reauth = await _reauth_token(client_admin_staff, actor)

    # Promote user -> SUPERUSER
    resp = await client_admin_staff.post(f"/api/v1/admin/staff/{target.id}/promote", json={"reauth_token": reauth}, headers=headers)
    assert resp.status_code == 200
    assert resp.json().get("role") in ("UserRole.SUPERUSER", "SUPERUSER")

    # make-admin on superuser without allow_demotion -> 400
    resp = await client_admin_staff.post(f"/api/v1/admin/staff/{target.id}/make-admin", json={"reauth_token": reauth}, headers=headers)
    assert resp.status_code == 400
    # with allow_demotion -> success to ADMIN
    resp = await client_admin_staff.post(f"/api/v1/admin/staff/{target.id}/make-admin", json={"reauth_token": reauth, "allow_demotion": True}, headers=headers)
    assert resp.status_code == 200
    assert resp.json().get("role") in ("UserRole.ADMIN", "ADMIN")

    # remove-admin -> USER
    resp = await client_admin_staff.post(f"/api/v1/admin/staff/{target.id}/remove-admin", json={"reauth_token": reauth}, headers=headers)
    assert resp.status_code == 200
    assert resp.json().get("role") in ("UserRole.USER", "USER")

    # promote again to SUPERUSER for demotion test
    await client_admin_staff.post(f"/api/v1/admin/staff/{target.id}/promote", json={"reauth_token": reauth}, headers=headers)
    # Demote superuser -> USER
    resp = await client_admin_staff.post(f"/api/v1/admin/staff/{target.id}/demote", json={"reauth_token": reauth}, headers=headers)
    assert resp.status_code == 200
    assert resp.json().get("role") in ("UserRole.USER", "USER")


@pytest.mark.anyio
async def test_admin_users_crud_flags_sessions(db_session: AsyncSession, client_admin_staff: AsyncClient):
    actor = await create_user(session=db_session, role=OrgRole.SUPERUSER, is_verified=True, is_active=True)
    u = await create_user(session=db_session, role=OrgRole.USER, is_verified=False, is_active=True)
    headers = await _auth_headers_for(actor)
    reauth = await _reauth_token(client_admin_staff, actor)

    # list with email filter
    resp = await client_admin_staff.get(f"/api/v1/admin/users?email={u.email[:5]}", headers=headers)
    assert resp.status_code == 200

    # get by id
    resp = await client_admin_staff.get(f"/api/v1/admin/users/{u.id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["id"] == str(u.id)

    # patch flags requires reauth
    resp = await client_admin_staff.patch(f"/api/v1/admin/users/{u.id}", json={"is_verified": True, "reauth_token": reauth}, headers=headers)
    assert resp.status_code == 200
    assert resp.json().get("is_active") is True

    # deactivate requires reauth
    resp = await client_admin_staff.post(f"/api/v1/admin/users/{u.id}/deactivate", json={"reauth_token": reauth}, headers=headers)
    assert resp.status_code == 200

    # reactivate
    resp = await client_admin_staff.post(f"/api/v1/admin/users/{u.id}/reactivate", headers=headers)
    assert resp.status_code == 200

    # sessions listing (empty likely ok)
    resp = await client_admin_staff.get(f"/api/v1/admin/users/{u.id}/sessions", headers=headers)
    assert resp.status_code == 200

    # revoke all sessions for user
    resp = await client_admin_staff.post(f"/api/v1/admin/users/{u.id}/sessions/revoke-all", headers=headers)
    assert resp.status_code == 200

    # delete user (reauth)
    resp = await client_admin_staff.delete(f"/api/v1/admin/users/{u.id}", json={"reauth_token": reauth}, headers=headers)
    assert resp.status_code == 200

