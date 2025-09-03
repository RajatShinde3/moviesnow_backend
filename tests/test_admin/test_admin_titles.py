
import pytest
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI
from typing import AsyncGenerator
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.routers import admin_titles as admin_titles_router
from app.db.session import get_async_db
from tests.fixtures.db import get_override_get_db
from app.core.security import create_access_token
from app.db.models.user import User
from tests.utils.factory import create_user
from app.schemas.enums import TitleType, TitleStatus, OrgRole


@pytest.fixture()
async def app_admin_titles(db_session: AsyncSession) -> FastAPI:
    app = FastAPI()
    app.include_router(admin_titles_router.router, prefix="/api/v1/admin")
    app.dependency_overrides[get_async_db] = get_override_get_db(db_session)
    return app


@pytest.fixture()
async def client_admin_titles(app_admin_titles: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(transport=ASGITransport(app=app_admin_titles), base_url="http://test") as client:
        yield client


async def _auth_headers_for(user: User) -> dict[str, str]:
    token = await create_access_token(user_id=str(user.id), mfa_authenticated=True)
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.anyio
async def test_create_list_get_patch_publish_delete_titles(db_session: AsyncSession, client_admin_titles: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    headers = await _auth_headers_for(admin)

    # Create (idempotent via Idempotency-Key)
    idem = {"Idempotency-Key": "tcreate-1"}
    body = {"type": "MOVIE", "name": "My Movie", "slug": "my-movie", "status": "ANNOUNCED"}
    resp = await client_admin_titles.post("/api/v1/admin/titles", json=body, headers={**headers, **idem})
    assert resp.status_code == 200, resp.text
    title = resp.json(); tid = title["id"]
    resp2 = await client_admin_titles.post("/api/v1/admin/titles", json=body, headers={**headers, **idem})
    assert resp2.status_code == 200

    # List with filters & sort
    resp = await client_admin_titles.get("/api/v1/admin/titles?type=MOVIE&status=ANNOUNCED&sort=-created_at", headers=headers)
    assert resp.status_code == 200
    items = resp.json(); assert any(i["id"] == tid for i in items)

    # Get by id
    resp = await client_admin_titles.get(f"/api/v1/admin/titles/{tid}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["id"] == tid

    # Patch
    resp = await client_admin_titles.patch(f"/api/v1/admin/titles/{tid}", json={"status": "RELEASED", "tagline": "Wow"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] in ("TitleStatus.RELEASED", "RELEASED")

    # Publish
    resp = await client_admin_titles.post(f"/api/v1/admin/titles/{tid}/publish", headers=headers)
    assert resp.status_code == 200
    # Unpublish
    resp = await client_admin_titles.post(f"/api/v1/admin/titles/{tid}/unpublish", headers=headers)
    assert resp.status_code == 200

    # Delete
    resp = await client_admin_titles.delete(f"/api/v1/admin/titles/{tid}", headers=headers)
    assert resp.status_code == 200

