# tests/test_admin/test_admin_cdn_delivery.py
from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI
from typing import AsyncGenerator, Dict

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.routers import admin_assets as admin_assets_router
from app.db.session import get_async_db
from tests.fixtures.db import get_override_get_db
from tests.utils.factory import create_user
from app.core.security import create_access_token
from app.schemas.enums import OrgRole

# no real CloudFront; queue path used
class _FakeRW:
    def __init__(self): self._list=[]
    async def idempotency_get(self,k): return None
    async def idempotency_set(self,k,v,ttl_seconds=600): return True
    async def json_set(self, *a, **k): return True
    async def json_get(self, *a, **k): return None
    @property
    def client(self):
        parent = self
        class _C:
            async def rpush(self, key, *vals): parent._list.extend(vals); return len(parent._list)
        return _C()

class _FakeS3:
    bucket="ut"
    def presigned_get(self, key, expires_in=300, response_content_disposition=None): return f"https://get/{key}"
    def presigned_put(self, *a, **k): return "https://put/x"
    def delete(self, *a, **k): return True
    def put_bytes(self, *a, **k): return True
    @property
    def client(self):
        class _C: pass
        return _C()

async def _hdrs(uid: str) -> Dict[str, str]:
    tok = await create_access_token(user_id=uid, mfa_authenticated=True)
    return {"Authorization": f"Bearer {tok}"}

@pytest.fixture()
async def app_admin_cdn(db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    app = FastAPI()
    app.include_router(admin_assets_router.router, prefix="/api/v1/admin")
    app.dependency_overrides[get_async_db] = get_override_get_db(db_session)
    monkeypatch.setattr(admin_assets_router, "redis_wrapper", _FakeRW(), raising=True)
    monkeypatch.setattr(admin_assets_router, "_ensure_s3", lambda: _FakeS3(), raising=True)
    # force queue path (no CloudFront)
    monkeypatch.delenv("CLOUDFRONT_DISTRIBUTION_ID", raising=False)
    return app

@pytest.fixture()
async def client_admin_cdn(app_admin_cdn: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(transport=ASGITransport(app=app_admin_cdn), base_url="http://test") as client:
        yield client

@pytest.mark.anyio
async def test_cdn_invalidate_and_delivery(db_session: AsyncSession, client_admin_cdn: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.SUPERUSER, is_verified=True, is_active=True)
    h = await _hdrs(str(admin.id))

    # CDN invalidate queues
    payload = {"paths": ["/a/b.m3u8"], "prefixes": ["videos/abc"]}
    r = await client_admin_cdn.post("/api/v1/admin/cdn/invalidate", json=payload, headers=h)
    assert r.status_code == 200
    assert r.json()["status"] in ("QUEUED","SUBMITTED")

    # Signed URL (GET)
    r = await client_admin_cdn.post("/api/v1/admin/delivery/signed-url", json={"storage_key":"videos/file.m3u8","expires_in":300}, headers=h)
    assert r.status_code == 200 and "url" in r.json()

    # One-time download token
    r = await client_admin_cdn.post("/api/v1/admin/delivery/download-token", json={"storage_key":"premium/4k.iso","ttl_seconds":600}, headers=h)
    assert r.status_code == 200 and "token" in r.json()
