# tests/test_admin/test_admin_uploads.py
from __future__ import annotations

import base64
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

# fakes
class _FakeLock:
    async def __aenter__(self): return self
    async def __aexit__(self, a,b,c): return False
class _FakeRW:
    def __init__(self): self._json={}
    async def idempotency_get(self,k): return None
    async def idempotency_set(self,k,v,ttl_seconds=600): return True
    def lock(self,k,timeout=10,blocking_timeout=3): return _FakeLock()
    async def json_set(self,k,v,ttl_seconds=3600): self._json[k]=v
    async def json_get(self,k): return self._json.get(k)
    @property
    def client(self):
        class _C:
            async def sadd(self, *a, **k): return 1
            async def smembers(self, *a, **k): return set()
            async def rpush(self, *a, **k): return 1
        return _C()
class _FakeS3:
    bucket = "ut"
    def presigned_put(self, key, content_type, public=False): return f"https://put/{key}"
    def presigned_get(self, key, expires_in=300, response_content_disposition=None): return f"https://get/{key}"
    def delete(self, key): return True
    def put_bytes(self, key, data, content_type, public=False): return True
    @property
    def client(self):
        class _C:
            def create_multipart_upload(self, **kw): return {"UploadId": "UPL"}
            def generate_presigned_url(self, **kw): return "https://part/1"
            def complete_multipart_upload(self, **kw): return {"ok": True}
            def abort_multipart_upload(self, **kw): return {"ok": True}
        return _C()

async def _hdrs(uid: str) -> Dict[str, str]:
    token = await create_access_token(user_id=uid, mfa_authenticated=True)
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture()
async def app_admin_uploads(db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    app = FastAPI()
    app.include_router(admin_assets_router.router, prefix="/api/v1/admin")
    app.dependency_overrides[get_async_db] = get_override_get_db(db_session)
    monkeypatch.setenv("AWS_BUCKET_NAME", "ut")
    monkeypatch.setattr(admin_assets_router, "_ensure_s3", lambda: _FakeS3(), raising=True)
    monkeypatch.setattr(admin_assets_router, "redis_wrapper", _FakeRW(), raising=True)
    return app

@pytest.fixture()
async def client_admin_uploads(app_admin_uploads: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(transport=ASGITransport(app=app_admin_uploads), base_url="http://test") as client:
        yield client

@pytest.mark.anyio
async def test_uploads_single_and_multipart_and_proxy(db_session: AsyncSession, client_admin_uploads: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    h = await _hdrs(str(admin.id))

    # single
    r = await client_admin_uploads.post("/api/v1/admin/uploads/init", json={"content_type":"image/png","key_prefix":"uploads/title","filename_hint":"poster"}, headers=h)
    assert r.status_code == 200 and "upload_url" in r.json()

    # multipart create
    r = await client_admin_uploads.post("/api/v1/admin/uploads/multipart/create", json={"content_type":"video/mp4","key_prefix":"uploads/multipart","filename_hint":"bigfile"}, headers=h)
    assert r.status_code == 200
    uploadId = r.json()["uploadId"]; key = r.json()["storage_key"]

    # part url
    r = await client_admin_uploads.get(f"/api/v1/admin/uploads/multipart/{uploadId}/part-url?key={key}&partNumber=1", headers=h)
    assert r.status_code == 200 and "upload_url" in r.json()

    # complete
    r = await client_admin_uploads.post(f"/api/v1/admin/uploads/multipart/{uploadId}/complete", json={"key": key, "parts":[{"ETag":"etag1","PartNumber":1}]}, headers=h)
    assert r.status_code == 200

    # abort (harmless after complete; endpoint should still respond OK/503 depending on impl)
    r = await client_admin_uploads.post(f"/api/v1/admin/uploads/multipart/{uploadId}/abort", json={"key": key}, headers=h)
    assert r.status_code in (200, 503)

    # direct proxy (small)
    data = base64.b64encode(b"hello").decode()
    r = await client_admin_uploads.post("/api/v1/admin/uploads/direct-proxy", json={"content_type":"text/plain","data_base64":data,"key_prefix":"uploads/direct","filename_hint":"note"}, headers=h)
    assert r.status_code == 200 and "storage_key" in r.json()
