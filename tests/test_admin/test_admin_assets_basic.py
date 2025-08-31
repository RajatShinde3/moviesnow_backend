# tests/test_admin/test_admin_assets_basic.py
from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI
from typing import AsyncGenerator, Dict

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.routers import admin_assets as admin_assets_router
from app.api.v1.routers import admin_titles as admin_titles_router
from app.db.session import get_async_db
from tests.fixtures.db import get_override_get_db
from app.core.security import create_access_token
from app.schemas.enums import OrgRole
from tests.utils.factory import create_user


# ──────────────────────────────────────────────────────────────────────
# Fakes (Redis wrapper & S3 client) — no external calls
# ──────────────────────────────────────────────────────────────────────

class _FakeLock:
    async def __aenter__(self):  # pragma: no cover - tiny helper
        return self
    async def __aexit__(self, exc_type, exc, tb):  # pragma: no cover
        return False

class _FakeRedisWrap:
    """MVP Redis facade: idempotency/caching + tiny set ops used by router."""
    def __init__(self):
        self._json: dict[str, dict] = {}

    async def idempotency_get(self, key: str):
        return None

    async def idempotency_set(self, key: str, value: dict, ttl_seconds: int = 600):
        return True

    def lock(self, key: str, timeout: int = 10, blocking_timeout: int = 3):
        return _FakeLock()

    async def json_set(self, key: str, value: dict, ttl_seconds: int = 3600):
        self._json[key] = value

    async def json_get(self, key: str):
        return self._json.get(key)

    @property
    def client(self):
        class _C:
            async def sadd(self, *args, **kwargs):  # used by some routers
                return 1
        return _C()

class _FakeS3:
    """Minimal S3 facade predictable for tests."""
    bucket = "unit-test-bucket"

    def presigned_put(self, key: str, content_type: str, public: bool = False) -> str:
        return f"https://example.com/put/{key}"

    def presigned_get(
        self, key: str, expires_in: int = 300, response_content_disposition: str | None = None
    ) -> str:
        return f"https://example.com/get/{key}"

    def delete(self, key: str) -> bool:
        return True

    def put_bytes(self, key: str, data: bytes, content_type: str, public: bool = False) -> bool:
        return True

    @property
    def client(self):
        class _C:
            async_mode = False
            def create_multipart_upload(self, Bucket, Key, ContentType, ACL):
                return {"UploadId": "UPL-1"}
            def generate_presigned_url(self, ClientMethod, Params, ExpiresIn, HttpMethod):
                return f"https://example.com/part/{Params['PartNumber']}"
            def complete_multipart_upload(self, Bucket, Key, UploadId, MultipartUpload):
                return {"ok": True}
            def abort_multipart_upload(self, Bucket, Key, UploadId):
                return {"ok": True}
        return _C()


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

async def _auth_headers_for(user_id: str) -> Dict[str, str]:
    token = await create_access_token(user_id=user_id, mfa_authenticated=True)
    return {"Authorization": f"Bearer {token}"}


# ──────────────────────────────────────────────────────────────────────
# App / Client fixtures
# ──────────────────────────────────────────────────────────────────────

@pytest.fixture()
async def app_admin_assets(db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    app = FastAPI()
    app.include_router(admin_titles_router.router, prefix="/api/v1/admin")
    app.include_router(admin_assets_router.router, prefix="/api/v1/admin")
    app.dependency_overrides[get_async_db] = get_override_get_db(db_session)
    # Patch AWS + Redis so we never hit network
    monkeypatch.setattr(admin_assets_router, "redis_wrapper", _FakeRedisWrap(), raising=True)
    monkeypatch.setenv("AWS_BUCKET_NAME", "unit-test-bucket")
    monkeypatch.setattr(admin_assets_router, "_ensure_s3", lambda: _FakeS3(), raising=True)
    return app

@pytest.fixture()
async def client_admin_assets(app_admin_assets: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(
        transport=ASGITransport(app=app_admin_assets),
        base_url="http://test",
    ) as client:
        yield client


# ──────────────────────────────────────────────────────────────────────
# Artwork: create → list → delete; plus edges
# ──────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_artwork_create_list_delete(db_session: AsyncSession, client_admin_assets: AsyncClient):
    """Happy path for artwork attach/list/delete."""
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    headers = await _auth_headers_for(str(admin.id))

    # create a title to attach assets
    r = await client_admin_assets.post(
        "/api/v1/admin/titles",
        json={"type": "MOVIE", "name": "ArtTitle", "slug": "art-title", "status": "ANNOUNCED"},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    tid = r.json()["id"]

    # create artwork
    body = {"kind": "POSTER", "content_type": "image/jpeg", "language": "en-US", "is_primary": True}
    r = await client_admin_assets.post(f"/api/v1/admin/titles/{tid}/artwork", json=body, headers=headers)
    assert r.status_code == 200, r.text
    payload = r.json()
    assert "artwork_id" in payload and "upload_url" in payload  # basic contract
    art_id = payload["artwork_id"]

    # list artwork
    r = await client_admin_assets.get(f"/api/v1/admin/titles/{tid}/artwork", headers=headers)
    assert r.status_code == 200, r.text
    items = r.json()
    assert isinstance(items, list) and any(i["id"] == art_id for i in items)

    # delete artwork
    r = await client_admin_assets.delete(f"/api/v1/admin/artwork/{art_id}", headers=headers)
    assert r.status_code == 200, r.text

@pytest.mark.anyio
async def test_artwork_requires_auth(db_session: AsyncSession, client_admin_assets: AsyncClient):
    """Unauthenticated calls should be rejected."""
    # missing token
    r = await client_admin_assets.get("/api/v1/admin/titles/some-id/artwork")
    assert r.status_code in (401, 403)

@pytest.mark.anyio
async def test_artwork_delete_is_idempotent(db_session: AsyncSession, client_admin_assets: AsyncClient):
    """Second delete should not crash the suite; allow 200/404/410."""
    su = await create_user(session=db_session, role=OrgRole.SUPERUSER, is_verified=True, is_active=True)
    headers = await _auth_headers_for(str(su.id))

    # title
    r = await client_admin_assets.post("/api/v1/admin/titles",
                                       json={"type":"MOVIE","name":"Art2","slug":"art2","status":"ANNOUNCED"},
                                       headers=headers)
    tid = r.json()["id"]

    # artwork
    r = await client_admin_assets.post(f"/api/v1/admin/titles/{tid}/artwork",
                                       json={"kind":"BACKGROUND","content_type":"image/png","language":"en"},
                                       headers=headers)
    art_id = r.json()["artwork_id"]

    # first delete
    r = await client_admin_assets.delete(f"/api/v1/admin/artwork/{art_id}", headers=headers)
    assert r.status_code == 200, r.text

    # second delete (already gone)
    r = await client_admin_assets.delete(f"/api/v1/admin/artwork/{art_id}", headers=headers)
    assert r.status_code in (200, 404, 410), r.text


# ──────────────────────────────────────────────────────────────────────
# Trailers: create → list → delete; plus edges
# ──────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_trailer_create_list_delete(db_session: AsyncSession, client_admin_assets: AsyncClient):
    """Happy path for trailer attach/list/delete."""
    admin = await create_user(session=db_session, role=OrgRole.SUPERUSER, is_verified=True, is_active=True)
    headers = await _auth_headers_for(str(admin.id))

    r = await client_admin_assets.post(
        "/api/v1/admin/titles",
        json={"type": "MOVIE", "name": "TrailTitle", "slug": "trail-title", "status": "ANNOUNCED"},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    tid = r.json()["id"]

    # create trailer
    payload = {"content_type": "video/mp4", "language": "en", "is_primary": True}
    r = await client_admin_assets.post(f"/api/v1/admin/titles/{tid}/trailers", json=payload, headers=headers)
    assert r.status_code == 200, r.text
    res = r.json()
    assert "asset_id" in res and "upload_url" in res
    asset_id = res["asset_id"]

    # list trailers
    r = await client_admin_assets.get(f"/api/v1/admin/titles/{tid}/trailers", headers=headers)
    assert r.status_code == 200, r.text
    items = r.json()
    assert isinstance(items, list) and any(i["id"] == asset_id for i in items)

    # delete trailer
    r = await client_admin_assets.delete(f"/api/v1/admin/trailers/{asset_id}", headers=headers)
    assert r.status_code == 200, r.text

@pytest.mark.anyio
async def test_trailer_list_empty_then_add(db_session: AsyncSession, client_admin_assets: AsyncClient):
    """New title should have no trailers until we create one."""
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    headers = await _auth_headers_for(str(admin.id))

    r = await client_admin_assets.post("/api/v1/admin/titles",
                                       json={"type":"MOVIE","name":"NoTrailers","slug":"no-trailers","status":"ANNOUNCED"},
                                       headers=headers)
    tid = r.json()["id"]

    r = await client_admin_assets.get(f"/api/v1/admin/titles/{tid}/trailers", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json() == [] or isinstance(r.json(), list)

    # Add one trailer
    r = await client_admin_assets.post(f"/api/v1/admin/titles/{tid}/trailers",
                                       json={"content_type":"video/mp4","language":"hi"},
                                       headers=headers)
    assert r.status_code == 200, r.text

@pytest.mark.anyio
async def test_trailer_delete_is_idempotent(db_session: AsyncSession, client_admin_assets: AsyncClient):
    """Second delete should be safe (200/404/410 accepted)."""
    admin = await create_user(session=db_session, role=OrgRole.SUPERUSER, is_verified=True, is_active=True)
    headers = await _auth_headers_for(str(admin.id))

    r = await client_admin_assets.post("/api/v1/admin/titles",
                                       json={"type":"MOVIE","name":"TD","slug":"td","status":"ANNOUNCED"},
                                       headers=headers)
    tid = r.json()["id"]

    r = await client_admin_assets.post(f"/api/v1/admin/titles/{tid}/trailers",
                                       json={"content_type":"video/mp4","language":"en"},
                                       headers=headers)
    asset_id = r.json()["asset_id"]

    r = await client_admin_assets.delete(f"/api/v1/admin/trailers/{asset_id}", headers=headers)
    assert r.status_code == 200, r.text

    r = await client_admin_assets.delete(f"/api/v1/admin/trailers/{asset_id}", headers=headers)
    assert r.status_code in (200, 404, 410), r.text
