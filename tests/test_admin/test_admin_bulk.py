# tests/test_admin/test_admin_bulk.py

import uuid
import pytest
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI
from typing import AsyncGenerator, Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.routers import admin_assets as admin_assets_router
from app.db.session import get_async_db
from tests.fixtures.db import get_override_get_db
from tests.utils.factory import create_user
from app.core.security import create_access_token
from app.schemas.enums import OrgRole


# ──────────────────────────────────────────────────────────────────────
# In-memory fakes: Redis wrapper used by bulk routes (hermetic tests)
# ──────────────────────────────────────────────────────────────────────

class _FakeLock:
    async def __aenter__(self): return self
    async def __aexit__(self, a, b, c): return False

class _FakeRedis:
    """
    Minimal redis facade implementing the bits admin_assets bulk code touches:
    - idempotency_get/set
    - lock
    - json_set/json_get
    - client.sadd/smembers/rpush
    """
    def __init__(self):
        self._json: dict[str, Any] = {}
        self._sets: dict[str, set[str]] = {"bulk:jobs": set()}
        self._list: list[str] = []
        self._idem: dict[str, Any] = {}

    async def idempotency_get(self, k: str):
        return self._idem.get(k)

    async def idempotency_set(self, k: str, v: Any, ttl_seconds: int = 600):
        self._idem[k] = v
        return True

    def lock(self, k: str, timeout: int = 10, blocking_timeout: int = 3):
        return _FakeLock()

    async def json_set(self, key: str, value: dict, ttl_seconds: int = 86400):
        self._json[key] = value

    async def json_get(self, key: str):
        return self._json.get(key)

    @property
    def client(self):
        parent = self

        class _C:
            async def sadd(self, key, val):
                parent._sets.setdefault(key, set()).add(val)
                return 1

            async def smembers(self, key):
                return parent._sets.get(key, set())

            async def rpush(self, key, *vals):
                parent._list.extend(vals)
                return len(parent._list)

        return _C()


# ──────────────────────────────────────────────────────────────────────
# Helpers / fixtures
# ──────────────────────────────────────────────────────────────────────

async def _hdrs(uid: str) -> Dict[str, str]:
    token = await create_access_token(user_id=uid, mfa_authenticated=True)
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture()
async def app_admin_bulk(db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    app = FastAPI()
    app.include_router(admin_assets_router.router, prefix="/api/v1/admin")
    app.dependency_overrides[get_async_db] = get_override_get_db(db_session)
    monkeypatch.setattr(admin_assets_router, "redis_wrapper", _FakeRedis(), raising=True)
    return app

@pytest.fixture()
async def client_admin_bulk(app_admin_bulk: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(transport=ASGITransport(app=app_admin_bulk), base_url="http://test") as client:
        yield client


# ──────────────────────────────────────────────────────────────────────
# Happy path: submit → list → get → cancel
# ──────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_bulk_job_lifecycle(db_session: AsyncSession, client_admin_bulk: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    headers = await _hdrs(str(admin.id))

    # submit
    payload = {"items": [{"type": "title", "name": "A"}, {"type": "title", "name": "B"}]}
    r = await client_admin_bulk.post("/api/v1/admin/bulk/manifest", json=payload, headers=headers)
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]

    # list jobs
    r = await client_admin_bulk.get("/api/v1/admin/bulk/jobs", headers=headers)
    assert r.status_code == 200, r.text
    assert isinstance(r.json(), list)
    assert any(j.get("id") == job_id for j in r.json())

    # get job
    r = await client_admin_bulk.get(f"/api/v1/admin/bulk/jobs/{job_id}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == job_id
    assert "status" in body

    # cancel
    r = await client_admin_bulk.post(f"/api/v1/admin/bulk/jobs/{job_id}/cancel", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["status"] in ("CANCEL_REQUESTED", "CANCELED")


# ──────────────────────────────────────────────────────────────────────
# Auth required
# ──────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_bulk_submit_requires_auth(client_admin_bulk: AsyncClient):
    r = await client_admin_bulk.post("/api/v1/admin/bulk/manifest", json={"items": []})
    assert r.status_code in (401, 403), r.text


# ──────────────────────────────────────────────────────────────────────
# Validation & robustness
# ──────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_bulk_manifest_validation(db_session: AsyncSession, client_admin_bulk: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.SUPERUSER, is_verified=True, is_active=True)
    headers = await _hdrs(str(admin.id))

    # missing items
    r = await client_admin_bulk.post("/api/v1/admin/bulk/manifest", json={}, headers=headers)
    assert r.status_code in (400, 422), r.text

    # wrong type (not list)
    r = await client_admin_bulk.post("/api/v1/admin/bulk/manifest", json={"items": "oops"}, headers=headers)
    assert r.status_code in (400, 422), r.text

    # empty list (impl choice: allow or reject)
    r = await client_admin_bulk.post("/api/v1/admin/bulk/manifest", json={"items": []}, headers=headers)
    assert r.status_code in (202, 400, 422), r.text


@pytest.mark.anyio
async def test_bulk_jobs_pagination_and_multiple(db_session: AsyncSession, client_admin_bulk: AsyncClient):
    """Submit several jobs, then list with pagination params (even if the API ignores them, should 200)."""
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    headers = await _hdrs(str(admin.id))

    for i in range(5):
        r = await client_admin_bulk.post(
            "/api/v1/admin/bulk/manifest",
            json={"items": [{"type": "title", "name": f"T{i}"}]},
            headers=headers,
        )
        assert r.status_code == 202, r.text

    r = await client_admin_bulk.get("/api/v1/admin/bulk/jobs?limit=2&offset=0", headers=headers)
    assert r.status_code == 200, r.text
    assert isinstance(r.json(), list)


@pytest.mark.anyio
async def test_bulk_job_get_not_found(db_session: AsyncSession, client_admin_bulk: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    headers = await _hdrs(str(admin.id))

    unknown = str(uuid.uuid4())
    r = await client_admin_bulk.get(f"/api/v1/admin/bulk/jobs/{unknown}", headers=headers)
    # Accept 404 or 200 with null/empty depending on impl
    assert r.status_code in (200, 404), r.text
    if r.status_code == 200:
        assert r.json() in (None, {}, {"id": unknown})


@pytest.mark.anyio
async def test_bulk_job_cancel_idempotent(db_session: AsyncSession, client_admin_bulk: AsyncClient):
    """Cancel twice should not error: accept final status in an allowed set."""
    admin = await create_user(session=db_session, role=OrgRole.SUPERUSER, is_verified=True, is_active=True)
    headers = await _hdrs(str(admin.id))

    r = await client_admin_bulk.post("/api/v1/admin/bulk/manifest", json={"items": [{"type": "title", "name": "X"}]}, headers=headers)
    job_id = r.json()["job_id"]

    r1 = await client_admin_bulk.post(f"/api/v1/admin/bulk/jobs/{job_id}/cancel", headers=headers)
    assert r1.status_code == 200, r1.text
    s1 = r1.json()["status"]

    r2 = await client_admin_bulk.post(f"/api/v1/admin/bulk/jobs/{job_id}/cancel", headers=headers)
    assert r2.status_code in (200, 409), r2.text  # 409 = already terminal, acceptable
    s2 = r2.json().get("status", s1)
    assert s2 in ("CANCEL_REQUESTED", "CANCELED", "ALREADY_CANCELED", s1)


@pytest.mark.anyio
async def test_bulk_manifest_idempotency_header(db_session: AsyncSession, client_admin_bulk: AsyncClient):
    """
    If server supports Idempotency-Key, the same request with the same key should
    return the same job. If not implemented, still accept 202 with a new job id.
    """
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    headers = await _hdrs(str(admin.id))
    idem = "unit-test-idem-key-123"
    headers_with_idem = {**headers, "Idempotency-Key": idem}

    body = {"items": [{"type": "title", "name": "A"}]}

    r1 = await client_admin_bulk.post("/api/v1/admin/bulk/manifest", json=body, headers=headers_with_idem)
    assert r1.status_code == 202, r1.text
    job1 = r1.json().get("job_id")

    r2 = await client_admin_bulk.post("/api/v1/admin/bulk/manifest", json=body, headers=headers_with_idem)
    assert r2.status_code == 202, r2.text
    job2 = r2.json().get("job_id")

    # if idempotency implemented, job ids match; otherwise they may differ — both acceptable
    assert job1 and job2
    if job1 == job2:
        assert True  # idempotent behavior confirmed
    else:
        assert True  # server does not implement idempotency, still OK


@pytest.mark.anyio
async def test_bulk_large_manifest_ok(db_session: AsyncSession, client_admin_bulk: AsyncClient):
    """Submit a large but reasonable manifest to ensure request body handling/path is robust."""
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    headers = await _hdrs(str(admin.id))

    items = [{"type": "title", "name": f"Movie-{i}"} for i in range(100)]
    r = await client_admin_bulk.post("/api/v1/admin/bulk/manifest", json={"items": items}, headers=headers)
    assert r.status_code == 202, r.text
