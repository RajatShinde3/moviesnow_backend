
import pytest
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI
from typing import AsyncGenerator, Dict
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.routers import admin_taxonomy as admin_tax_router
from app.api.v1.routers import admin_titles as admin_titles_router
from app.db.session import get_async_db
from tests.fixtures.db import get_override_get_db
from app.core.security import create_access_token
from app.schemas.enums import OrgRole, TitleType
from tests.utils.factory import create_user
from app.db.models.person import Person
from app.db.models.title import Title

# ───────── fakes (redis wrapper) ─────────

class _Lock:
    async def __aenter__(self): return self
    async def __aexit__(self, a,b,c): return False

class _FakeRW:
    def __init__(self):
        self._json = {}
        self._idem = {}
    async def idempotency_get(self,k): return self._idem.get(k)
    async def idempotency_set(self,k,v,ttl_seconds=600): self._idem[k]=v
    def lock(self, key, timeout=10, blocking_timeout=3): return _Lock()
    async def json_set(self, key, value, ttl_seconds=300): self._json[key]=value
    async def json_get(self, key): return self._json.get(key)
    @property
    def client(self):
        class _C: pass
        return _C()

async def _auth(uid:str)->Dict[str,str]:
    tok = await create_access_token(user_id=uid, mfa_authenticated=True)
    return {"Authorization": f"Bearer {tok}"}

# ───────── app/client fixtures ─────────

@pytest.fixture()
async def app_taxonomy(db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    app = FastAPI()
    # include titles (to create Title) + taxonomy
    app.include_router(admin_titles_router.router, prefix="/api/v1/admin")
    app.include_router(admin_tax_router.router, prefix="/api/v1/admin")
    app.dependency_overrides[get_async_db] = get_override_get_db(db_session)
    # patch redis wrapper
    monkeypatch.setattr(admin_tax_router, "redis_wrapper", _FakeRW(), raising=True)
    return app

@pytest.fixture()
async def client_taxonomy(app_taxonomy: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(transport=ASGITransport(app=app_taxonomy), base_url="http://test") as client:
        yield client

# ───────── tests: genres ─────────

@pytest.mark.anyio
async def test_genres_create_idempotent_list_patch_delete(db_session: AsyncSession, client_taxonomy: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    h = await _auth(str(admin.id))

    # create (with Idempotency-Key)
    body = {"name":"Action","slug":"action","description":"A","is_active":True}
    headers = {**h, "Idempotency-Key":"req-1"}
    r1 = await client_taxonomy.post("/api/v1/admin/genres", json=body, headers=headers)
    assert r1.status_code == 200, r1.text
    gid = r1.json()["id"]
    r2 = await client_taxonomy.post("/api/v1/admin/genres", json=body, headers=headers)
    assert r2.status_code == 200 and r2.json()["id"] == gid

    # list
    r = await client_taxonomy.get("/api/v1/admin/genres?q=act", headers=h)
    assert r.status_code == 200
    assert any(g["id"] == gid for g in r.json())

    # patch
    r = await client_taxonomy.patch(f"/api/v1/admin/genres/{gid}", json={"description":"Updated"}, headers=h)
    assert r.status_code == 200 and r.json()["description"] == "Updated"

    # delete
    r = await client_taxonomy.delete(f"/api/v1/admin/genres/{gid}", headers=h)
    assert r.status_code == 200

@pytest.mark.anyio
async def test_genre_attach_detach_title(db_session: AsyncSession, client_taxonomy: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.SUPERUSER, is_verified=True, is_active=True)
    h = await _auth(str(admin.id))

    # create title (series or movie is fine)
    r = await client_taxonomy.post("/api/v1/admin/titles", json={"type":"MOVIE","name":"GTitle","slug":"g-title","status":"ANNOUNCED"}, headers=h)
    assert r.status_code == 200, r.text
    tid = r.json()["id"]

    # create genre
    r = await client_taxonomy.post("/api/v1/admin/genres", json={"name":"Drama","slug":"drama"}, headers=h)
    gid = r.json()["id"]

    # attach (twice -> idempotent)
    ra = await client_taxonomy.post(f"/api/v1/admin/titles/{tid}/genres/{gid}", headers=h)
    assert ra.status_code == 200
    ra2 = await client_taxonomy.post(f"/api/v1/admin/titles/{tid}/genres/{gid}", headers=h)
    assert ra2.status_code == 200

    # detach (twice tolerated)
    rd = await client_taxonomy.delete(f"/api/v1/admin/titles/{tid}/genres/{gid}", headers=h)
    assert rd.status_code == 200
    rd2 = await client_taxonomy.delete(f"/api/v1/admin/titles/{tid}/genres/{gid}", headers=h)
    assert rd2.status_code == 200

# ───────── tests: credits ─────────

@pytest.mark.anyio
async def test_credits_crud(db_session: AsyncSession, client_taxonomy: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.ADMIN, is_verified=True, is_active=True)
    h = await _auth(str(admin.id))

    # create title + person
    r = await client_taxonomy.post("/api/v1/admin/titles", json={"type":"MOVIE","name":"CTitle","slug":"c-title","status":"ANNOUNCED"}, headers=h)
    tid = r.json()["id"]
    # insert a person directly
    p = Person(full_name="Ada Actor")
    db_session.add(p); await db_session.flush(); await db_session.commit()

    # create credit
    payload = {"person_id": str(p.id), "kind":"CAST", "role":"Lead", "character_name":"Ada"}
    r = await client_taxonomy.post(f"/api/v1/admin/titles/{tid}/credits", json=payload, headers=h)
    assert r.status_code == 200, r.text
    cid = r.json()["id"]

    # list credits (filter)
    r = await client_taxonomy.get(f"/api/v1/admin/titles/{tid}/credits?kind=cast", headers=h)
    assert r.status_code == 200 and any(c["id"] == cid for c in r.json())

    # patch
    r = await client_taxonomy.patch(f"/api/v1/admin/credits/{cid}", json={"credited_as":"A. Actor","is_voice":True}, headers=h)
    assert r.status_code == 200 and r.json()["credited_as"] == "A. Actor" and r.json()["is_voice"] is True

    # delete
    r = await client_taxonomy.delete(f"/api/v1/admin/credits/{cid}", headers=h)
    assert r.status_code == 200

# ───────── tests: compliance ─────────

@pytest.mark.anyio
async def test_compliance_block_and_dmca(db_session: AsyncSession, client_taxonomy: AsyncClient):
    admin = await create_user(session=db_session, role=OrgRole.SUPERUSER, is_verified=True, is_active=True)
    h = await _auth(str(admin.id))

    # create title
    r = await client_taxonomy.post("/api/v1/admin/titles", json={"type":"MOVIE","name":"CompTitle","slug":"comp-title","status":"ANNOUNCED","is_published":True}, headers=h)
    tid = r.json()["id"]

    # block (regions + unpublish)
    payload = {"regions":["us","IN"], "system":"OTHER", "min_age":18, "notes":"Mature", "unpublish": True}
    r = await client_taxonomy.post(f"/api/v1/admin/titles/{tid}/block", json=payload, headers=h)
    assert r.status_code == 200
    assert set(map(str.upper, r.json()["regions"])) == {"US","IN"}

    # dmca
    r = await client_taxonomy.post(f"/api/v1/admin/titles/{tid}/dmca", json={"reason":"Rights issue","source_url":"https://src"}, headers=h)
    assert r.status_code == 200 and r.json()["message"]

    # enums
    r = await client_taxonomy.get("/api/v1/admin/compliance/flags", headers=h)
    assert r.status_code == 200
    assert "certification_systems" in r.json()
