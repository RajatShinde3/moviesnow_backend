# tests/test_live/test_stop_impersonation.py

import pytest
from httpx import AsyncClient
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone  # noqa: F401
from fastapi import FastAPI

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.models.revoked_token import RevokedToken
from app.schemas.enums import OrgRole

BASE = "/api/v1/course/live/security"  # keep aligned with your router mount


# ------------------------ helpers ------------------------

class _Token:
    """Tiny stand-in for TokenPayload with attribute access."""
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

def _make_impersonation_token(
    *, sub: UUID, org_id: UUID, impersonated_by: UUID,
    minutes=15, jti=None, include_session=False, token_type="access"
):
    now = datetime.now(timezone.utc)
    exp = int((now + timedelta(minutes=minutes)).timestamp())
    d = dict(
        sub=sub,                # user being impersonated
        org_id=str(org_id),
        is_impersonated=True,
        impersonated_by=str(impersonated_by),
        token_type=token_type,
        iat=int(now.timestamp()),
        exp=exp,
        jti=jti or str(uuid4()),
    )
    if include_session:
        d["session_id"] = str(uuid4())
    return _Token(**d)


# ------------------------ dependency override fixture (use FastAPI app) ------------------------

@pytest.fixture
def override_token_dep(app: FastAPI):
    """
    Override Depends(get_token_payload_model) to return our provided token object.
    Auto-cleans after each test.
    """
    from app.api.v1.course.live import security as sec

    def _apply(token_obj):
        async def fake_dep():  # <<< no *args/**kwargs
            return token_obj
        app.dependency_overrides[sec.get_token_payload_model] = fake_dep
        return sec  # module handle for further monkeypatches

    yield _apply
    app.dependency_overrides.clear()


# ------------------------ tests ------------------------

@pytest.mark.anyio
async def test_stop_impersonation__200_revokes_blacklists_and_clears(
    app: FastAPI, async_client: AsyncClient, db_session: AsyncSession,
    org_user_with_token, override_token_dep, monkeypatch
):
    actor, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    tok = _make_impersonation_token(
        sub=actor.id, org_id=org.id, impersonated_by=actor.id, minutes=20, include_session=True
    )
    sec = override_token_dep(tok)

    calls = {"bl": None, "del": None}

    async def fake_blacklist(jti, ttl_seconds):
        calls["bl"] = (jti, ttl_seconds)
        return True

    async def fake_delete_key(user_id, session_id):
        calls["del"] = (str(user_id), str(session_id))
        return True

    monkeypatch.setattr(sec, "_redis_blacklist_jti", fake_blacklist, raising=True)
    monkeypatch.setattr(sec, "_redis_delete_live_user_session_key", fake_delete_key, raising=True)

    r = await async_client.post(f"{BASE}/stop-impersonation", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["revoked_jti"] == tok.jti
    assert body["already_revoked"] is False
    assert body["user_id"] == str(tok.sub)
    assert body["impersonated_by"] == str(tok.impersonated_by)
    assert body.get("expires_at")

    q = await db_session.execute(select(RevokedToken).where(RevokedToken.jti == tok.jti).limit(1))
    row = q.scalars().first()
    assert row is not None and row.token_type == "impersonation"

    jti, ttl = calls["bl"]
    assert jti == tok.jti and ttl > 0
    assert calls["del"] == (str(tok.sub), tok.session_id)


@pytest.mark.anyio
async def test_stop_impersonation__200_idempotent_when_already_revoked(
    app: FastAPI, async_client: AsyncClient, db_session: AsyncSession,
    org_user_with_token, override_token_dep, monkeypatch
):
    actor, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    tok = _make_impersonation_token(sub=actor.id, org_id=org.id, impersonated_by=actor.id, minutes=10)

    db_session.add(RevokedToken(
        id=uuid4(),
        jti=tok.jti,
        token_type="impersonation",
        user_id=actor.id,
        revoked_by=actor.id,
        org_id=org.id,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        revoked_at=datetime.now(timezone.utc),
        reason="seed",
    ))
    await db_session.commit()

    sec = override_token_dep(tok)

    bl = {}
    async def fake_blacklist(jti, ttl_seconds):
        bl["args"] = (jti, ttl_seconds)
        return True

    monkeypatch.setattr(sec, "_redis_blacklist_jti", fake_blacklist, raising=True)

    r = await async_client.post(f"{BASE}/stop-impersonation", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["already_revoked"] is True
    assert bl["args"][0] == tok.jti and bl["args"][1] > 0


@pytest.mark.anyio
async def test_stop_impersonation__400_not_impersonating(
    app: FastAPI, async_client: AsyncClient, org_user_with_token, override_token_dep
):
    actor, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    tok = _Token(
        sub=actor.id,
        org_id=str(org.id),
        is_impersonated=False,
        impersonated_by=None,
        token_type="access",
        iat=int(datetime.now(timezone.utc).timestamp()),
        exp=int((datetime.now(timezone.utc) + timedelta(minutes=10)).timestamp()),
        jti=str(uuid4()),
    )
    override_token_dep(tok)

    r = await async_client.post(f"{BASE}/stop-impersonation", headers=headers)
    assert r.status_code == 400
    assert "not currently impersonating" in r.text.lower()


@pytest.mark.anyio
async def test_stop_impersonation__400_invalid_token_type(
    app: FastAPI, async_client: AsyncClient, org_user_with_token, override_token_dep
):
    actor, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    tok = _make_impersonation_token(
        sub=actor.id, org_id=org.id, impersonated_by=actor.id, minutes=10, token_type="refresh"
    )
    override_token_dep(tok)

    r = await async_client.post(f"{BASE}/stop-impersonation", headers=headers)
    assert r.status_code == 400
    assert "invalid token type" in r.text.lower()


@pytest.mark.anyio
async def test_stop_impersonation__400_missing_jti(
    app: FastAPI, async_client: AsyncClient, org_user_with_token, override_token_dep
):
    actor, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    tok = _make_impersonation_token(sub=actor.id, org_id=org.id, impersonated_by=actor.id, minutes=5)
    del tok.jti
    override_token_dep(tok)

    r = await async_client.post(f"{BASE}/stop-impersonation", headers=headers)
    assert r.status_code == 400
    assert "missing jti/exp" in r.text.lower()


@pytest.mark.anyio
async def test_stop_impersonation__400_invalid_exp(
    app: FastAPI, async_client: AsyncClient, org_user_with_token, override_token_dep
):
    actor, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    tok = _make_impersonation_token(sub=actor.id, org_id=org.id, impersonated_by=actor.id, minutes=5)
    tok.exp = "not-an-int"
    override_token_dep(tok)

    r = await async_client.post(f"{BASE}/stop-impersonation", headers=headers)
    assert r.status_code == 400
    assert "invalid exp" in r.text.lower()


@pytest.mark.anyio
async def test_stop_impersonation__audit_failure_does_not_block(
    app: FastAPI, async_client: AsyncClient, db_session: AsyncSession,
    org_user_with_token, override_token_dep, monkeypatch
):
    actor, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    tok = _make_impersonation_token(sub=actor.id, org_id=org.id, impersonated_by=actor.id, minutes=5)
    sec = override_token_dep(tok)

    async def boom(**kwargs):
        raise RuntimeError("audit down")

    monkeypatch.setattr(sec, "log_org_event", boom, raising=True)

    r = await async_client.post(f"{BASE}/stop-impersonation", headers=headers)
    assert r.status_code == 200, r.text
    q = await db_session.execute(select(RevokedToken).where(RevokedToken.jti == tok.jti))
    assert q.scalars().first() is not None


@pytest.mark.anyio
async def test_stop_impersonation__500_when_db_commit_fails(
    app: FastAPI, async_client: AsyncClient, db_session: AsyncSession,
    org_user_with_token, override_token_dep
):
    # Arrange
    actor, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    tok = _make_impersonation_token(sub=actor.id, org_id=org.id, impersonated_by=actor.id, minutes=5)

    # Return our token via dependency override
    from app.api.v1.course.live import security as sec
    async def token_dep():
        return tok
    app.dependency_overrides[sec.get_token_payload_model] = token_dep

    # Shim session that raises a non-IntegrityError during write
    class _BoomSession:
        def __init__(self, base: AsyncSession):
            self._base = base

        async def execute(self, *a, **k): return await self._base.execute(*a, **k)
        async def commit(self):           return await self._base.commit()
        async def rollback(self):         return await self._base.rollback()
        def add_all(self, *a, **k):       return self._base.add_all(*a, **k)

        def add(self, *_a, **_k):
            # Non-IntegrityError -> unhandled by the route
            raise RuntimeError("db down")

        def __getattr__(self, name):
            return getattr(self._base, name)

    async def db_dep():
        yield _BoomSession(db_session)

    app.dependency_overrides[sec.get_async_db] = db_dep

    # Act + Assert: FastAPI test app re-raises unhandled exceptions from the endpoint.
    with pytest.raises(RuntimeError, match="db down"):
        await async_client.post(f"{BASE}/stop-impersonation", headers=headers)

    # Clean up overrides
    app.dependency_overrides.clear()
