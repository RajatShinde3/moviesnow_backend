# tests/test_live/test_token_status.py

import pytest
from httpx import AsyncClient
from uuid import uuid4
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.schemas.enums import OrgRole
from app.db.models.live_sessions import LiveSession
from app.db.models.user_organization import UserOrganization
from app.db.models.user import User
from app.db.models.revoked_token import RevokedToken
from app.core.redis_client import redis_wrapper

BASE = "/api/v1/course/live/security"  # change if your router prefix differs


# ------------------------ helpers ------------------------

def _mk_session(org_id, *, deleted=False):
    now = datetime.now(timezone.utc)
    data = dict(
        title="Live Token Status",
        organization_id=org_id,
        start_time=now - timedelta(minutes=5),
        end_time=now + timedelta(minutes=60),
    )
    if hasattr(LiveSession, "is_deleted"):
        data["is_deleted"] = deleted
    return LiveSession(**data)

async def _mk_user(db: AsyncSession, email: str, full_name: str = None):
    from app.db.models.user import User
    # reuse if already exists (prevents UNIQUE(email) violation)
    existing = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if existing:
        return existing

    u = User(
        email=email,
        hashed_password="x",
        is_active=True,
        is_verified=True,
        full_name=full_name,
        created_at=datetime.now(timezone.utc),
        **({"updated_at": datetime.now(timezone.utc)} if hasattr(User, "updated_at") else {}),
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u

async def _add_membership(db: AsyncSession, user_id, org_id, role=OrgRole.INTERN, is_active=True):
    m = UserOrganization(
        user_id=user_id,
        organization_id=org_id,
        role=role,
        is_active=is_active,
    )
    db.add(m)
    await db.commit()
    await db.refresh(m)
    return m

def _token_record(*, jti: str, issued_at: datetime, expires_at: datetime):
    """
    Shape returned by get_user_session_token().
    We supply naive timestamps (your route normalizes with _to_aware_utc).
    """
    return {
        "jti": jti,
        "issued_at": issued_at.replace(tzinfo=None) if issued_at.tzinfo else issued_at,
        "expires_at": expires_at.replace(tzinfo=None) if expires_at.tzinfo else expires_at,
    }


# ------------------------ autouse fixtures ------------------------

@pytest.fixture(autouse=True)
def _install_mock_redis(monkeypatch):
    """
    Install a small redis mock that supports exists() and setex(),
    so header auth & blacklist lookups work.
    """
    class MockRedisClient:
        def __init__(self): self.store = {}
        async def exists(self, key): return 1 if key in self.store else 0
        async def setex(self, key, seconds, value):
            self.store[key] = value
            return True

    monkeypatch.setattr(redis_wrapper, "_client", MockRedisClient(), raising=True)


@pytest.fixture(autouse=True)
def _robust_to_aware(monkeypatch):
    """
    Make _to_aware_utc robust against naive/aware dt or iso/epoch, returning aware UTC.
    Keeps tests stable across envs.
    """
    import app.api.v1.course.live.security as sec

    def _to_aware_utc(val):
        if val is None:
            return None
        if isinstance(val, datetime):
            return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
        if isinstance(val, (int, float)):
            return datetime.fromtimestamp(val, tz=timezone.utc)
        try:
            s = str(val).rstrip("Z")
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    monkeypatch.setattr(sec, "_to_aware_utc", _to_aware_utc, raising=True)


# ------------------------ tests ------------------------

@pytest.mark.anyio
async def test_token_status__active_200(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    user = await _mk_user(db_session, "active@example.com")
    await _add_membership(db_session, user.id, org.id, role=OrgRole.INTERN, is_active=True)

    # session in org
    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)

    # newest unexpired token
    now = datetime.now(timezone.utc)
    jti = str(uuid4())
    tok = _token_record(jti=jti, issued_at=now - timedelta(minutes=2), expires_at=now + timedelta(minutes=30))

    import app.api.v1.course.live.security as sec
    async def fake_get_user_token(db, org_id, session_id, user_id):
        assert org_id == org.id and session_id == session.id and user_id == user.id
        return {"user_id": user.id, **tok}
    monkeypatch.setattr(sec, "get_user_session_token", fake_get_user_token, raising=True)

    r = await async_client.get(f"{BASE}/sessions/{str(session.id)}/token-status/{str(user.id)}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["active"] is True
    assert body["jti"] == jti
    assert body["user_id"] == str(user.id)
    assert body["session_id"] == str(session.id)


@pytest.mark.anyio
async def test_token_status__404_session_not_found(async_client: AsyncClient, org_user_with_token):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    missing_session = str(uuid4())
    missing_user = str(uuid4())
    r = await async_client.get(f"{BASE}/sessions/{missing_session}/token-status/{missing_user}", headers=headers)
    assert r.status_code == 404
    assert "not found" in r.text.lower()


@pytest.mark.anyio
async def test_token_status__200_token_not_found(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    user = await _mk_user(db_session, "none@example.com")
    await _add_membership(db_session, user.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)

    import app.api.v1.course.live.security as sec
    async def none_token(db, org_id, session_id, user_id): return None
    monkeypatch.setattr(sec, "get_user_session_token", none_token, raising=True)

    r = await async_client.get(f"{BASE}/sessions/{str(session.id)}/token-status/{str(user.id)}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["active"] is False and body["reason"] == "token_not_found"


@pytest.mark.anyio
async def test_token_status__200_revoked_in_redis(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    user = await _mk_user(db_session, "redis@example.com")
    await _add_membership(db_session, user.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)

    now = datetime.now(timezone.utc)
    jti = str(uuid4())
    tok = _token_record(jti=jti, issued_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=15))

    import app.api.v1.course.live.security as sec
    async def fake_get_user_token(db, org_id, session_id, user_id):
        return {"user_id": user.id, **tok}
    monkeypatch.setattr(sec, "get_user_session_token", fake_get_user_token, raising=True)

    # Seed redis blacklist key
    prefix = sec._REDIS_REVOKE_PREFIX  # route uses this prefix
    await redis_wrapper.client.setex(f"{prefix}{jti}", 600, "1")

    r = await async_client.get(f"{BASE}/sessions/{str(session.id)}/token-status/{str(user.id)}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["active"] is False
    assert body["reason"] == "token_revoked_blacklist"
    assert body["jti"] == jti


@pytest.mark.anyio
async def test_token_status__200_revoked_in_db(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    user = await _mk_user(db_session, "dbrevoked@example.com")
    await _add_membership(db_session, user.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)

    now = datetime.now(timezone.utc)
    jti = str(uuid4())
    tok = _token_record(jti=jti, issued_at=now - timedelta(minutes=3), expires_at=now + timedelta(minutes=30))

    import app.api.v1.course.live.security as sec
    async def fake_get_user_token(db, org_id, session_id, user_id):
        return {"user_id": user.id, **tok}
    monkeypatch.setattr(sec, "get_user_session_token", fake_get_user_token, raising=True)

    # Insert DB revocation row (satisfy NOT NULLs)
    revoked = RevokedToken(
        id=uuid4(),
        jti=jti,
        token_type="access",
        user_id=user.id,
        revoked_by=actor.id,
        org_id=org.id,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        revoked_at=datetime.now(timezone.utc),
        reason="test",
    )
    db_session.add(revoked); await db_session.commit()

    r = await async_client.get(f"{BASE}/sessions/{str(session.id)}/token-status/{str(user.id)}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["active"] is False and body["reason"] == "token_revoked"
    assert body["jti"] == jti
    assert body.get("revoked_by") == str(actor.id)


@pytest.mark.anyio
async def test_token_status__200_expired(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    user = await _mk_user(db_session, "expired@example.com")
    await _add_membership(db_session, user.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)

    # expired token
    jti = str(uuid4())
    tok = _token_record(jti=jti, issued_at=datetime.now(timezone.utc) - timedelta(minutes=10), expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))

    import app.api.v1.course.live.security as sec
    async def fake_get_user_token(db, org_id, session_id, user_id):
        return {"user_id": user.id, **tok}
    monkeypatch.setattr(sec, "get_user_session_token", fake_get_user_token, raising=True)

    r = await async_client.get(f"{BASE}/sessions/{str(session.id)}/token-status/{str(user.id)}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["active"] is False and body["reason"] == "token_expired"
    assert body["jti"] == jti


@pytest.mark.anyio
async def test_token_status__500_malformed_missing_jti(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    user = await _mk_user(db_session, "nojti@example.com"); await _add_membership(db_session, user.id, org.id)

    session = _mk_session(org.id); db_session.add(session); await db_session.commit(); await db_session.refresh(session)

    import app.api.v1.course.live.security as sec
    async def bad_token(db, org_id, session_id, user_id):
        now = datetime.now(timezone.utc)
        # missing jti on purpose
        return {"user_id": user.id, "issued_at": now - timedelta(minutes=2), "expires_at": now + timedelta(minutes=20)}
    monkeypatch.setattr(sec, "get_user_session_token", bad_token, raising=True)

    r = await async_client.get(f"{BASE}/sessions/{str(session.id)}/token-status/{str(user.id)}", headers=headers)
    assert r.status_code == 500
    assert "missing jti" in r.text.lower()


@pytest.mark.anyio
async def test_token_status__500_malformed_missing_timestamps(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    user = await _mk_user(db_session, "notimes@example.com"); await _add_membership(db_session, user.id, org.id)

    session = _mk_session(org.id); db_session.add(session); await db_session.commit(); await db_session.refresh(session)

    import app.api.v1.course.live.security as sec
    async def bad_token(db, org_id, session_id, user_id):
        return {"user_id": user.id, "jti": str(uuid4())}  # missing issued_at/expires_at
    monkeypatch.setattr(sec, "get_user_session_token", bad_token, raising=True)

    r = await async_client.get(f"{BASE}/sessions/{str(session.id)}/token-status/{str(user.id)}", headers=headers)
    assert r.status_code == 500
    assert "missing timestamps" in r.text.lower()


@pytest.mark.anyio
async def test_token_status__redis_outage_falls_back_to_db(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    user = await _mk_user(db_session, "fallback@example.com")
    await _add_membership(db_session, user.id, org.id)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)

    now = datetime.now(timezone.utc)
    jti = str(uuid4())
    tok = _token_record(jti=jti, issued_at=now - timedelta(minutes=2), expires_at=now + timedelta(minutes=20))

    import app.api.v1.course.live.security as sec

    async def fake_get_user_token(db, org_id, session_id, user_id):
        return {"user_id": user.id, **tok}

    monkeypatch.setattr(sec, "get_user_session_token", fake_get_user_token, raising=True)

    # Break Redis ONLY for the route's blacklist key; let auth's Redis calls pass.
    class _SelectiveBrokenRedis:
        async def exists(self, key):
            key_str = str(key)
            if key_str.startswith(sec._REDIS_REVOKE_PREFIX):
                raise RuntimeError("boom")  # simulate outage for blacklist check
            return 0  # auth-layer existence checks keep working

        async def setex(self, key, seconds, value):
            return True

    monkeypatch.setattr(redis_wrapper, "_client", _SelectiveBrokenRedis(), raising=True)

    # Insert matching DB revocation so the fallback path returns revoked
    db_session.add(RevokedToken(
        id=uuid4(), jti=jti, token_type="access",
        user_id=user.id, revoked_by=actor.id, org_id=org.id,
        issued_at=datetime.now(timezone.utc), expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        revoked_at=datetime.now(timezone.utc), reason="fallback"
    ))
    await db_session.commit()

    r = await async_client.get(
        f"{BASE}/sessions/{str(session.id)}/token-status/{str(user.id)}",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["active"] is False and body["reason"] == "token_revoked"
