# tests/test_live/test_revoke_session_tokens.py

import pytest
from httpx import AsyncClient
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.schemas.enums import OrgRole
from app.db.models.live_sessions import LiveSession
from app.db.models.revoked_token import RevokedToken
from app.db.models.user_organization import UserOrganization
from app.db.models.user import User
from app.core.redis_client import redis_wrapper

BASE = "/api/v1/course/live/security"  

# ------------------------ helpers ------------------------

def _now_aware():
    return datetime.now(timezone.utc)

def _mk_session(org_id, *, deleted=False):
    now = datetime.now(timezone.utc)
    data = dict(
        title="Revoke Session",
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

def _token_dict(*, jti: str, user_id: UUID, issued_at: datetime, expires_at: datetime):
    """
    Route inserts issued_at directly (no tz stripping) -> must be NAIVE UTC.
    Route normalizes expires_at to aware UTC for TTL math, then strips tz for DB.
    This helper guarantees that shape.
    """
    issued_naive = issued_at.replace(tzinfo=None) if issued_at.tzinfo is not None else issued_at
    expires_aware = expires_at if expires_at.tzinfo is not None else expires_at.replace(tzinfo=timezone.utc)
    return {
        "jti": jti,
        "user_id": user_id,
        "issued_at": issued_naive,   # naive
        "expires_at": expires_aware, # aware
    }

# ------------------------ autouse patches ------------------------

@pytest.fixture(autouse=True)
def _patch_time_and_parsers(monkeypatch):
    """
    Make _to_aware_utc robust for tests, accepting dt/iso/epoch and returning aware UTC.
    """
    import app.api.v1.course.live.security as sec

    def _to_aware_utc(val):
        if val is None:
            return None
        if isinstance(val, datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=timezone.utc)
            return val.astimezone(timezone.utc)
        if isinstance(val, (int, float)):
            return datetime.fromtimestamp(val, tz=timezone.utc)
        # treat as ISO-ish string
        try:
            s = str(val).rstrip("Z")
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            return _now_aware()

    monkeypatch.setattr(sec, "_to_aware_utc", _to_aware_utc, raising=True)

# ------------------------ tests ------------------------

@pytest.mark.anyio
async def test_revoke_all__200_revokes_and_blacklists(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    # create two members & active session
    u1 = await _mk_user(db_session, "m1@example.com")
    u2 = await _mk_user(db_session, "m2@example.com")
    await _add_membership(db_session, u1.id, org.id, role=OrgRole.INTERN, is_active=True)
    await _add_membership(db_session, u2.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    # make two valid unexpired tokens
    now_aw = _now_aware()
    toks = [
        _token_dict(jti=str(uuid4()), user_id=u1.id, issued_at=datetime.now(timezone.utc) - timedelta(minutes=1), expires_at=now_aw + timedelta(minutes=30)),
        _token_dict(jti=str(uuid4()), user_id=u2.id, issued_at=datetime.now(timezone.utc) - timedelta(minutes=2), expires_at=now_aw + timedelta(minutes=25)),
    ]

    # token gatherer + redis blacklist
    import app.api.v1.course.live.security as sec

    async def fake_get_all(db, org_id, session_id):
        assert org_id == org.id and session_id == session.id
        return toks

    calls = []
    async def fake_blacklist(jti, ttl):
        calls.append((jti, ttl))
        return True

    # ensure auth passes AND route takes redis branch
    class _AuthFriendlyRedis:
        async def exists(self, key):  # used by auth token decode
            return 0

    monkeypatch.setattr(redis_wrapper, "_client", _AuthFriendlyRedis(), raising=True)
    monkeypatch.setattr(sec, "get_all_session_tokens", fake_get_all, raising=True)
    monkeypatch.setattr(sec, "_redis_blacklist_jti", fake_blacklist, raising=True)

    r = await async_client.post(
        f"{BASE}/sessions/{sid}/revoke-token",
        headers=headers,
        json={"revoke_all": True, "reason": "cleanup"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["revoke_all"] is True
    statuses = {res["user_id"]: res["status"] for res in body["results"]}
    assert statuses[str(u1.id)] == "revoked"
    assert statuses[str(u2.id)] == "revoked"

    # redis blacklist called twice with positive TTLs
    assert len(calls) == 2
    for jti, ttl in calls:
        assert jti in {toks[0]["jti"], toks[1]["jti"]}
        assert ttl > 0


@pytest.mark.anyio
async def test_revoke_user__200_revokes_latest_for_user(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    member = await _mk_user(db_session, "member@example.com")
    await _add_membership(db_session, member.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    now_aw = _now_aware()
    tok = _token_dict(
        jti=str(uuid4()),
        user_id=member.id,
        issued_at=datetime.now(timezone.utc) - timedelta(minutes=3),   # naive
        expires_at=now_aw + timedelta(minutes=20),            # aware
    )

    import app.api.v1.course.live.security as sec
    async def fake_get_user(db, org_id, session_id, user_id):
        assert user_id == member.id
        return tok

    # allow auth to pass; no need to hit redis blacklist branch here
    class _AuthFriendlyRedis:
        async def exists(self, key): return 0
    monkeypatch.setattr(redis_wrapper, "_client", _AuthFriendlyRedis(), raising=True)

    monkeypatch.setattr(sec, "get_user_session_token", fake_get_user, raising=True)

    r = await async_client.post(
        f"{BASE}/sessions/{sid}/revoke-token",
        headers=headers,
        json={"revoke_all": False, "user_id": str(member.id), "reason": "manual"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["revoke_all"] is False
    assert {"user_id": str(member.id), "status": "revoked"} in body["results"]


@pytest.mark.anyio
async def test_revoke_user__404_when_no_active_token(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    member = await _mk_user(db_session, "noactive@example.com")
    await _add_membership(db_session, member.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    import app.api.v1.course.live.security as sec
    async def none_user_token(db, org_id, session_id, user_id):
        return None

    class _AuthFriendlyRedis:
        async def exists(self, key): return 0
    monkeypatch.setattr(redis_wrapper, "_client", _AuthFriendlyRedis(), raising=True)

    monkeypatch.setattr(sec, "get_user_session_token", none_user_token, raising=True)

    r = await async_client.post(
        f"{BASE}/sessions/{sid}/revoke-token",
        headers=headers,
        json={"revoke_all": False, "user_id": str(member.id)},
    )
    assert r.status_code == 404
    assert "no active token" in r.text.lower()


@pytest.mark.anyio
async def test_revoke_all__200_no_active_tokens_due_to_expired_and_invalid(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    now_aw = _now_aware()
    invalid = {"user_id": None, "expires_at": now_aw + timedelta(minutes=10)}  # missing jti
    expired = _token_dict(
        jti=str(uuid4()),
        user_id=uuid4(),
        issued_at=datetime.now(timezone.utc) - timedelta(minutes=40),  # naive
        expires_at=now_aw - timedelta(minutes=1),             # aware, already expired
    )

    import app.api.v1.course.live.security as sec
    async def fake_all(db, org_id, session_id):
        return [invalid, expired]

    class _AuthFriendlyRedis:
        async def exists(self, key): return 0
    monkeypatch.setattr(redis_wrapper, "_client", _AuthFriendlyRedis(), raising=True)

    monkeypatch.setattr(sec, "get_all_session_tokens", fake_all, raising=True)

    r = await async_client.post(
        f"{BASE}/sessions/{sid}/revoke-token",
        headers=headers,
        json={"revoke_all": True},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["detail"].lower().startswith("no active tokens")
    statuses = [res["status"] for res in body["results"]]
    assert "invalid_record" in statuses
    assert "already_expired" in statuses


@pytest.mark.anyio
async def test_payload_semantics__400_both_fields_set(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)

    r = await async_client.post(
        f"{BASE}/sessions/{str(session.id)}/revoke-token",
        headers=headers,
        json={"revoke_all": True, "user_id": str(uuid4())},
    )
    assert r.status_code == 400
    assert "either" in r.text.lower()


@pytest.mark.anyio
async def test_payload_semantics__400_neither_field_set(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)

    r = await async_client.post(
        f"{BASE}/sessions/{str(session.id)}/revoke-token",
        headers=headers,
        json={"revoke_all": False},
    )
    assert r.status_code == 400
    assert "user_id is required" in r.text.lower()


@pytest.mark.anyio
async def test_session_not_found__404(async_client: AsyncClient, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    missing = str(uuid4())

    r = await async_client.post(
        f"{BASE}/sessions/{missing}/revoke-token",
        headers=headers,
        json={"revoke_all": True},
    )
    assert r.status_code == 404
    assert "session" in r.text.lower()


@pytest.mark.anyio
async def test_idempotent__already_revoked_is_reported(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    subject = await _mk_user(db_session, "revoked@example.com")
    await _add_membership(db_session, subject.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    now_aw = _now_aware()
    jti = str(uuid4())
    # Seed an existing revocation row so the route should mark it as already_revoked
    seeded = RevokedToken(
        id=uuid4(),
        jti=jti,
        token_type="access",
        user_id=subject.id,
        revoked_by=admin.id,
        org_id=org.id,
        issued_at=datetime.now(timezone.utc),                        # naive
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=20),  # naive ok for DB
        revoked_at=datetime.now(timezone.utc),
        reason="seed",
    )
    db_session.add(seeded); await db_session.commit()

    tok = _token_dict(
        jti=jti,
        user_id=subject.id,
        issued_at=datetime.now(timezone.utc) - timedelta(minutes=5),  # naive
        expires_at=now_aw + timedelta(minutes=15),           # aware
    )

    import app.api.v1.course.live.security as sec
    async def get_user(db, org_id, session_id, user_id):
        return tok

    class _AuthFriendlyRedis:
        async def exists(self, key): return 0
    monkeypatch.setattr(redis_wrapper, "_client", _AuthFriendlyRedis(), raising=True)

    monkeypatch.setattr(sec, "get_user_session_token", get_user, raising=True)

    r = await async_client.post(
        f"{BASE}/sessions/{sid}/revoke-token",
        headers=headers,
        json={"revoke_all": False, "user_id": str(subject.id)},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert {"user_id": str(subject.id), "status": "already_revoked"} in body["results"]
