# tests/test_live/test_terminate_session.py

import pytest
from httpx import AsyncClient
from uuid import uuid4
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.schemas.enums import OrgRole
from app.db.models.live_sessions import LiveSession
from app.db.models.revoked_token import RevokedToken
from app.db.models.user_organization import UserOrganization
from app.db.models.user import User
from app.core.redis_client import redis_wrapper

BASE = "/api/v1/course/live/security"  # change if your router prefix differs


# ------------------------ helpers ------------------------

def _now_aw():
    return datetime.now(timezone.utc)

def _mk_session(org_id, *, deleted=False):
    now = datetime.now(timezone.utc)
    data = dict(
        title="Terminate Session",
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

def _token_dict(*, jti: str, user_id, issued_at: datetime, expires_at: datetime):
    """
    Route inserts issued_at & expires_at directly into DB.
    Your DB expects **naive** timestamps; TTL/compare uses aware.
    So we pass issued_at **naive** and expires_at **naive**,
    which the route will convert to aware for comparisons.
    """
    issued_naive = issued_at.replace(tzinfo=None) if issued_at.tzinfo else issued_at
    expires_naive = expires_at.replace(tzinfo=None) if expires_at.tzinfo else expires_at
    return {
        "jti": jti,
        "user_id": user_id,
        "issued_at": issued_naive,    # naive UTC for DB insert
        "expires_at": expires_naive,  # naive UTC for DB insert (route makes aware for math)
    }


# ------------------------ autouse: make auth happy ------------------------

@pytest.fixture(autouse=True)
def _install_full_mock_redis(monkeypatch):
    """
    Use the comprehensive mock that supports exists/setex/pipeline/ttl/etc.
    This avoids auth decode failures and lets the route's setex path run.
    """
    from tests.fixtures.mocks.redis import MockRedisClient
    monkeypatch.setattr(redis_wrapper, "_client", MockRedisClient(), raising=True)


# ------------------------ tests ------------------------

@pytest.mark.anyio
async def test_terminate__200_full_flow_revokes_blacklists_soft_deletes(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    owner, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    u1 = await _mk_user(db_session, "a@example.com")
    u2 = await _mk_user(db_session, "b@example.com")
    await _add_membership(db_session, u1.id, org.id, role=OrgRole.INTERN, is_active=True)
    await _add_membership(db_session, u2.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    now = _now_aw()
    toks = [
        _token_dict(jti=str(uuid4()), user_id=u1.id, issued_at=datetime.now(timezone.utc) - timedelta(minutes=2), expires_at=now + timedelta(minutes=30)),
        _token_dict(jti=str(uuid4()), user_id=u2.id, issued_at=datetime.now(timezone.utc) - timedelta(minutes=3), expires_at=now + timedelta(minutes=20)),
    ]

    import app.api.v1.course.live.security as sec

    async def fake_get_all(db, org_id, s_id):
        assert org_id == org.id and s_id == session.id
        return toks

    bl_calls, del_calls = [], []

    async def fake_blacklist(jti, ttl):
        bl_calls.append((jti, ttl)); return True

    async def fake_delete_user_session_token(uid, s_id):
        del_calls.append((str(uid), str(s_id))); return True

    monkeypatch.setattr(sec, "get_all_session_tokens", fake_get_all, raising=True)
    monkeypatch.setattr(sec, "_redis_blacklist_jti", fake_blacklist, raising=True)
    monkeypatch.setattr(sec, "delete_user_session_token", fake_delete_user_session_token, raising=True)

    r = await async_client.post(
        f"{BASE}/sessions/{sid}/terminate-session",
        headers=headers,
        json={"notify_participants": True, "reason": "shutdown"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["detail"].lower().startswith("session terminated")

    statuses = {res["user_id"]: res["status"] for res in body["results"]}
    assert statuses[str(u1.id)] == "revoked"
    assert statuses[str(u2.id)] == "revoked"

    # soft-deleted
    refreshed = (await db_session.execute(select(LiveSession).where(LiveSession.id == session.id))).scalar_one()
    assert getattr(refreshed, "is_deleted", True) is True
    # deleted_at should be set if column exists
    if hasattr(refreshed, "deleted_at"):
        assert getattr(refreshed, "deleted_at") is not None

    # redis blacklist and per-user delete called for both tokens with positive TTLs
    assert len(bl_calls) == 2 and len(del_calls) == 2
    for jti, ttl in bl_calls:
        assert jti in {t["jti"] for t in toks}
        assert ttl > 0
    for uid, s in del_calls:
        assert uid in {str(u1.id), str(u2.id)}
        assert s == sid


@pytest.mark.anyio
async def test_terminate__404_session_not_found(async_client: AsyncClient, org_user_with_token):
    owner, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    missing = str(uuid4())

    r = await async_client.post(
        f"{BASE}/sessions/{missing}/terminate-session",
        headers=headers,
        json={"notify_participants": False},
    )
    assert r.status_code == 404
    assert "not found" in r.text.lower()


@pytest.mark.anyio
async def test_terminate__idempotent_when_already_revoked(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    owner, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    member = await _mk_user(db_session, "already@example.com")
    await _add_membership(db_session, member.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    jti = str(uuid4())
    # seed existing revocation row
    seeded = RevokedToken(
        id=uuid4(),
        jti=jti,
        token_type="access",
        user_id=member.id,
        revoked_by=owner.id,
        org_id=org.id,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        revoked_at=datetime.now(timezone.utc),
        reason="seed",
    )
    db_session.add(seeded); await db_session.commit()

    tok = _token_dict(jti=jti, user_id=member.id, issued_at=datetime.now(timezone.utc) - timedelta(minutes=5), expires_at=datetime.now(timezone.utc) + timedelta(minutes=25))

    import app.api.v1.course.live.security as sec
    async def fake_get_all(db, org_id, s_id):
        return [tok]

    bl = []
    async def fake_blacklist(jti, ttl):
        bl.append((jti, ttl)); return True

    del_calls = []
    async def fake_delete(uid, s_id):
        del_calls.append((str(uid), str(s_id))); return True

    monkeypatch.setattr(sec, "get_all_session_tokens", fake_get_all, raising=True)
    monkeypatch.setattr(sec, "_redis_blacklist_jti", fake_blacklist, raising=True)
    monkeypatch.setattr(sec, "delete_user_session_token", fake_delete, raising=True)

    r = await async_client.post(
        f"{BASE}/sessions/{sid}/terminate-session",
        headers=headers,
        json={},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert {"user_id": str(member.id), "status": "already_revoked"} in body["results"]
    # since already revoked, redis/delete may be skipped
    assert all(call[0] != jti for call in bl)


@pytest.mark.anyio
async def test_terminate__skips_expired_tokens(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    owner, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    member = await _mk_user(db_session, "expired@example.com")
    await _add_membership(db_session, member.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    # expired by 1 minute
    tok = _token_dict(jti=str(uuid4()), user_id=member.id, issued_at=datetime.now(timezone.utc) - timedelta(minutes=30), expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))

    import app.api.v1.course.live.security as sec
    async def fake_get_all(db, org_id, s_id):
        return [tok]

    bl = []
    async def fake_blacklist(jti, ttl):
        bl.append((jti, ttl)); return True

    del_calls = []
    async def fake_delete(uid, s_id):
        del_calls.append((str(uid), str(s_id))); return True

    monkeypatch.setattr(sec, "get_all_session_tokens", fake_get_all, raising=True)
    monkeypatch.setattr(sec, "_redis_blacklist_jti", fake_blacklist, raising=True)
    monkeypatch.setattr(sec, "delete_user_session_token", fake_delete, raising=True)

    r = await async_client.post(
        f"{BASE}/sessions/{sid}/terminate-session",
        headers=headers,
        json={},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert {"user_id": str(member.id), "status": "already_expired"} in body["results"]
    # No blacklist/deletion for expired tokens
    assert bl == []
    assert del_calls == []


@pytest.mark.anyio
async def test_terminate__invalid_records_are_reported(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    owner, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    bad1 = {"user_id": None, "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)}  # missing jti
    bad2 = {"jti": str(uuid4()), "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)}  # missing user_id
    bad3 = {"jti": str(uuid4()), "user_id": uuid4()}  # missing expires_at

    import app.api.v1.course.live.security as sec
    async def fake_get_all(db, org_id, s_id):
        return [bad1, bad2, bad3]

    # allow route to attempt side-effects harmlessly
    async def noop(*a, **k): return True
    monkeypatch.setattr(sec, "get_all_session_tokens", fake_get_all, raising=True)
    monkeypatch.setattr(sec, "_redis_blacklist_jti", noop, raising=True)
    monkeypatch.setattr(sec, "delete_user_session_token", noop, raising=True)

    r = await async_client.post(
        f"{BASE}/sessions/{sid}/terminate-session",
        headers=headers,
        json={"reason": "cleanup"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    statuses = [r["status"] for r in body["results"]]
    assert statuses.count("invalid_record") == 3


@pytest.mark.anyio
async def test_terminate__empty_token_list_ok(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    owner, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    import app.api.v1.course.live.security as sec
    async def fake_get_all(db, org_id, s_id):
        return []  # no tokens

    monkeypatch.setattr(sec, "get_all_session_tokens", fake_get_all, raising=True)

    r = await async_client.post(
        f"{BASE}/sessions/{sid}/terminate-session",
        headers=headers,
        json={},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["results"] == []


@pytest.mark.anyio
async def test_terminate__redis_and_delete_failures_are_best_effort(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    owner, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    member = await _mk_user(db_session, "resilient@example.com")
    await _add_membership(db_session, member.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    tok = _token_dict(jti=str(uuid4()), user_id=member.id, issued_at=datetime.now(timezone.utc) - timedelta(minutes=5), expires_at=datetime.now(timezone.utc) + timedelta(minutes=20))

    import app.api.v1.course.live.security as sec
    async def fake_get_all(db, org_id, s_id):
        return [tok]

    async def boom_blacklist(*a, **k): raise RuntimeError("boom")
    async def boom_delete(*a, **k): raise RuntimeError("boom")

    monkeypatch.setattr(sec, "get_all_session_tokens", fake_get_all, raising=True)
    monkeypatch.setattr(sec, "_redis_blacklist_jti", boom_blacklist, raising=True)
    monkeypatch.setattr(sec, "delete_user_session_token", boom_delete, raising=True)

    r = await async_client.post(
        f"{BASE}/sessions/{sid}/terminate-session",
        headers=headers,
        json={},
    )
    # best-effort side-effects shouldn't fail the request
    assert r.status_code == 200, r.text


@pytest.mark.anyio
async def test_terminate__notify_true_still_200(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    owner, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    import app.api.v1.course.live.security as sec
    async def fake_get_all(db, org_id, s_id): return []

    monkeypatch.setattr(sec, "get_all_session_tokens", fake_get_all, raising=True)

    r = await async_client.post(
        f"{BASE}/sessions/{sid}/terminate-session",
        headers=headers,
        json={"notify_participants": True},
    )
    assert r.status_code == 200, r.text
