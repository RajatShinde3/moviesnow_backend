# tests/test_auth/test_impersonate_user.py

import pytest
from httpx import AsyncClient
from uuid import uuid4
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.db.models.user_organization import UserOrganization
from app.db.models.user import User
from app.core.redis_client import redis_wrapper

BASE = "/api/v1/course/live/security" 


# ------------------------ helpers ------------------------

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

async def _add_membership(
    db: AsyncSession,
    user_id,
    org_id,
    role: OrgRole = OrgRole.INTERN,
    is_active: bool = True,
    is_default: bool = False,
):
    # If membership exists, update fields and return (idempotent)
    q = await db.execute(
        select(UserOrganization).where(
            UserOrganization.user_id == user_id,
            UserOrganization.organization_id == org_id,
        )
    )
    existing = q.scalar_one_or_none()
    if existing:
        if hasattr(existing, "role"):
            existing.role = role
        if hasattr(existing, "is_active"):
            existing.is_active = is_active
        if hasattr(existing, "is_default"):
            existing.is_default = is_default
        await db.commit()
        await db.refresh(existing)
        return existing

    # Otherwise create it
    ou = UserOrganization(
        user_id=user_id,
        organization_id=org_id,
        role=role,
        is_active=is_active,
        is_default=is_default,
    )
    db.add(ou)
    await db.commit()
    await db.refresh(ou)
    return ou

# ------------------------ autouse: install mock redis for auth & rate limit ------------------------

@pytest.fixture(autouse=True)
def _install_mock_redis(monkeypatch):
    """
    The auth layer and rate limiter call redis. Provide a basic client with exists/setex.
    """
    class MockRedisClient:
        def __init__(self):
            self.store = {}
        async def exists(self, key):
            return 1 if key in self.store else 0
        async def setex(self, key, seconds, value):
            self.store[key] = value
            return True

    monkeypatch.setattr(redis_wrapper, "_client", MockRedisClient(), raising=True)


# ------------------------ tests ------------------------

@pytest.mark.anyio
async def test_impersonate__200_admin_impersonates_member(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    target = await _mk_user(db_session, "member@example.com")
    await _add_membership(db_session, target.id, org.id, role=OrgRole.INTERN, is_active=True)

    # no-op rate limiter
    import app.api.v1.course.live.security as sec
    async def no_rl(org_id, issuer_id): return None
    monkeypatch.setattr(sec, "_ratelimit_issuer", no_rl, raising=True)

    # capture create_access_token args
    calls = {}
    async def fake_create_access_token(**kwargs):
        calls.update(kwargs)
        return "FAKE_TOKEN"
    monkeypatch.setattr(sec, "create_access_token", fake_create_access_token, raising=True)

    r = await async_client.get(
        f"{BASE}/impersonate",
        headers=headers,
        params={"user_id": str(target.id), "reason": "support case #123"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["impersonated_user_id"] == str(target.id)
    assert body["token"] == "FAKE_TOKEN"
    assert body.get("issued_at") and body.get("expires_at")

    # verify token flags/active_org were passed to the helper
    assert calls.get("user_id") == target.id
    assert calls.get("mfa_authenticated") is True
    assert calls.get("is_impersonated") is True
    assert calls.get("impersonated_by") == admin.id
    assert isinstance(calls.get("impersonation_started_at"), datetime)
    active_org = calls.get("active_org") or {}
    assert active_org.get("org_id") == str(org.id)
    assert active_org.get("role") in (OrgRole.INTERN.value, "member")  # depends on enum serialization


@pytest.mark.anyio
async def test_impersonate__200_self_impersonation_audited(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    owner, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    await _add_membership(db_session, owner.id, org.id, role=OrgRole.OWNER, is_active=True)

    import app.api.v1.course.live.security as sec
    async def no_rl(*a, **k): return None
    monkeypatch.setattr(sec, "_ratelimit_issuer", no_rl, raising=True)
    async def fake_create(**k): return "TOK"
    monkeypatch.setattr(sec, "create_access_token", fake_create, raising=True)

    # capture audit payload
    audit_calls = []
    async def fake_audit(**kwargs):
        audit_calls.append(kwargs)
    monkeypatch.setattr(sec, "log_org_event", fake_audit, raising=True)

    r = await async_client.get(
        f"{BASE}/impersonate",
        headers=headers,
        params={"user_id": str(owner.id), "reason": "debug"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["impersonated_user_id"] == str(owner.id)

    # check that one audit call contains self_impersonation=True
    meta_datas = [c.get("meta_data") for c in audit_calls if c.get("meta_data")]
    assert any(md.get("self_impersonation") is True for md in meta_datas)


@pytest.mark.anyio
async def test_impersonate__404_target_not_in_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    stranger = await _mk_user(db_session, "stranger@example.com")  # no org membership

    import app.api.v1.course.live.security as sec
    async def no_rl(*a, **k): return None
    monkeypatch.setattr(sec, "_ratelimit_issuer", no_rl, raising=True)

    r = await async_client.get(
        f"{BASE}/impersonate",
        headers=headers,
        params={"user_id": str(stranger.id)},
    )
    assert r.status_code == 404
    assert "not found" in r.text.lower()


@pytest.mark.anyio
async def test_impersonate__404_target_inactive(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    inactive = await _mk_user(db_session, "inactive@example.com")
    await _add_membership(db_session, inactive.id, org.id, role=OrgRole.INTERN, is_active=False)

    import app.api.v1.course.live.security as sec
    async def no_rl(*a, **k): return None
    monkeypatch.setattr(sec, "_ratelimit_issuer", no_rl, raising=True)

    r = await async_client.get(
        f"{BASE}/impersonate",
        headers=headers,
        params={"user_id": str(inactive.id)},
    )
    assert r.status_code == 404
    assert "inactive" in r.text.lower()


@pytest.mark.anyio
async def test_impersonate__403_cannot_impersonate_up(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    target = await _mk_user(db_session, "owner@example.com")
    await _add_membership(db_session, target.id, org.id, role=OrgRole.OWNER, is_active=True)

    import app.api.v1.course.live.security as sec
    async def no_rl(*a, **k): return None
    monkeypatch.setattr(sec, "_ratelimit_issuer", no_rl, raising=True)

    # Force hierarchy check to fail (simulate "no impersonate up")
    from fastapi import HTTPException
    def deny(actor_role, target_role):
        raise HTTPException(status_code=403, detail="Cannot impersonate up")
    monkeypatch.setattr(sec, "_validate_impersonation_hierarchy", deny, raising=True)

    r = await async_client.get(
        f"{BASE}/impersonate",
        headers=headers,
        params={"user_id": str(target.id)},
    )
    assert r.status_code == 403
    assert "cannot impersonate up" in r.text.lower()


@pytest.mark.anyio
async def test_impersonate__429_rate_limited(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    owner, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    member = await _mk_user(db_session, "member2@example.com")
    await _add_membership(db_session, member.id, org.id, role=OrgRole.INTERN, is_active=True)

    import app.api.v1.course.live.security as sec
    from fastapi import HTTPException
    async def rl_exceeded(org_id, issuer_id):
        raise HTTPException(status_code=429, detail="Too many requests")
    monkeypatch.setattr(sec, "_ratelimit_issuer", rl_exceeded, raising=True)

    r = await async_client.get(
        f"{BASE}/impersonate",
        headers=headers,
        params={"user_id": str(member.id)},
    )
    assert r.status_code == 429
    assert "too many" in r.text.lower()


@pytest.mark.anyio
async def test_impersonate__audit_failure_does_not_block(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    target = await _mk_user(db_session, "audit@example.com")
    await _add_membership(db_session, target.id, org.id, role=OrgRole.INTERN, is_active=True)

    import app.api.v1.course.live.security as sec
    async def no_rl(*a, **k): return None
    monkeypatch.setattr(sec, "_ratelimit_issuer", no_rl, raising=True)
    async def fake_create(**k): return "TOK"
    monkeypatch.setattr(sec, "create_access_token", fake_create, raising=True)

    # Make audit logging explode; route should still succeed
    async def boom(**kwargs): raise RuntimeError("audit down")
    monkeypatch.setattr(sec, "log_org_event", boom, raising=True)

    r = await async_client.get(
        f"{BASE}/impersonate",
        headers=headers,
        params={"user_id": str(target.id)},
    )
    assert r.status_code == 200, r.text
    assert r.json()["token"] == "TOK"


@pytest.mark.anyio
async def test_impersonate__500_when_token_mint_fails(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    target = await _mk_user(db_session, "fail@example.com")
    await _add_membership(db_session, target.id, org.id, role=OrgRole.INTERN, is_active=True)

    import app.api.v1.course.live.security as sec
    async def no_rl(*a, **k): return None
    monkeypatch.setattr(sec, "_ratelimit_issuer", no_rl, raising=True)

    async def boom_create(**kwargs):
        raise RuntimeError("signer exploded")
    monkeypatch.setattr(sec, "create_access_token", boom_create, raising=True)

    r = await async_client.get(
        f"{BASE}/impersonate",
        headers=headers,
        params={"user_id": str(target.id)},
    )
    assert r.status_code == 500
    assert "failed to impersonate user" in r.text.lower()
