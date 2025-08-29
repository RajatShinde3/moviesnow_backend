import pytest
from datetime import datetime, timedelta, timezone
from uuid import UUID

from httpx import AsyncClient
from jose import jwt
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token
from app.db.models.token import RefreshToken
from app.db.models.user import User
from app.db.models.user_organization import UserOrganization
from app.services.token_service import store_refresh_token


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def ip_header(seed: int) -> dict[str, str]:
    # Make each test look like a different client to dodge per-IP rate limits
    return {"X-Forwarded-For": f"127.0.0.{seed}"}

async def bearer(user: User) -> dict[str, str]:
    access = await create_access_token(user_id=user.id)
    return {"Authorization": f"Bearer {access}"}

async def make_refresh_session(
    db: AsyncSession,
    user: User,
    redis_client,
    *,
    parent_jti: str | None = None,
    session_id: str | None = None,
):
    """
    Create a refresh token, register it in Redis session set & DB, and return
    (token_str, jti, expires_at).
    """
    data = await create_refresh_token(user.id, parent_jti=parent_jti, session_id=session_id)
    await redis_client.sadd(f"session:{user.id}", data["jti"])
    await store_refresh_token(
        db,
        user_id=user.id,
        token=data["token"],
        jti=data["jti"],
        expires_at=data["expires_at"],
        parent_jti=data["parent_jti"],
        ip_address="127.0.0.1",
    )
    return data["token"], data["jti"], data["expires_at"]


# ──────────────────────────────────────────────────────────────────────────────
# /refresh-token
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_refresh_token_success(async_client: AsyncClient, create_test_user, redis_client, db_session: AsyncSession):
    user = await create_test_user(is_verified=True)

    token_str, jti, _ = await make_refresh_session(db_session, user, redis_client)

    resp = await async_client.post(
        "/api/v1/auth/refresh-token",
        json={"refresh_token": token_str},
        headers=ip_header(100),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert "access_token" in body and "refresh_token" in body

    # Old JTI should be removed from the session set
    assert not await redis_client.sismember(f"session:{user.id}", jti)


@pytest.mark.anyio
async def test_refresh_token_invalid_jwt(async_client: AsyncClient):
    resp = await async_client.post(
        "/api/v1/auth/refresh-token",
        json={"refresh_token": "not-a-real-jwt"},
        headers=ip_header(101),
    )
    assert resp.status_code == 401
    assert "invalid refresh token" in resp.text.lower()


@pytest.mark.anyio
async def test_refresh_token_reuse_detected(async_client: AsyncClient, create_test_user, redis_client, db_session: AsyncSession):
    user = await create_test_user(is_verified=True)
    token_str, jti, _ = await make_refresh_session(db_session, user, redis_client)

    # Mark the JTI as revoked in Redis to simulate reuse detection
    await redis_client.setex(f"revoked:jti:{jti}", 3600, "revoked")

    resp = await async_client.post(
        "/api/v1/auth/refresh-token",
        json={"refresh_token": token_str},
        headers=ip_header(102),
    )
    assert resp.status_code == 401
    assert "reused" in resp.text.lower()


@pytest.mark.anyio
async def test_refresh_token_db_revoked(async_client: AsyncClient, create_test_user, redis_client, db_session: AsyncSession):
    user = await create_test_user(is_verified=True)
    token_str, jti, _ = await make_refresh_session(db_session, user, redis_client)

    # Mark as revoked in DB
    await db_session.execute(update(RefreshToken).where(RefreshToken.jti == jti).values(is_revoked=True))
    await db_session.commit()

    resp = await async_client.post(
        "/api/v1/auth/refresh-token",
        json={"refresh_token": token_str},
        headers=ip_header(103),
    )
    assert resp.status_code == 401
    assert "invalid or reused" in resp.text.lower()


@pytest.mark.anyio
async def test_refresh_token_db_expired(async_client: AsyncClient, create_test_user, redis_client, db_session: AsyncSession):
    user = await create_test_user(is_verified=True)
    token_str, jti, _ = await make_refresh_session(db_session, user, redis_client)

    # Force the DB record to be expired (route checks DB expiry)
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    await db_session.execute(
        update(RefreshToken)
        .where(RefreshToken.jti == jti)
        .values(created_at=past - timedelta(seconds=1), expires_at=past)
    )
    await db_session.commit()


    resp = await async_client.post(
        "/api/v1/auth/refresh-token",
        json={"refresh_token": token_str},
        headers=ip_header(104),
    )
    assert resp.status_code == 401
    assert "expired" in resp.text.lower()


@pytest.mark.anyio
async def test_refresh_token_rotation_adds_new_session(async_client: AsyncClient, create_test_user, redis_client, db_session: AsyncSession):
    user = await create_test_user(is_verified=True)
    token_str, old_jti, _ = await make_refresh_session(db_session, user, redis_client)

    resp = await async_client.post(
        "/api/v1/auth/refresh-token",
        json={"refresh_token": token_str},
        headers=ip_header(105),
    )
    assert resp.status_code == 200
    new_rt = resp.json()["refresh_token"]

    # Decode new JTI from the returned refresh token
    decoded = jwt.decode(
        new_rt,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["jti"]},
    )
    new_jti = str(decoded["jti"])

    # Old removed, new present
    assert not await redis_client.sismember(f"session:{user.id}", old_jti)
    assert await redis_client.sismember(f"session:{user.id}", new_jti)


# ──────────────────────────────────────────────────────────────────────────────
# /logout
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_logout_single_session(async_client: AsyncClient, create_test_user, redis_client, db_session: AsyncSession):
    user = await create_test_user(is_verified=True)
    token_str, jti, _ = await make_refresh_session(db_session, user, redis_client)

    resp = await async_client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": token_str},
        headers=ip_header(200),
    )
    assert resp.status_code == 200
    assert resp.json()["message"].lower().startswith("logged out")

    # Session set no longer contains that JTI
    assert not await redis_client.sismember(f"session:{user.id}", jti)

    # DB should mark the token as revoked
    db_row = (await db_session.execute(select(RefreshToken).where(RefreshToken.jti == jti))).scalar_one_or_none()
    assert db_row is None or db_row.is_revoked is True


@pytest.mark.anyio
async def test_logout_all_sessions(async_client: AsyncClient, create_test_user, redis_client, db_session: AsyncSession):
    user = await create_test_user(is_verified=True)

    tokens = []
    for _ in range(3):
        tokens.append(await make_refresh_session(db_session, user, redis_client))

    # Use the first token to request "revoke_all"
    first_token = tokens[0][0]
    resp = await async_client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": first_token, "revoke_all": True},
        headers=ip_header(201),
    )
    assert resp.status_code == 200
    assert resp.json()["message"].lower().startswith("logged out")

    # Redis set for the user should be empty
    assert await redis_client.smembers(f"session:{user.id}") == set()


@pytest.mark.anyio
async def test_logout_invalid_refresh_token(async_client: AsyncClient):
    resp = await async_client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": "not-a-jwt"},
        headers=ip_header(202),
    )
    assert resp.status_code == 401
    assert "invalid refresh token" in resp.text.lower()


# ──────────────────────────────────────────────────────────────────────────────
# /revoke-token
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_revoke_tokens_self(async_client: AsyncClient, create_test_user, redis_client, db_session: AsyncSession):
    user = await create_test_user(is_verified=True)
    headers = await bearer(user)

    # Create two active sessions
    await make_refresh_session(db_session, user, redis_client)
    await make_refresh_session(db_session, user, redis_client)

    resp = await async_client.post(
        "/api/v1/auth/revoke-token",
        json={"user_id": str(user.id)},
        headers=headers | ip_header(300),
    )
    assert resp.status_code == 200
    assert "revoked" in resp.json()["message"].lower()

    # All user's tokens should now be revoked
    rows = (await db_session.execute(select(RefreshToken).where(RefreshToken.user_id == user.id))).scalars().all()
    assert rows and all(getattr(r, "is_revoked", False) for r in rows)


@pytest.mark.anyio
async def test_revoke_tokens_admin_same_org(async_client: AsyncClient, create_test_user, create_organization_fixture, redis_client, db_session: AsyncSession):
    org = await create_organization_fixture()

    admin = await create_test_user(is_verified=True, is_superuser=True, organizations=[org])
    target = await create_test_user(is_verified=True, organizations=[org])
    headers = await bearer(admin)

    # Give target a couple of active refresh tokens
    await make_refresh_session(db_session, target, redis_client)
    await make_refresh_session(db_session, target, redis_client)

    resp = await async_client.post(
        "/api/v1/auth/revoke-token",
        json={"user_id": str(target.id)},
        headers=headers | ip_header(301),
    )
    assert resp.status_code == 200
    assert "revoked" in resp.json()["message"].lower()

    rows = (await db_session.execute(select(RefreshToken).where(RefreshToken.user_id == target.id))).scalars().all()
    assert rows and all(getattr(r, "is_revoked", False) for r in rows)


@pytest.mark.anyio
async def test_revoke_tokens_admin_different_org_forbidden(async_client: AsyncClient, create_test_user, create_organization_fixture, db_session: AsyncSession):
    org_a = await create_organization_fixture()
    org_b = await create_organization_fixture()

    admin = await create_test_user(is_verified=True, is_superuser=True, organizations=[org_a])
    target = await create_test_user(is_verified=True, organizations=[org_b])
    headers = await bearer(admin)

    resp = await async_client.post(
        "/api/v1/auth/revoke-token",
        json={"user_id": str(target.id)},
        headers=headers | ip_header(302),
    )
    assert resp.status_code == 403
    assert "different organization" in resp.text.lower()


@pytest.mark.anyio
async def test_revoke_tokens_non_admin_other_user_forbidden(async_client: AsyncClient, create_test_user):
    alice = await create_test_user(is_verified=True)
    bob = await create_test_user(is_verified=True)
    headers = await bearer(alice)

    resp = await async_client.post(
        "/api/v1/auth/revoke-token",
        json={"user_id": str(bob.id)},
        headers=headers | ip_header(303),
    )
    assert resp.status_code == 403
    assert "not authorized" in resp.text.lower()


@pytest.mark.anyio
async def test_revoke_tokens_no_active_found(async_client: AsyncClient, create_test_user, db_session: AsyncSession):
    user = await create_test_user(is_verified=True)
    headers = await bearer(user)

    # Ensure the user has no active tokens in DB
    await db_session.execute(update(RefreshToken).where(RefreshToken.user_id == user.id).values(is_revoked=True))
    await db_session.commit()

    resp = await async_client.post(
        "/api/v1/auth/revoke-token",
        json={"user_id": str(user.id)},
        headers=headers | ip_header(304),
    )
    assert resp.status_code == 404
    assert "no active refresh tokens" in resp.text.lower()
