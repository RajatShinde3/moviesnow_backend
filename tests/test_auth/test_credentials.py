# tests/test_auth/test_credentials.py
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from httpx import AsyncClient
from jose import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token, get_password_hash, verify_password
from app.db.models.user import User
from app.db.models.token import RefreshToken
from app.services.token_service import store_refresh_token

BASE = "/api/v1/auth"

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def ip_header(seed: int) -> dict[str, str]:
    """Keep per-IP limiter happy; ensure valid IPv4."""
    seed = max(0, min(255, int(seed)))
    return {"X-Forwarded-For": f"127.0.0.{seed}"}

async def bearer(user: User, *, session_id: str | None = None) -> dict[str, str]:
    """Make an ACCESS bearer with session lineage and MFA flag."""
    access = await create_access_token(
        user_id=user.id,
        mfa_authenticated=True,
        session_id=session_id,
    )
    return {"Authorization": f"Bearer {access}"}

def make_reauth_token(*, user_id, session_id: str, mfa: bool = True, exp_seconds: int = 600) -> str:
    """
    Mint a valid **reauth** JWT matching your dependency’s expectations:
    - typ/token_type = "reauth"
    - sub, exp
    - session_id lineage same as access
    - mfa_authenticated flag
    """
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(user_id),
        "exp": int((now + timedelta(seconds=exp_seconds)).timestamp()),
        "jti": str(uuid4()),
        "session_id": session_id,
        "mfa_authenticated": bool(mfa),
        "typ": "reauth",
        "token_type": "reauth",
    }
    return jwt.encode(claims, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=settings.JWT_ALGORITHM)

async def make_refresh_session(
    db: AsyncSession,
    user: User,
    redis_client,
    *,
    session_id: str | None = None,
    with_meta: bool = False,
    ip: str = "198.51.100.50",
    ua: str = "pytest/ua",
):
    """
    Create + persist one refresh session:

    - Mint refresh token (with optional session_id lineage).
    - Add JTI to Redis `session:{user_id}`.
    - Store DB row (hashed token handled by service).
    - Optionally write `sessionmeta:{jti}` hash (best-effort UX).

    Returns: (token_str, jti, expires_at)
    """
    data = await create_refresh_token(user.id, session_id=session_id)
    await redis_client.sadd(f"session:{user.id}", data["jti"])
    await store_refresh_token(
        db,
        user_id=user.id,
        token=data["token"],
        jti=data["jti"],
        expires_at=data["expires_at"],
        parent_jti=data.get("parent_jti"),
        ip_address=ip,
    )

    if with_meta:
        ttl = max(1, int((data["expires_at"] - datetime.now(timezone.utc)).total_seconds()))
        await redis_client.hset(
            f"sessionmeta:{data['jti']}",
            mapping={
                "session_id": session_id or data["jti"],
                "ip": ip,
                "ua": ua,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_seen": datetime.now(timezone.utc).isoformat(),
            },
        )
        await redis_client.expire(f"sessionmeta:{data['jti']}", ttl)

    return data["token"], data["jti"], data["expires_at"]

async def set_user_password(db: AsyncSession, user: User, raw_pwd: str):
    # Supports hashed_password or password_hash
    model = (await db.execute(select(User).where(User.id == user.id))).scalar_one()
    if hasattr(model, "hashed_password"):
        model.hashed_password = get_password_hash(raw_pwd)
    elif hasattr(model, "password_hash"):
        model.password_hash = get_password_hash(raw_pwd)
    else:
        # Fall back to a commonly used field; adjust if your model differs
        setattr(model, "hashed_password", get_password_hash(raw_pwd))
    await db.commit()

def _b2s(v) -> str:
    return v.decode() if isinstance(v, (bytes, bytearray)) else str(v)

# ─────────────────────────────────────────────────────────────
# POST /auth/password/change
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_password_change_happy_path(
    async_client: AsyncClient, create_test_user, redis_client, db_session: AsyncSession
):
    """
    Rotates password with step-up; keeps current session, revokes others,
    updates hash, and (optionally) sets password_changed_at.
    """
    user = await create_test_user(is_verified=True)
    # Set known password
    old_pwd = "OldP@ssw0rd!"
    new_pwd = "NewP@ssw0rd!"
    await set_user_password(db_session, user, old_pwd)

    # Two sessions: current lineage + another
    sid_keep = str(uuid4())
    headers = await bearer(user, session_id=sid_keep)

    _, j_keep, _ = await make_refresh_session(
        db_session, user, redis_client, session_id=sid_keep, with_meta=True, ip="198.51.100.61"
    )
    _, j_other, _ = await make_refresh_session(
        db_session, user, redis_client, session_id=str(uuid4()), with_meta=True, ip="198.51.100.62"
    )

    # Add reauth (MFA-backed) bound to same session
    reauth = make_reauth_token(user_id=user.id, session_id=sid_keep, mfa=True)
    headers |= {"X-Reauth": reauth}

    payload = {"current_password": old_pwd, "new_password": new_pwd}
    r = await async_client.post(f"{BASE}/password/change", headers=headers | ip_header(201), json=payload)
    assert r.status_code == 200, r.text

    # Hash updated & old password no longer valid
    db_user = (await db_session.execute(select(User).where(User.id == user.id))).scalar_one()
    # Pull stored hash (support either field)
    stored = getattr(db_user, "hashed_password", None) or getattr(db_user, "password_hash", None)
    assert stored and verify_password(new_pwd, stored) and not verify_password(old_pwd, stored)

    # Optional timestamp
    if hasattr(db_user, "password_changed_at"):
        assert getattr(db_user, "password_changed_at") is not None

    # Sessions: keep current, revoke others
    assert await redis_client.sismember(f"session:{user.id}", j_keep)
    assert not await redis_client.sismember(f"session:{user.id}", j_other)
    # DB row revoked (or gone)
    row_other = (
        await db_session.execute(select(RefreshToken).where(RefreshToken.user_id == user.id, RefreshToken.jti == j_other))
    ).scalar_one_or_none()
    assert row_other is None or getattr(row_other, "is_revoked", False) is True
    # Reuse sentinel written
    assert await redis_client.exists(f"revoked:jti:{j_other}") in (1, True)

@pytest.mark.anyio
async def test_password_change_bad_current_rejected(
    async_client: AsyncClient, create_test_user, redis_client, db_session: AsyncSession
):
    user = await create_test_user(is_verified=True)
    await set_user_password(db_session, user, "SomeKnownPwd1!")
    sid_keep = str(uuid4())
    headers = await bearer(user, session_id=sid_keep)
    headers |= {"X-Reauth": make_reauth_token(user_id=user.id, session_id=sid_keep, mfa=True)}

    payload = {"current_password": "WRONG!", "new_password": "AnotherNewPwd1!"}
    r = await async_client.post(f"{BASE}/password/change", headers=headers | ip_header(202), json=payload)
    assert r.status_code == 400
    assert "Invalid current password" in r.text

@pytest.mark.anyio
async def test_password_change_requires_step_up(
    async_client: AsyncClient, create_test_user, db_session: AsyncSession
):
    user = await create_test_user(is_verified=True)
    await set_user_password(db_session, user, "SomeKnownPwd2!")
    headers = await bearer(user, session_id=str(uuid4()))
    payload = {"current_password": "SomeKnownPwd2!", "new_password": "NewPwdX1!"}
    r = await async_client.post(f"{BASE}/password/change", headers=headers | ip_header(203), json=payload)
    assert r.status_code in (401, 403)

# ─────────────────────────────────────────────────────────────
# Email change: start + confirm
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_email_change_full_flow(
    async_client: AsyncClient, create_test_user, redis_client, db_session: AsyncSession
):
    """
    Start: stores token in Redis for the new email.
    Confirm: validates token, updates email, clears Redis, and revokes other sessions.
    """
    user = await create_test_user(is_verified=True)
    await set_user_password(db_session, user, "FlowPwd1!")

    # Prepare a couple of sessions
    sid_keep = str(uuid4())
    headers = await bearer(user, session_id=sid_keep)
    headers_step = {"X-Reauth": make_reauth_token(user_id=user.id, session_id=sid_keep, mfa=True)}
    headers |= headers_step

    _, j_keep, _ = await make_refresh_session(
        db_session, user, redis_client, session_id=sid_keep, with_meta=True, ip="198.51.100.71"
    )
    _, j_other, _ = await make_refresh_session(
        db_session, user, redis_client, session_id=str(uuid4()), with_meta=True, ip="198.51.100.72"
    )

    # Start change
    new_email = f"new_{uuid4().hex[:8]}@example.com"
    r1 = await async_client.post(
        f"{BASE}/email/change/start",
        headers=headers | ip_header(211),
        json={"new_email": new_email, "current_password": "FlowPwd1!"},
    )
    assert r1.status_code == 200, r1.text

    # Fetch token from Redis storage (service doesn’t return it in prod)
    raw = await redis_client.hgetall(f"emailchg:{user.id}")
    pending = { _b2s(k): _b2s(v) for k, v in (raw or {}).items() }
    assert pending.get("new_email") == new_email
    token = pending.get("token")
    assert token and len(token) >= 16

    # Confirm with fresh step-up (do not assume one-time; be robust)
    headers_confirm = (await bearer(user, session_id=sid_keep)) | {"X-Reauth": make_reauth_token(user_id=user.id, session_id=sid_keep, mfa=True)}

    r2 = await async_client.post(
        f"{BASE}/email/change/confirm", headers=headers_confirm | ip_header(212), json={"token": token}
    )
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body.get("email") == new_email

    # DB reflects new email (+ is_verified=True if model supports it)
    db_user = (await db_session.execute(select(User).where(User.id == user.id))).scalar_one()
    assert db_user.email == new_email
    if hasattr(db_user, "is_verified"):
        assert db_user.is_verified is True

    # Redis key cleared
    assert await redis_client.exists(f"emailchg:{user.id}") in (0, False)

    # Sessions hygiene: current remains, other revoked
    assert await redis_client.sismember(f"session:{user.id}", j_keep)
    assert not await redis_client.sismember(f"session:{user.id}", j_other)
    assert await redis_client.exists(f"revoked:jti:{j_other}") in (1, True)

@pytest.mark.anyio
async def test_email_change_start_requires_step_up(
    async_client: AsyncClient, create_test_user, db_session: AsyncSession
):
    user = await create_test_user(is_verified=True)
    headers = await bearer(user, session_id=str(uuid4()))
    r = await async_client.post(
        f"{BASE}/email/change/start",
        headers=headers | ip_header(221),
        json={"new_email": f"n_{uuid4().hex[:8]}@example.com"},
    )
    assert r.status_code in (401, 403)

@pytest.mark.anyio
async def test_email_change_start_rejects_existing_email(
    async_client: AsyncClient, create_test_user, redis_client, db_session: AsyncSession
):
    user1 = await create_test_user(is_verified=True)
    user2 = await create_test_user(is_verified=True)  # we’ll attempt to take this email
    await set_user_password(db_session, user1, "PwdZ1!")
    sid = str(uuid4())
    headers = (await bearer(user1, session_id=sid)) | {"X-Reauth": make_reauth_token(user_id=user1.id, session_id=sid, mfa=True)}

    r = await async_client.post(
        f"{BASE}/email/change/start",
        headers=headers | ip_header(222),
        json={"new_email": user2.email, "current_password": "PwdZ1!"},
    )
    assert r.status_code == 400
    assert "already in use" in r.text.lower()

@pytest.mark.anyio
async def test_email_change_confirm_invalid_token(
    async_client: AsyncClient, create_test_user, redis_client, db_session: AsyncSession
):
    user = await create_test_user(is_verified=True)
    await set_user_password(db_session, user, "PwdX1!")
    sid = str(uuid4())
    headers = (await bearer(user, session_id=sid)) | {"X-Reauth": make_reauth_token(user_id=user.id, session_id=sid, mfa=True)}

    # Start to create pending state
    new_email = f"take_{uuid4().hex[:6]}@example.com"
    r1 = await async_client.post(
        f"{BASE}/email/change/start",
        headers=headers | ip_header(231),
        json={"new_email": new_email, "current_password": "PwdX1!"},
    )
    assert r1.status_code == 200

    # Confirm with wrong token
    r2 = await async_client.post(
        f"{BASE}/email/change/confirm",
        headers=headers | ip_header(232),
        json={"token": "not-the-right-token"},
    )
    assert r2.status_code == 400
    # Pending still exists
    assert await redis_client.exists(f"emailchg:{user.id}") in (1, True)

@pytest.mark.anyio
async def test_email_change_confirm_requires_step_up(
    async_client: AsyncClient, create_test_user, redis_client, db_session: AsyncSession
):
    user = await create_test_user(is_verified=True)
    await set_user_password(db_session, user, "PwdY1!")
    sid = str(uuid4())
    headers = await bearer(user, session_id=sid)

    # Create pending
    r1 = await async_client.post(
        f"{BASE}/email/change/start",
        headers=(headers | {"X-Reauth": make_reauth_token(user_id=user.id, session_id=sid, mfa=True)} ) | ip_header(241),
        json={"new_email": f"change_{uuid4().hex[:6]}@example.com", "current_password": "PwdY1!"},
    )
    assert r1.status_code == 200
    raw = await redis_client.hgetall(f"emailchg:{user.id}")
    pending = { _b2s(k): _b2s(v) for k, v in (raw or {}).items() }
    token = pending.get("token")
    assert token

    # Try confirm without step-up header
    r2 = await async_client.post(
        f"{BASE}/email/change/confirm",
        headers=headers | ip_header(242),
        json={"token": token},
    )
    assert r2.status_code in (401, 403)

@pytest.mark.anyio
async def test_email_change_confirm_without_pending_is_client_error(
    async_client: AsyncClient, create_test_user, db_session: AsyncSession
):
    user = await create_test_user(is_verified=True)
    sid = str(uuid4())
    headers = (await bearer(user, session_id=sid)) | {
        "X-Reauth": make_reauth_token(user_id=user.id, session_id=sid, mfa=True)
    }

    r = await async_client.post(
        f"{BASE}/email/change/confirm",
        headers=headers | ip_header(251),
        json={"token": "whatever"},
    )

    # Some implementations use 400 (“no pending”), others 422 (validation-ish).
    assert r.status_code in (400, 422)

    # Be flexible on the payload text, but still verify it’s a meaningful client error.
    if r.status_code == 400:
        assert "pending" in r.text.lower() or "no pending" in r.text.lower()
    else:  # 422
        # Typical FastAPI/Pydantic validation message or custom detail
        assert (
            "field" in r.text.lower()
            or "token" in r.text.lower()
            or "code" in r.text.lower()
            or "pending" in r.text.lower()
        )
