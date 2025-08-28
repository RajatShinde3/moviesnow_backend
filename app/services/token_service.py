# app/services/token_service.py

from __future__ import annotations

"""
MoviesNow — Refresh Token Service (org-free, production-grade)
=============================================================
- Stores refresh tokens as SHA-256 digests (no raw tokens at rest)
- Rotation with revocation sentinels in Redis (re-use detection)
- Per-user session cap enforcement
- Global revoke helpers

Notes:
- Uses the shared Redis wrapper (`app.core.redis_client.redis_wrapper`)
- Relies on `app.core.security.create_refresh_token` to mint refresh JWTs
"""

import logging
import hashlib
from typing import Optional, Set, List
from uuid import UUID
from datetime import datetime, timezone

from fastapi import HTTPException
from jose import jwt, JWTError
from sqlalchemy import update, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.redis_client import redis_wrapper
from app.db.models.token import RefreshToken
from app.core.security import create_refresh_token

logger = logging.getLogger("auth.token")

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────
MAX_RETRIES = 3
MAX_SESSIONS = 5  # per-user hard cap; tune via settings if needed

# Redis key helpers (standardize everywhere)
def _session_key(user_id: UUID) -> str:
    return f"session:{user_id}"

def _revoked_key(jti: str) -> str:
    return f"revoked:jti:{jti}"

# Byte → str normalization for aioredis responses
def _b2s(value) -> str:
    return value.decode() if isinstance(value, (bytes, bytearray)) else str(value)

async def _smembers_str(key: str) -> Set[str]:
    members = await redis_wrapper.client.smembers(key)
    return {_b2s(m) for m in (members or set())}


# ──────────────────────────────────────────────────────────────────────────────
# 🔐 Store Refresh Token (Async with Conflict Handling)
# ──────────────────────────────────────────────────────────────────────────────
async def store_refresh_token(
    db: AsyncSession,
    user_id: UUID,
    token: str,
    jti: str,
    expires_at: datetime,
    parent_jti: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> None:
    """
    Persist a refresh token **digest** for a user (never the raw token).
    Enforces JTI uniqueness via DB unique constraint.
    """
    token_digest = hashlib.sha256(token.encode("utf-8")).hexdigest()

    attempt = 0
    while attempt < MAX_RETRIES:
        attempt += 1
        try:
            entry = RefreshToken(
                user_id=user_id,
                token=token_digest,
                jti=jti,
                expires_at=expires_at,
                parent_jti=parent_jti,
                ip_address=ip_address,
                is_revoked=False,
                created_at=datetime.now(timezone.utc),
            )
            db.add(entry)
            await db.flush()
            await db.commit()
            return

        except IntegrityError as e:
            await db.rollback()
            msg = str(getattr(e, "orig", e)).lower()
            if "jti" in msg:
                logger.error("JTI uniqueness violation while storing token (jti=%s, user=%s)", jti, user_id)
                raise
            if attempt >= MAX_RETRIES:
                raise RuntimeError(f"Token storage error (retries exhausted): {e}") from e
            logger.warning("Retrying token store after IntegrityError (attempt %s/%s)", attempt, MAX_RETRIES)

    raise RuntimeError("Retry limit exceeded while storing refresh token.")


# ──────────────────────────────────────────────────────────────────────────────
# 🔁 Rotate Token & Revoke Old
# ──────────────────────────────────────────────────────────────────────────────
async def rotate_refresh_token(
    db: AsyncSession,
    old_jti: str,
    user_id: UUID,
    session_id: str,
    ip_address: Optional[str] = None,
) -> dict:
    """
    Rotate a refresh token: **revoke old**, **mint new**, **enforce session cap**.

    - Validates the JTI belongs to the user and is active.
    - Marks old token revoked (DB) and sets a Redis revocation sentinel
      (`revoked:jti:{old_jti}`) with remaining TTL to detect re-use.
    - Adds new JTI to `session:{user_id}` set.
    - Enforces MAX_SESSIONS with best-effort eviction (unordered SET).
    """
    # 1) Lookup presented token by JTI (and user guard)
    db_token = (
        await db.execute(
            select(RefreshToken).where(
                RefreshToken.jti == old_jti,
                RefreshToken.user_id == user_id,
            )
        )
    ).scalar_one_or_none()

    if not db_token or db_token.is_revoked:
        await redis_wrapper.client.srem(_session_key(user_id), old_jti)
        raise HTTPException(status_code=401, detail="Token invalid or reused")

    now_utc = datetime.now(timezone.utc)
    if db_token.expires_at <= now_utc:
        raise HTTPException(status_code=401, detail="Token expired")

    # 2) Revoke presented token (DB + Redis sentinel)
    db_token.is_revoked = True
    await db.commit()

    ttl = max(0, int((db_token.expires_at - now_utc).total_seconds()))
    await redis_wrapper.client.setex(_revoked_key(old_jti), ttl, "revoked")
    await redis_wrapper.client.srem(_session_key(user_id), old_jti)

    # 3) Mint a new refresh token (same session lineage)
    refresh_data = await create_refresh_token(
        user_id=user_id,
        parent_jti=old_jti,
        session_id=session_id,
    )

    # 4) Register new JTI in Redis session set
    sess_key = _session_key(user_id)
    await redis_wrapper.client.sadd(sess_key, refresh_data["jti"])

    # 5) Enforce per-user session cap (best-effort with SET)
    session_jtis = await _smembers_str(sess_key)
    if len(session_jtis) > MAX_SESSIONS:
        surplus = len(session_jtis) - MAX_SESSIONS
        evict_candidates: List[str] = [
            sid for sid in session_jtis if sid != refresh_data["jti"]
        ][:surplus]
        for sid in evict_candidates:
            await redis_wrapper.client.setex(
                _revoked_key(sid),
                int(settings.REFRESH_TOKEN_EXPIRE_DAYS) * 86400,
                "revoked",
            )
            await redis_wrapper.client.srem(sess_key, sid)

    # 6) Persist the new refresh token digest in DB
    await store_refresh_token(
        db=db,
        user_id=user_id,
        token=refresh_data["token"],            # hashed inside store_refresh_token
        jti=refresh_data["jti"],
        expires_at=refresh_data["expires_at"],
        parent_jti=refresh_data["parent_jti"],
        ip_address=ip_address,
    )

    return refresh_data


# ──────────────────────────────────────────────────────────────────────────────
# 🔒 Revoke Refresh Token by Token ID (JTI)
# ──────────────────────────────────────────────────────────────────────────────
async def revoke_refresh_token_by_jti(db: AsyncSession, jti: str) -> None:
    """Revoke a specific refresh token by its **JTI**."""
    token = await db.get(RefreshToken, jti)
    if token and not token.is_revoked:
        token.is_revoked = True
        await db.commit()
        logger.debug("🔒 Revoked refresh token with jti=%s", jti)


# ──────────────────────────────────────────────────────────────────────────────
# 🔒 Revoke All Tokens for a User (Global Logout)
# ──────────────────────────────────────────────────────────────────────────────
async def revoke_all_refresh_tokens(db: AsyncSession, user_id: UUID) -> int:
    """
    Revoke **all** active refresh tokens for a user (global sign-out).
    Returns the number of tokens revoked.
    """
    # DB mass update
    stmt = (
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.is_revoked.is_(False))
        .values(is_revoked=True)
    )
    result = await db.execute(stmt)
    await db.commit()
    revoked = result.rowcount or 0

    # Redis cleanup (best-effort)
    try:
        r = redis_wrapper.client
        sess_key = _session_key(user_id)
        jtis = await _smembers_str(sess_key)
        if jtis:
            ttl_seconds = int(settings.REFRESH_TOKEN_EXPIRE_DAYS) * 86400
            for sid in jtis:
                await r.setex(_revoked_key(sid), ttl_seconds, "revoked")
            await r.delete(sess_key)
    except Exception as e:
        logger.warning("Redis cleanup failed during revoke_all_refresh_tokens: %s", e)

    logger.debug("🔒 Revoked all tokens for user=%s (count=%s)", user_id, revoked)
    return revoked


# ──────────────────────────────────────────────────────────────────────────────
# 🧠 Decode & Validation Helpers
# ──────────────────────────────────────────────────────────────────────────────
def decode_refresh_token(token: str) -> dict:
    """
    Decode and validate a **refresh** JWT without touching DB/Redis.
    Raises ValueError on invalid signature/claims.
    """
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM],
        )
    except JWTError as e:
        raise ValueError(f"Invalid refresh token: {e}")


async def is_refresh_token_reused(db: AsyncSession, jti: str) -> bool:
    """
    Check if a refresh token **JTI** is considered reused/invalid.
    Returns True when the token record is missing or flagged revoked.
    """
    token = await db.get(RefreshToken, jti)
    return token is None or token.is_revoked
