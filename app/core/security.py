# app/core/security.py
from __future__ import annotations

"""
MoviesNow — Authentication & Security Helpers (org-free)
========================================================
- Strong JWT creation (iss/aud/iat/nbf/jti), refresh + access
- Redis-backed JTI lanes for fast revocation (access + refresh)
- No decode logic duplication: decoding is delegated to `app.core.jwt`
- MFA/TOTP helpers
- Clean FastAPI dependency to fetch the **current user**

This is a trimmed, MoviesNow-specific extraction of your original module
(with all organization/tenant helpers removed).
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from uuid import UUID, uuid4
import logging
import os

import pyotp
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.jwt import decode_access_token as jwt_decode_access_token  # single source of truth
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.db.models.user import User
from app.schemas.auth import TokenPayload

# ───────────────────────────────────────────────
# 🔐 Security Constants and Setup
# ───────────────────────────────────────────────
ALGORITHM: str = settings.JWT_ALGORITHM
ISSUER: Optional[str] = getattr(settings, "JWT_ISSUER", None)
AUDIENCE: Optional[str] = getattr(settings, "JWT_AUDIENCE", None)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()
logger = logging.getLogger("security")


# ───────────────────────────────────────────────
# 🔐 Password Hashing Utilities
# ───────────────────────────────────────────────
def get_password_hash(password: str) -> str:
    """Return a salted hash using Passlib's bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Constant-time verify of a plaintext password against a stored hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ───────────────────────────────────────────────
# 🎟️ JWT — Refresh Token Generation
# ───────────────────────────────────────────────
async def create_refresh_token(
    user_id: UUID,
    parent_jti: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a signed **refresh token** and register its JTI in Redis.

    Used for initial login and rotation. Includes optional `parent_jti` for
    token chaining and `session_id` for session-wide revocation.
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    jti = str(uuid4())

    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "exp": expire,
        "iat": now,
        "nbf": now,
        "jti": jti,
        "token_type": "refresh",
    }
    if ISSUER:
        payload["iss"] = ISSUER
    if AUDIENCE:
        payload["aud"] = AUDIENCE
    if parent_jti:
        payload["parent_jti"] = parent_jti
    if session_id:
        payload["session_id"] = session_id

    token = jwt.encode(payload, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=ALGORITHM)

    # Track in Redis for validity lane; revoked lane is separate
    redis_key = f"refresh:jti:{jti}"
    ttl_seconds = int((expire - now).total_seconds())
    try:
        await redis_wrapper.client.setex(redis_key, ttl_seconds, "valid")
        logger.debug("Stored refresh JTI", extra={"jti": jti, "ttl": ttl_seconds})
    except Exception as e:  # pragma: no cover — infra failures bubble up
        logger.error(f"Redis error while storing refresh JTI: {e}")
        raise

    return {"token": token, "jti": jti, "expires_at": expire, "parent_jti": parent_jti}


# ───────────────────────────────────────────────
# 🪪 JWT — Access Token Generation
# ───────────────────────────────────────────────
async def create_access_token(
    user_id: UUID,
    expires_delta: Optional[timedelta] = None,
    *,
    mfa_authenticated: bool = False,
    session_id: Optional[str] = None,
) -> str:
    """Create a signed **access token** and store its JTI in Redis for revocation."""
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    jti = str(uuid4())

    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "exp": expire,
        "iat": now,
        "nbf": now,
        "jti": jti,
        "token_type": "access",
        "mfa_authenticated": bool(mfa_authenticated),
    }
    if ISSUER:
        payload["iss"] = ISSUER
    if AUDIENCE:
        payload["aud"] = AUDIENCE
    if session_id:
        payload["session_id"] = session_id

    token = await _sign_jwt(payload, default_alg=ALGORITHM)

    # Track JTI for fast revocation checks
    redis_key = f"access:jti:{jti}"
    ttl_seconds = int((expire - now).total_seconds())
    try:
        await redis_wrapper.client.setex(redis_key, ttl_seconds, "valid")
        logger.debug("Stored access JTI", extra={"jti": jti, "ttl": ttl_seconds})
    except Exception as e:  # pragma: no cover
        logger.error(f"Redis error while storing access JTI: {e}")
        raise

    return token


# ───────────────────────────────────────────────
# 🆔 Helpers — Extract User ID from Payload
# ───────────────────────────────────────────────
def get_user_id_from_payload(payload: Dict[str, Any]) -> UUID:
    """Extract and validate `sub` as a UUID; raise 401 if malformed/missing."""
    user_id = payload.get("sub") or payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token: missing user_id")
    try:
        return UUID(str(user_id))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token: malformed user_id")


# ───────────────────────────────────────────────
# 👤 Dependency — Get Current User
# ───────────────────────────────────────────────
async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_async_db),
) -> User:
    """Authenticate a user from the presented **access** token.

    Steps:
    1) Decode & validate JWT (revocation, expiry, type) via `app.core.jwt`.
    2) Load user from DB, ensure active.
    3) Attach parsed TokenPayload to `user.token_payload` and `request.state`.
    """
    token = credentials.credentials

    # 1) Decode & validate (delegated)
    payload = await jwt_decode_access_token(token)
    user_id = get_user_id_from_payload(payload)

    # 2) Load user
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    if not user or not user.is_active:
        raise HTTPException(status_code=403, detail="Inactive or missing user")

    # 3) Attach payload to user/request
    try:
        user.token_payload = TokenPayload(**payload)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid token payload structure")

    request.state.user_id = user.id
    request.state.token_payload = user.token_payload

    logger.debug("[Auth] Authenticated", extra={"user_id": str(user.id)})
    return user


# ───────────────────────────────────────────────
# 🔢 TOTP/MFA Helpers
# ───────────────────────────────────────────────
TOTP_STEP_SECONDS = int(getattr(settings, "TOTP_STEP_SECONDS", 30))
TOTP_DIGITS = int(getattr(settings, "TOTP_DIGITS", 6))


def generate_totp(secret: str) -> pyotp.TOTP:
    """Return a TOTP object for verifying MFA codes (default 30s window)."""
    return pyotp.TOTP(secret, interval=TOTP_STEP_SECONDS, digits=TOTP_DIGITS)


def generate_mfa_token(user_id: str, expires_in_minutes: int = 5) -> str:
    """Create a short-lived JWT used as MFA proof (not an access token)."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=expires_in_minutes)
    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "exp": expire,
        "iat": now,
        "nbf": now,
        "jti": str(uuid4()),
        "type": "mfa_token",
        "mfa_pending": True,
    }
    if ISSUER:
        payload["iss"] = ISSUER
    if AUDIENCE:
        payload["aud"] = AUDIENCE

    return jwt.encode(payload, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=ALGORITHM)


async def _sign_jwt(payload: Dict[str, Any], *, default_alg: str) -> str:
    """
    Sign a JWT using RS256 private JWK when `JWT_SIGN_WITH_JWKS=1` and available;
    otherwise fall back to HS secret with configured algorithm.
    """
    if str(getattr(settings, "JWT_SIGN_WITH_JWKS", os.getenv("JWT_SIGN_WITH_JWKS", "0"))).lower() in {"1", "true", "yes", "on"}:
        try:
            from app.services.jwks_service import get_active_private_jwk  # local import to avoid cycles
            jwk = await get_active_private_jwk()
            if isinstance(jwk, dict) and jwk.get("kty") in {"RSA", "EC"}:
                alg = jwk.get("alg") or "RS256"
                return jwt.encode(payload, jwk, algorithm=alg)
        except Exception:
            logger.warning("JWKS signing unavailable; falling back to HS secret")
    return jwt.encode(payload, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=default_alg)


__all__ = [
    "get_password_hash",
    "verify_password",
    "create_refresh_token",
    "create_access_token",
    "get_user_id_from_payload",
    "get_current_user",
    "generate_totp",
    "generate_mfa_token",
]
