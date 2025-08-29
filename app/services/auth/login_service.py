# app/services/auth/login_service.py
from __future__ import annotations

"""
Login service — MoviesNow (org‑free, hardened)
==============================================

What this module provides
-------------------------
- **Email + password login** that is MFA‑aware (no org context).
- **MFA challenge flow** (short‑lived JWT) + **MFA finalize** with TOTP.
- **Neutral errors** to avoid user enumeration.
- **Redis‑backed rate limits** (per identifier and per IP) with graceful degradation.
- **Idempotency** using an `Idempotency-Key` header (best‑effort snapshot in Redis).
- Strict JWT handling for the MFA challenge (iss/aud/iat/nbf/exp/jti).
- **Session lineage**: refresh minted first, then `sessionmeta:{jti}`, then access token.
- **Activity stream**: compact events pushed to a Redis ring buffer.

Assumptions
-----------
- Redis tools: `app.utils.redis_utils.enforce_rate_limit`, `idempotency_get`, `idempotency_set`.
- Token helpers: `create_access_token` / `create_refresh_token`; refresh tokens are persisted
  hashed by `store_refresh_token`.
- MFA helper: `generate_totp` returns a `pyotp.TOTP`‑compatible object.
- `AuditEvent` enum and `log_audit_event` available from audit service.
"""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Optional
from uuid import UUID, uuid4
import json

from fastapi import HTTPException, Request, status
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.schemas.auth import LoginRequest, TokenResponse, MFALoginRequest, MFAChallengeResponse
from app.db.models.user import User
from app.core.security import (
    verify_password,
    create_refresh_token,
    create_access_token,
    generate_totp,
)
from app.services.token_service import store_refresh_token
from app.services.audit_log_service import log_audit_event, AuditEvent
from app.core.redis_client import redis_wrapper
import app.utils.redis_utils as redis_utils


# ─────────────────────────────────────────────────────────────
# 🔧 Helpers
# ─────────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _client_ip(request: Optional[Request]) -> str:
    """Best‑effort client IP for rate limiting (X‑Forwarded‑For aware)."""
    try:
        if not request:
            return "-"
        fwd = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip")
        if fwd:
            return fwd.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
    except Exception:
        pass
    return "-"


def _norm_email(email: str) -> str:
    return (email or "").strip().lower()


async def _register_session_and_meta(
    user_id: UUID,
    refresh_data: dict,
    session_id: str,
    request: Request,
) -> None:
    """Register the new refresh JTI under session set and write `sessionmeta:{jti}`.
    TTL matches refresh expiry. Best‑effort (never raises outward).
    """
    try:
        r = redis_wrapper.client
        jti = refresh_data["jti"]
        await r.sadd(f"session:{user_id}", jti)
        ttl = max(0, int((refresh_data["expires_at"] - _now_utc()).total_seconds()))
        await r.hset(
            f"sessionmeta:{jti}",
            mapping={
                "session_id": session_id,
                "ip": (request.client.host if request.client else "") or "",
                "ua": (request.headers.get("User-Agent") or ""),
                "created_at": _now_utc().isoformat(),
                "last_seen": _now_utc().isoformat(),
            },
        )
        await r.expire(f"sessionmeta:{jti}", ttl)
    except Exception:
        pass


async def _push_activity_event(user_id: UUID, action: str, session_id: str, request: Request, jti: str) -> None:
    """Push a compact activity event into the user's Redis ring buffer (best‑effort)."""
    try:
        evt = {
            "id": jti,
            "at": _now_utc().isoformat(),
            "action": action,
            "status": "SUCCESS",
            "ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("User-Agent"),
            "meta": {"session_id": session_id},
        }
        key = f"audit:recent:{user_id}"
        r = redis_wrapper.client
        await r.rpush(key, json.dumps(evt))
        await r.ltrim(key, -int(getattr(settings, "ACTIVITY_RING_MAX", 200)), -1)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────
# 🔐 Email + Password login (MFA‑aware, org‑free)
# ─────────────────────────────────────────────────────────────
async def login_user(
    payload: LoginRequest,
    db: AsyncSession,
    request: Request,
) -> TokenResponse | MFAChallengeResponse:
    """
    Authenticate a user by email and password; either return tokens directly or
    start an MFA challenge.

    Security properties
    -------------------
    - **Neutral errors** on user lookup and password mismatch.
    - **Throttling** per email and per IP (Redis Lua); graceful on Redis hiccups.
    - **Idempotency**: if `Idempotency-Key` is provided, previously produced response
      is replayed (best‑effort) within a short TTL.
    - **No org logic**: any `org_id` in the request is ignored (MoviesNow is org‑free).
    """
    now = _now_utc()
    client_ip = _client_ip(request)
    email_norm = _norm_email(payload.email)

    # ── [Step 1] Throttle attempts per email & per IP ─────────────────────────
    try:
        await redis_utils.enforce_rate_limit(
            key_suffix=f"login:email:{sha256(email_norm.encode()).hexdigest()}",
            seconds=60,
            max_calls=5,
            error_message="Too many attempts. Please try again shortly.",
        )
        await redis_utils.enforce_rate_limit(
            key_suffix=f"login:ip:{client_ip}",
            seconds=60,
            max_calls=20,
            error_message="Too many attempts. Please try again shortly.",
        )
    except Exception:
        # Graceful degradation on Redis hiccups; route‑level throttles may still apply
        pass

    # ── [Step 2] (Optional) Idempotency replay ───────────────────────────────
    idem_key = request.headers.get("Idempotency-Key")
    if idem_key:
        try:
            snap = await redis_utils.idempotency_get(f"idem:login:{idem_key}")
            if snap:
                return TokenResponse(**snap) if "access_token" in snap else MFAChallengeResponse(**snap)
        except Exception:
            pass

    # ── [Step 3] Lookup user (neutral error on miss) ─────────────────────────
    user = (await db.execute(select(User).where(User.email == email_norm))).scalar_one_or_none()
    if not user:
        await log_audit_event(
            db,
            user=None,
            action=AuditEvent.LOGIN,
            status="FAILURE",
            request=request,
            meta_data={"reason": "user_not_found", "email_sha256": sha256(email_norm.encode()).hexdigest()},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    # ── [Step 4] Verify password (timing‑safe) ───────────────────────────────
    if not verify_password(payload.password, user.hashed_password):
        await log_audit_event(
            db, user=user, action=AuditEvent.LOGIN, status="FAILURE", request=request, meta_data={"reason": "invalid_password"}
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    # ── [Step 5] Account gates: verified & active ────────────────────────────
    if not getattr(user, "is_verified", False):
        await log_audit_event(
            db, user=user, action=AuditEvent.LOGIN, status="FAILURE", request=request, meta_data={"reason": "email_not_verified"}
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not verified")

    if not getattr(user, "is_active", True):
        await log_audit_event(
            db, user=user, action=AuditEvent.LOGIN, status="FAILURE", request=request, meta_data={"reason": "account_deactivated"}
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")

    # ── [Step 6] MFA challenge if enabled ────────────────────────────────────
    if getattr(user, "mfa_enabled", False):
        mfa_claims = {
            "iss": getattr(settings, "JWT_ISSUER", "moviesnow"),
            "aud": getattr(settings, "JWT_AUDIENCE", "moviesnow-clients"),
            "sub": str(user.id),
            # Use both for cross‑compat: token_type/typ + legacy "type"
            "token_type": "mfa",
            "typ": "mfa",
            "type": "mfa_token",
            "mfa_pending": True,
            "jti": str(uuid4()),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        }
        mfa_token = jwt.encode(mfa_claims, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=settings.JWT_ALGORITHM)
        await log_audit_event(db, user=user, action=AuditEvent.LOGIN, status="MFA_REQUIRED", request=request)
        resp = MFAChallengeResponse(mfa_token=mfa_token)
        if idem_key:
            try:
                await redis_utils.idempotency_set(f"idem:login:{idem_key}", resp.model_dump(), ttl_seconds=600)
            except Exception:
                pass
        return resp

    # ── [Step 7] Issue refresh first (to derive session lineage) ─────────────
    refresh_data = await create_refresh_token(user.id)
    session_id = refresh_data.get("session_id") or refresh_data["jti"]

    # ── [Step 7a] Register session JTI + metadata in Redis ───────────────────
    await _register_session_and_meta(user.id, refresh_data, session_id, request)

    # ── [Step 8] Persist refresh token (hashed at rest) ──────────────────────
    await store_refresh_token(
        db=db,
        user_id=user.id,
        token=refresh_data["token"],  # stored hashed inside store_refresh_token
        jti=refresh_data["jti"],
        expires_at=refresh_data["expires_at"],
        parent_jti=refresh_data.get("parent_jti"),
        ip_address=(request.client.host if request.client else None),
    )

    # ── [Step 9] Issue access token bound to this session ────────────────────
    access_token = await create_access_token(
        user_id=user.id,
        session_id=session_id,
        # MFA not required in this branch → consider satisfied for baseline UX
        mfa_authenticated=True,
    )

    # ── [Step 10] Activity ring buffer push ──────────────────────────────────
    await _push_activity_event(user.id, action="LOGIN", session_id=session_id, request=request, jti=refresh_data["jti"])

    # ── [Step 11] Audit success ─────────────────────────────────────────────
    await log_audit_event(db, user=user, action=AuditEvent.LOGIN, status="SUCCESS", request=request)

    resp = TokenResponse(access_token=access_token, refresh_token=refresh_data["token"], token_type="bearer")
    if idem_key:
        try:
            await redis_utils.idempotency_set(f"idem:login:{idem_key}", resp.model_dump(), ttl_seconds=600)
        except Exception:
            pass
    return resp


# ─────────────────────────────────────────────────────────────
# 🔐 MFA login — validate challenge + TOTP, then issue tokens
# ─────────────────────────────────────────────────────────────
async def login_with_mfa(payload: MFALoginRequest, db: AsyncSession, request: Request) -> TokenResponse:
    """
    Finalize an MFA login by verifying the challenge token and TOTP code.
    Then mint refresh (→ sessionmeta) and an access token bound to the lineage.

    Security properties
    -------------------
    - **Strict JWT decode**: audience required; `iss` verified manually; claims
      must indicate MFA (`token_type`/`typ`/`type`) and `mfa_pending=True`.
    - **TOTP** verified with a small drift window; never logs the provided code.
    - **No org context** is processed.
    - **Throttle** per‑user and per‑IP to slow guessing attacks.
    """
    # ── [Step 0] Throttle MFA finalize per IP (and later per user) ───────────
    try:
        await redis_utils.enforce_rate_limit(
            key_suffix=f"mfa_finalize:ip:{_client_ip(request)}",
            seconds=60,
            max_calls=60,
            error_message="Too many attempts. Please try again shortly.",
        )
    except Exception:
        pass

    # ── [Step 1] Decode MFA challenge ────────────────────────────────────────
    try:
        decoded = jwt.decode(
            payload.mfa_token,
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM],
            audience=getattr(settings, "JWT_AUDIENCE", "moviesnow-clients"),
            options={"require": ["exp", "sub"]},
        )
    except ExpiredSignatureError:
        await log_audit_event(db, user=None, action=AuditEvent.LOGIN, status="MFA_TOKEN_EXPIRED", request=request)
        raise HTTPException(status_code=401, detail="MFA token has expired")
    except JWTError:
        await log_audit_event(db, user=None, action=AuditEvent.LOGIN, status="MFA_TOKEN_INVALID", request=request)
        raise HTTPException(status_code=401, detail="Invalid MFA token")

    # Manual issuer + type checks (be liberal in what we accept, strict in verify)
    if decoded.get("iss") != getattr(settings, "JWT_ISSUER", "moviesnow"):
        await log_audit_event(db, user=None, action=AuditEvent.LOGIN, status="MFA_TOKEN_ISS_MISMATCH", request=request)
        raise HTTPException(status_code=401, detail="Invalid MFA token")
    tok_typ = (decoded.get("token_type") or decoded.get("typ") or decoded.get("type") or "").lower()
    if tok_typ not in ("mfa", "mfa_token"):
        await log_audit_event(db, user=None, action=AuditEvent.LOGIN, status="MFA_TOKEN_INVALID_FORMAT", request=request)
        raise HTTPException(status_code=401, detail="MFA token invalid or expired")
    if not decoded.get("mfa_pending"):
        await log_audit_event(db, user=None, action=AuditEvent.LOGIN, status="MFA_TOKEN_NOT_PENDING", request=request)
        raise HTTPException(status_code=401, detail="MFA token invalid or expired")

    user_id = UUID(str(decoded.get("sub")))

    # ── [Step 2] Throttle per user now that we know who they are ─────────────
    try:
        await redis_utils.enforce_rate_limit(
            key_suffix=f"mfa_finalize:user:{user_id}",
            seconds=60,
            max_calls=20,
            error_message="Too many attempts. Please try again shortly.",
        )
    except Exception:
        pass

    # ── [Step 3] Load user & guardrails ──────────────────────────────────────
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        await log_audit_event(
            db, user=None, action=AuditEvent.LOGIN, status="MFA_USER_NOT_FOUND", request=request, meta_data={"user_id": str(user_id)}
        )
        raise HTTPException(status_code=404, detail="User not found")

    if not getattr(user, "mfa_enabled", False) or not getattr(user, "totp_secret", None):
        await log_audit_event(db, user=user, action=AuditEvent.LOGIN, status="MFA_NOT_ENABLED", request=request)
        raise HTTPException(status_code=400, detail="MFA not enabled")

    # ── [Step 4] Verify TOTP (never log the code) ────────────────────────────
    totp = generate_totp(user.totp_secret)
    if not totp.verify(payload.totp_code, valid_window=1):
        await log_audit_event(
            db, user=user, action=AuditEvent.LOGIN, status="MFA_INVALID_CODE", request=request, meta_data={"totp_attempt": "***redacted***"}
        )
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    # ── [Step 5] Issue refresh first → register sessionmeta → access ─────────
    refresh_data = await create_refresh_token(user.id)
    session_id = refresh_data.get("session_id") or refresh_data["jti"]

    await _register_session_and_meta(user.id, refresh_data, session_id, request)

    await store_refresh_token(
        db=db,
        user_id=user.id,
        token=refresh_data["token"],
        jti=refresh_data["jti"],
        expires_at=refresh_data["expires_at"],
        parent_jti=refresh_data.get("parent_jti"),
        ip_address=(request.client.host if request.client else None),
    )

    access_token = await create_access_token(
        user_id=user.id,
        mfa_authenticated=True,
        session_id=session_id,
    )

    # ── [Step 6] Activity ring + audit ───────────────────────────────────────
    await _push_activity_event(user.id, action="MFA_LOGIN", session_id=session_id, request=request, jti=refresh_data["jti"])

    await log_audit_event(
        db, user=user, action=AuditEvent.LOGIN, status="MFA_SUCCESS", request=request
    )

    return TokenResponse(access_token=access_token, refresh_token=refresh_data["token"], token_type="bearer")


__all__ = ["login_user", "login_with_mfa"]
