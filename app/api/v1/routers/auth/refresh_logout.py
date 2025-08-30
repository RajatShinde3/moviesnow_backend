# app/api/v1/auth/refresh_logout.py

"""
Refresh & Logout API — hardened, production-grade (MoviesNow, org-free)
=====================================================================

Overview
--------
This router exposes endpoints to **rotate refresh tokens**, **revoke tokens**,
and **log out** users. It emphasizes token-reuse detection, bounded session
fan-out, consistent auditing, and strict “no-store” cache headers.

Endpoints
---------
POST /refresh-token
    Rotate a valid refresh token, mint a new access token, and register a new
    refresh token (rotation). Detects reuse via Redis + DB and blocks it.

POST /revoke-token
    Revoke refresh tokens for a target user (self or **superuser**).

POST /logout
    Revoke the provided refresh token (or **all** sessions) and log out.

Security & Hardening
--------------------
- **Token reuse detection:** Redis keys `revoked:jti:*` (fast path) plus
  authoritative DB checks. Reuse events are *audited* and blocked.
- **Per-user session cap:** Configurable (default 5) with eviction of surplus.
- **Sensitive cache headers:** `Cache-Control: no-store` on token-bearing responses.
- **Centralized JWT decoding:** Neutral, consistent error semantics.
- **Defensive Redis usage:** Fail-safe wrappers; outages don’t break requests.
- **Session metadata:** `sessionmeta:{jti}` stored in Redis for `/sessions` UX.
- **Audit trail:** Best-effort success/failure records with IP/User-Agent.

MoviesNow Variant (org-free)
----------------------------
- No tenant/org claims; admin operations are **superuser-only**.
- Uses shared helpers from `app.core.jwt` and `app.core.security`.
"""

# ──────────────────────────────────────────────────────────────────────────────
# 📦 Imports
# ──────────────────────────────────────────────────────────────────────────────

import logging
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from jose import jwt as jose_jwt
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.jwt import decode_token
from app.core.limiter import rate_limit
from app.core.redis_client import redis_wrapper
from app.core.security import (
    create_access_token,
    create_refresh_token,
    get_current_user,
)
from app.db.models.token import RefreshToken
from app.db.models.user import User
from app.db.session import get_async_db
from app.schemas.auth import (
    LogoutRequest,
    MessageResponse,
    RefreshTokenRequest,
    TokenResponse,
    TokenRevokeRequest,
)
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import AuditEvent, log_audit_event
from app.services.token_service import revoke_all_refresh_tokens, store_refresh_token

router = APIRouter(tags=["Tokens & Sessions"])
logger = logging.getLogger("moviesnow.auth.refresh_logout")

# Tunables
MAX_SESSIONS = getattr(settings, "MAX_CONCURRENT_SESSIONS", 5)


# ──────────────────────────────────────────────────────────────────────────────
# 🧰 Helpers (Redis + safe request for audit)
# ──────────────────────────────────────────────────────────────────────────────

def _rc():
    """Return the shared Redis client (mock or real), or None."""
    try:
        return getattr(redis_wrapper, "client", None)
    except Exception:
        return None


def _safe_request(request: Optional[Request]) -> Optional[Request]:
    """
    Return the request only if the IPs look valid; otherwise, return None.

    We validate both X-Forwarded-For/X-Real-IP (first hop) and client.host,
    because the audit DB may store an inet field and explode on bad inputs
    like "127.0.0.300".
    """
    try:
        if not request:
            return None
        # Validate forwarded header first (what audit code typically prefers)
        fwd = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip")
        if fwd:
            ip_address(fwd.split(",")[0].strip())
        # Validate ASGI client host if present
        if getattr(request, "client", None) and getattr(request.client, "host", None):
            ip_address(request.client.host)
        return request
    except Exception:
        return None


async def _redis_smembers_str(key: str) -> set[str]:
    rc = _rc()
    if not rc:
        return set()
    try:
        members = await rc.smembers(key)
        return {m.decode() if isinstance(m, (bytes, bytearray)) else str(m) for m in members}
    except Exception:
        return set()


async def _redis_sadd(key: str, *values: str) -> None:
    rc = _rc()
    if not rc:
        return
    try:
        for v in values:
            await rc.sadd(key, v)  # some mocks support only single-arg sadd
    except Exception:
        pass


async def _redis_srem(key: str, *values: str) -> None:
    rc = _rc()
    if not rc:
        return
    try:
        for v in values:
            await rc.srem(key, v)
    except Exception:
        pass


async def _redis_setex(key: str, ttl: int, value: str) -> None:
    rc = _rc()
    if not rc or ttl <= 0:
        return
    try:
        await rc.setex(key, ttl, value)
    except Exception:
        pass


async def _redis_exists(key: str) -> bool:
    rc = _rc()
    if not rc:
        return False
    try:
        if hasattr(rc, "exists"):
            return bool(await rc.exists(key))
        val = await rc.get(key)
        return val is not None
    except Exception:
        return False


async def _redis_del(key: str) -> None:
    rc = _rc()
    if not rc:
        return
    try:
        if hasattr(rc, "delete"):
            await rc.delete(key)
            return
        # mock fallback: clear a set or poison with tiny TTL
        if hasattr(rc, "smembers") and hasattr(rc, "srem"):
            members = await rc.smembers(key)
            for m in list(members):
                await rc.srem(key, m)
        if hasattr(rc, "setex"):
            await rc.setex(key, 1, "")
    except Exception:
        pass


def _exp_to_ttl(exp: Optional[int]) -> int:
    """Compute remaining lifetime in seconds from a JWT `exp` (unix seconds)."""
    if not exp:
        return 0
    now = int(datetime.now(timezone.utc).timestamp())
    return max(0, int(exp) - now)


# ──────────────────────────────────────────────────────────────────────────────
# 🔄 POST /refresh-token — Rotate Access/Refresh Tokens
# ──────────────────────────────────────────────────────────────────────────────

@router.post(
    "/refresh-token",
    response_model=TokenResponse,
    summary="Rotate refresh token and mint a new access token",
)
@rate_limit("20/minute")
async def refresh_token_route(
    payload: RefreshTokenRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
) -> TokenResponse:
    """
    Rotate a valid **refresh token** and issue a **new access token** plus a **new
    refresh token** bound to the same session lineage.

    Behavior
    --------
    - **Validates** incoming refresh token (signature, required claims, `typ/token_type == "refresh"`).
    - **Reuse detection**: denies if JTI is already revoked (`revoked:jti:{jti}`) or DB shows revoked/expired.
    - **Revokes** the presented refresh token (DB + Redis) and **mints** a replacement bound to the same `session_id`.
    - **Registers** the new refresh JTI and **enforces session caps** by evicting surplus.
    - **Writes session metadata** into Redis (`sessionmeta:{jti}`) for session inventory UX.
    - **Issues** a short-lived **access token** (org-free) with `mfa_authenticated=True`.
    - **Audits** success/failure with IP and User-Agent metadata.
    - **Prevents caching** of token material (`Cache-Control: no-store`).

    Returns
    -------
    TokenResponse: `{ access_token, refresh_token, token_type="bearer" }`
    """
    # Harden response caching
    set_sensitive_cache(response)

    # [Step 0A] Pre-decode fast path: if JTI appears revoked in Redis → "reused"
    try:
        unverified = jose_jwt.get_unverified_claims(payload.refresh_token)
        pre_jti = str(unverified.get("jti") or "")
        pre_sub = unverified.get("sub")
        if pre_jti and await _redis_exists(f"revoked:jti:{pre_jti}"):
            await _redis_srem(f"session:{pre_sub}", pre_jti)
            try:
                await log_audit_event(
                    db,
                    action=AuditEvent.REFRESH_TOKEN,
                    status="REUSE_DETECTED",
                    request=_safe_request(request),
                    meta_data={"jti": pre_jti},
                )
            except Exception:
                pass
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token was reused")
    except Exception:
        # Not a JWT or no jti → continue to normal flow
        pass

    # [Step 1] Decode & validate incoming refresh token (centralized helper)
    try:
        decoded = await decode_token(payload.refresh_token, expected_types=["refresh"])  # type: ignore[arg-type]
        user_id = UUID(str(decoded.get("sub")))
        jti = str(decoded.get("jti"))
        parent_jti = decoded.get("parent_jti")
        session_id = decoded.get("session_id") or jti  # lineage fallback
    except Exception:
        # Try a second chance reuse detection on decode failure
        try:
            unverified = jose_jwt.get_unverified_claims(payload.refresh_token)
            ujti = str(unverified.get("jti") or "")
            if ujti and await _redis_exists(f"revoked:jti:{ujti}"):
                try:
                    await log_audit_event(
                        db,
                        action=AuditEvent.REFRESH_TOKEN,
                        status="REUSE_DETECTED",
                        request=_safe_request(request),
                        meta_data={"jti": ujti, "decode_failed": True},
                    )
                except Exception:
                    pass
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token was reused")
        except Exception:
            pass
        try:
            await log_audit_event(
                db,
                action=AuditEvent.REFRESH_TOKEN,
                status="FAILURE",
                request=_safe_request(request),
                meta_data={"reason": "decode/claims"},
            )
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # [Step 2] Reuse detection (Redis fast-path after decode)
    redis_jti_key = f"revoked:jti:{jti}"
    if await _redis_exists(redis_jti_key):
        await _redis_srem(f"session:{user_id}", jti)
        try:
            await log_audit_event(
                db,
                action=AuditEvent.REFRESH_TOKEN,
                status="REUSE_DETECTED",
                request=_safe_request(request),
                meta_data={
                    "jti": jti,
                },
            )
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token was reused")

    # [Step 3] DB validity check (exists, not revoked, not expired)
    try:
        db_token = (
            await db.execute(
                select(RefreshToken).where(RefreshToken.jti == jti, RefreshToken.user_id == user_id)
            )
        ).scalar_one_or_none()
    except Exception:
        try:
            await log_audit_event(
                db,
                action=AuditEvent.REFRESH_TOKEN,
                status="FAILURE",
                request=_safe_request(request),
                meta_data={"reason": "db_error_lookup"},
            )
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalid or reused")

    if not db_token or db_token.is_revoked:
        await _redis_srem(f"session:{user_id}", jti)
        try:
            await log_audit_event(
                db,
                action=AuditEvent.REFRESH_TOKEN,
                status="FAILURE",
                request=_safe_request(request),
                meta_data={"reason": "missing_or_revoked"},
            )
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalid or reused")

    now_utc = datetime.now(timezone.utc)
    if db_token.expires_at <= now_utc:
        try:
            await log_audit_event(
                db,
                action=AuditEvent.REFRESH_TOKEN,
                status="FAILURE",
                request=_safe_request(request),
                meta_data={"reason": "expired"},
            )
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")

    # [Step 4] Revoke the presented refresh token (DB + Redis)
    remaining_ttl = max(0, int((db_token.expires_at - now_utc).total_seconds()))
    await _redis_setex(redis_jti_key, remaining_ttl, "revoked")
    await _redis_srem(f"session:{user_id}", jti)
    db_token.is_revoked = True
    await db.commit()

    # [Step 5] Mint new refresh token (same session lineage)
    refresh_data = await create_refresh_token(user_id=user_id, parent_jti=jti, session_id=session_id)

    # [Step 6] Register new session JTI in Redis
    session_key = f"session:{user_id}"
    await _redis_sadd(session_key, refresh_data["jti"])

    # [Step 6A] Write session metadata (for /sessions UX) — best-effort
    try:
        rc = _rc()
        if rc:
            new_jti = refresh_data["jti"]
            ttl_seconds_to_refresh_expiry = max(
                0, int((refresh_data["expires_at"] - datetime.now(timezone.utc)).total_seconds())
            )
            await rc.hset(
                f"sessionmeta:{new_jti}",
                mapping={
                    "session_id": session_id or new_jti,
                    "ip": (getattr(request.client, "host", "") or ""),
                    "ua": (request.headers.get("User-Agent", "") or ""),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                },
            )
            await rc.expire(f"sessionmeta:{new_jti}", ttl_seconds_to_refresh_expiry)
    except Exception:
        pass  # never fail rotation on metadata issues

    # [Step 7] Enforce per-user session cap (evict surplus)
    session_jtis = await _redis_smembers_str(session_key)
    if len(session_jtis) > MAX_SESSIONS:
        surplus = len(session_jtis) - MAX_SESSIONS
        evict_candidates = [sid for sid in session_jtis if sid != refresh_data["jti"]][:surplus]
        for sid in evict_candidates:
            await _redis_setex(
                f"revoked:jti:{sid}",
                int(getattr(settings, "REFRESH_TOKEN_EXPIRE_DAYS", 7)) * 86400,
                "revoked",
            )
            await _redis_srem(session_key, sid)
            try:
                rc = _rc()
                if rc:
                    await rc.delete(f"sessionmeta:{sid}")
            except Exception:
                pass

    # [Step 8] Persist new refresh token (DB)
    await store_refresh_token(
        db=db,
        user_id=user_id,
        token=refresh_data["token"],  # hashed inside store_refresh_token
        jti=refresh_data["jti"],
        expires_at=refresh_data["expires_at"],
        parent_jti=refresh_data.get("parent_jti"),
        ip_address=getattr(request.client, "host", None),
    )

    # [Step 9] Mint org-free access token
    access_token = await create_access_token(
        user_id=user_id,
        mfa_authenticated=True,
        session_id=session_id,
    )

    # [Step 10] Audit & respond
    try:
        user = await db.get(User, user_id)
        await log_audit_event(
            db,
            action=AuditEvent.REFRESH_TOKEN,
            user=user,
            status="SUCCESS",
            request=_safe_request(request),
            meta_data={"new_jti": refresh_data["jti"], "parent_jti": parent_jti, "session_id": session_id},
        )
    except Exception:
        pass

    return TokenResponse(access_token=access_token, refresh_token=refresh_data["token"], token_type="bearer")


# ──────────────────────────────────────────────────────────────────────────────
# 🚪 POST /revoke-token — Revoke Tokens (Self or Superuser)
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/revoke-token", response_model=MessageResponse, summary="Revoke refresh tokens for a user")
@rate_limit("10/minute")
async def revoke_token(
    request: Request,
    response: Response,
    payload: TokenRevokeRequest,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> MessageResponse:
    """
    Revoke refresh tokens for the target user.

    Authorization
    -------------
    - The **user themselves** can revoke their own tokens.
    - A **superuser** may revoke tokens for any user.
    """
    set_sensitive_cache(response)

    # [Step 0] AuthZ check (org-free)
    if payload.user_id != current_user.id and not getattr(current_user, "is_superuser", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

    # [Step 1] Revoke via service (org-free)
    revoked_count = await revoke_all_refresh_tokens(db=db, user_id=payload.user_id)

    try:
        actor = await db.get(User, current_user.id)
    except Exception:
        actor = None

    if revoked_count == 0:
        try:
            await log_audit_event(
                db,
                user=actor,
                action=AuditEvent.REVOKE_TOKEN,
                status="NO_ACTIVE_TOKENS",
                request=_safe_request(request),
                meta_data={"target_user_id": str(payload.user_id)},
            )
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No active refresh tokens found")

    try:
        await log_audit_event(
            db,
            user=actor,
            action=AuditEvent.REVOKE_TOKEN,
            status="SUCCESS",
            request=_safe_request(request),
            meta_data={"target_user_id": str(payload.user_id), "revoked_count": revoked_count},
        )
    except Exception:
        pass
    return MessageResponse(message=f"{revoked_count} refresh token(s) revoked")


# ──────────────────────────────────────────────────────────────────────────────
# 🚪 POST /logout — Logout (Single or All Sessions)
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/logout", response_model=MessageResponse, summary="Logout by revoking one or all sessions")
@rate_limit("20/minute")
async def logout(
    payload: LogoutRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """
    Log out by revoking the presented refresh token or **all** sessions.

    Best-effort Redis cleanup is combined with authoritative DB revocation.
    """
    set_sensitive_cache(response)

    # [Step 1] Decode refresh token (for user/jti/exp if single-logout)
    try:
        decoded = await decode_token(payload.refresh_token, expected_types=["refresh"])  # type: ignore[arg-type]
        user_id = UUID(str(decoded.get("sub")))
        jti = str(decoded.get("jti"))
        exp = decoded.get("exp")
    except Exception:
        try:
            await log_audit_event(
                db,
                action=AuditEvent.LOGOUT,
                status="FAILURE",
                request=_safe_request(request),
                meta_data={"reason": "decode/claims"},
            )
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    session_key = f"session:{user_id}"
    rc = _rc()

    if payload.revoke_all:
        # [Step 2A] Revoke ALL: compute per-token TTLs from DB
        now_utc = datetime.now(timezone.utc)
        rows = (
            await db.execute(
                select(RefreshToken).where(RefreshToken.user_id == user_id, RefreshToken.is_revoked.is_(False))
            )
        ).scalars().all()

        # Redis: mark each JTI revoked with its own TTL; clear session set & metas
        if rc:
            for row in rows:
                ttl = max(0, int((row.expires_at - now_utc).total_seconds()))
                try:
                    await rc.setex(f"revoked:jti:{row.jti}", ttl, "revoked")
                    await rc.delete(f"sessionmeta:{row.jti}")
                except Exception:
                    pass
            try:
                await _redis_del(session_key)
            except Exception:
                pass

        # DB: mark all as revoked
        for row in rows:
            row.is_revoked = True
        await db.commit()

        try:
            await log_audit_event(
                db,
                action=AuditEvent.LOGOUT,
                user=await db.get(User, user_id),
                status="SUCCESS",
                request=_safe_request(request),
                meta_data={"scope": "all_sessions"},
            )
        except Exception:
            pass
        return MessageResponse(message="Logged out from all sessions")

    # [Step 2B] Revoke ONLY the presented token
    ttl = _exp_to_ttl(exp)
    await _redis_setex(f"revoked:jti:{jti}", ttl, "revoked")
    await _redis_srem(session_key, jti)
    try:
        if rc:
            await rc.delete(f"sessionmeta:{jti}")
    except Exception:
        pass

    # DB: mark the single token revoked
    await db.execute(update(RefreshToken).where(RefreshToken.jti == jti).values(is_revoked=True))
    await db.commit()

    try:
        await log_audit_event(
            db,
            action=AuditEvent.LOGOUT,
            user=await db.get(User, user_id),
            status="SUCCESS",
            request=_safe_request(request),
            meta_data={"scope": "single_session", "jti": jti},
        )
    except Exception:
        pass
    return MessageResponse(message="Logged out successfully")


__all__ = ["router", "refresh_token_route", "revoke_token", "logout"]
