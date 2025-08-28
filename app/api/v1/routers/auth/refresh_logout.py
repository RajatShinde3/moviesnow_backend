"""
Refresh & Logout API — hardened, production-grade
================================================

Endpoints
---------
POST /refresh-token
    Rotate a valid refresh token, issue a new access token, and register the
    new refresh token (rotation). Detects reuse via Redis + DB and blocks it.

POST /revoke-token
    Revoke refresh tokens for a target user (self or admin within same org).

POST /logout
    Revoke the provided refresh token (or **all** sessions) and log out.

Security & Hardening
--------------------
- **Token reuse detection** with Redis keys ``revoked:jti:*`` and DB checks.
- **Per-user session cap** (default 5; configurable) with automatic eviction.
- **Sensitive cache headers** set (``no-store``) on token-bearing responses.
- Careful JWT decoding using configured secret/algorithm; neutral errors.
- Defensive Redis usage: failures won't crash requests; best-effort cleanup.
- **Session metadata** in Redis (``sessionmeta:{jti}``) for /sessions UX.
- Audit trail for success/failure and suspicious events.
"""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from jose import JWTError, jwt
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.limiter import rate_limit
from app.core.security import (
    create_access_token,
    create_refresh_token,
    get_current_user,
)
from app.db.models.token import RefreshToken
from app.db.models.user import User
from app.db.models.user_organization import UserOrganization
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
from app.services.token_service import revoke_refresh_tokens_for_user, store_refresh_token
from app.core.redis_client import redis_wrapper 

router = APIRouter(tags=["Tokens & Sessions"])

# Tunables
MAX_SESSIONS = getattr(settings, "MAX_CONCURRENT_SESSIONS", 5)


# ──────────────────────────────────────────────────────────────────────────────
# Redis helpers (best-effort; tolerate Redis outages gracefully)
# ──────────────────────────────────────────────────────────────────────────────
def _rc():
    """Return the shared Redis client (mock or real)."""
    try:
        return getattr(redis_wrapper, "client", None)
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
            await rc.sadd(key, v)  # mock supports single value
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
        # mock fallback: try to clear set or set tiny ttl
        if hasattr(rc, "smembers") and hasattr(rc, "srem"):
            members = await rc.smembers(key)
            for m in list(members):
                await rc.srem(key, m)
        if hasattr(rc, "setex"):
            await rc.setex(key, 1, "")
    except Exception:
        pass


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
    Rotate a valid **refresh token** and issue a **new access token** (and a new refresh token).

    ## Behavior
    - **Validates** incoming refresh token (signature, required claims, `typ/token_type == "refresh"`).
    - **Reuse detection**: denies if the JTI is already revoked (Redis key `revoked:jti:{jti}`) or DB shows revoked/expired.
    - **Revokes** the presented refresh token (DB + Redis) and **mints** a new refresh token bound to the same `session_id`.
    - **Registers** the new refresh JTI in the user's session set and **enforces session caps** by evicting oldest surplus.
    - **Writes session metadata** into Redis (`sessionmeta:{jti}`) for session inventory UX.
    - **Issues** a short-lived **access token** with the user's most recent active org context.
    - **Audits** success/failure with IP and User-Agent metadata.
    - **Prevents caching** of token material (Cache-Control: no-store).

    ## Security Notes
    - Responds with 401 for invalid/expired/reused tokens (no token leakage).
    - Uses remaining TTL of the old token to expire the `revoked:jti:{jti}` marker.
    - Ties the new refresh token to the existing `session_id` to preserve device session lineage.

    Returns:
        TokenResponse: `{ access_token, refresh_token, token_type="bearer" }`
    """
    # ── [Step 0] Cache hardening ──────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Decode & validate incoming refresh token ─────────────────────
    try:
        decoded = jwt.decode(
            payload.refresh_token,
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["sub", "jti", "exp"]},
        )
        user_id = UUID(str(decoded.get("sub")))
        jti = str(decoded.get("jti"))
        parent_jti = decoded.get("parent_jti")
        session_id = decoded.get("session_id")
        tok_typ = (decoded.get("typ") or decoded.get("token_type") or "").lower()
        if tok_typ and tok_typ != "refresh":
            raise ValueError("Wrong token type")
        session_id = session_id or jti  # lineage fallback
    except Exception:
        await log_audit_event(
            db,
            action=AuditEvent.REFRESH_TOKEN,
            status="FAILURE",
            request=request,
            meta_data={"reason": "decode/claims"},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # ── [Step 2] Reuse detection (Redis fast-path) ────────────────────────────
    redis_jti_key = f"revoked:jti:{jti}"
    if await _redis_exists(redis_jti_key):
        await _redis_srem(f"session:{user_id}", jti)
        await log_audit_event(
            db,
            action=AuditEvent.REFRESH_TOKEN,
            status="REUSE_DETECTED",
            request=request,
            meta_data={
                "ip": getattr(request.client, "host", None),
                "user_agent": request.headers.get("User-Agent"),
                "jti": jti,
            },
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token was reused")

    # ── [Step 3] DB validity check (exists, not revoked, not expired) ─────────
    try:
        db_token = (
            await db.execute(
                select(RefreshToken).where(
                    RefreshToken.jti == jti,
                    RefreshToken.user_id == user_id,
                )
            )
        ).scalar_one_or_none()
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalid or reused")

    if not db_token or db_token.is_revoked:
        await _redis_srem(f"session:{user_id}", jti)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalid or reused")

    now_utc = datetime.now(timezone.utc)
    if db_token.expires_at <= now_utc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")

    # ── [Step 4] Revoke the presented refresh token (DB + Redis) ──────────────
    remaining_ttl = max(0, int((db_token.expires_at - now_utc).total_seconds()))
    await _redis_setex(redis_jti_key, remaining_ttl, "revoked")
    await _redis_srem(f"session:{user_id}", jti)
    db_token.is_revoked = True
    await db.commit()

    # ── [Step 5] Mint new refresh token (same session lineage) ────────────────
    refresh_data = await create_refresh_token(
        user_id=user_id,
        parent_jti=jti,
        session_id=session_id,
    )

    # ── [Step 6] Register new session JTI in Redis ────────────────────────────
    session_key = f"session:{user_id}"
    await _redis_sadd(session_key, refresh_data["jti"])

    # ── [Step 6A] Write session metadata (for /sessions UX) ───────────────────
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
                    "ip": getattr(request.client, "host", "") or "",
                    "ua": request.headers.get("User-Agent", "") or "",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                },
            )
            await rc.expire(f"sessionmeta:{new_jti}", ttl_seconds_to_refresh_expiry)
    except Exception:
        # metadata is best-effort; never fail the rotation on this
        pass

    # ── [Step 7] Enforce per-user session cap ─────────────────────────────────
    # NOTE: Redis SET is unordered; eviction is best-effort.
    session_jtis = await _redis_smembers_str(session_key)
    if len(session_jtis) > MAX_SESSIONS:
        surplus = len(session_jtis) - MAX_SESSIONS
        evict_candidates = [sid for sid in session_jtis if sid != refresh_data["jti"]][:surplus]
        for sid in evict_candidates:
            await _redis_setex(f"revoked:jti:{sid}", int(settings.REFRESH_TOKEN_EXPIRE_DAYS) * 86400, "revoked")
            await _redis_srem(session_key, sid)
            # best-effort: remove orphaned sessionmeta
            try:
                rc = _rc()
                if rc:
                    await rc.delete(f"sessionmeta:{sid}")
            except Exception:
                pass

    # ── [Step 8] Persist new refresh token (DB) ───────────────────────────────
    await store_refresh_token(
        db=db,
        user_id=user_id,
        token=refresh_data["token"],  # hashed inside store_refresh_token
        jti=refresh_data["jti"],
        expires_at=refresh_data["expires_at"],
        parent_jti=refresh_data.get("parent_jti"),
        ip_address=getattr(request.client, "host", None),
    )

    # ── [Step 9] Resolve active org context for access token ──────────────────
    user_org = (
        await db.execute(
            select(UserOrganization)
            .where(
                UserOrganization.user_id == user_id,
                UserOrganization.is_active == True,  # noqa: E712
            )
            .order_by(UserOrganization.joined_at.desc())
        )
    ).scalar_one_or_none()
    active_org = (
        {"org_id": str(user_org.organization_id), "role": user_org.role}
        if user_org
        else None
    )

    # ── [Step 10] Mint access token ───────────────────────────────────────────
    access_token = await create_access_token(
        user_id=user_id,
        active_org=active_org,
        mfa_authenticated=True,
        session_id=session_id,
    )

    # ── [Step 11] Audit & respond ─────────────────────────────────────────────
    user = await db.get(User, user_id)
    await log_audit_event(
        db,
        action=AuditEvent.REFRESH_TOKEN,
        user=user,
        status="SUCCESS",
        request=request,
        meta_data={
            "new_jti": refresh_data["jti"],
            "parent_jti": parent_jti,
            "session_id": session_id,
        },
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_data["token"],
        token_type="bearer",
    )


# ──────────────────────────────────────────────────────────────────────────────
# 🚪 POST /revoke-token — Revoke Tokens (Self or Admin)
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
    """Revoke refresh tokens for the target user.

    Only the user themselves or an admin **within the same organization** can
    perform this action.
    """
    if payload.user_id != current_user.id:
        if not getattr(current_user, "is_superuser", False):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

        # same-org constraint for admins
        admin_org = (
            await db.execute(
                select(UserOrganization).where(
                    UserOrganization.user_id == current_user.id,
                    UserOrganization.is_active == True,  # noqa: E712
                )
            )
        ).scalar_one_or_none()
        target_org = (
            await db.execute(
                select(UserOrganization).where(
                    UserOrganization.user_id == payload.user_id,
                    UserOrganization.is_active == True,  # noqa: E712
                )
            )
        ).scalar_one_or_none()
        if not admin_org or not target_org or admin_org.organization_id != target_org.organization_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Different organization")

    revoked_count = await revoke_refresh_tokens_for_user(
        db=db, user_id=payload.user_id, organization_id=payload.organization_id
    )

    actor = await db.get(User, current_user.id)
    if revoked_count == 0:
        await log_audit_event(
            db,
            user=actor,
            action=AuditEvent.REVOKE_TOKEN,
            status="NO_ACTIVE_TOKENS",
            request=request,
            meta_data={"target_user_id": str(payload.user_id)},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No active refresh tokens found")

    await log_audit_event(
        db,
        user=actor,
        action=AuditEvent.REVOKE_TOKEN,
        status="SUCCESS",
        request=request,
        meta_data={"target_user_id": str(payload.user_id), "revoked_count": revoked_count},
    )
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
    """Log out by revoking the presented refresh token or **all** sessions.

    Best-effort Redis cleanup is combined with authoritative DB revocation.
    """
    set_sensitive_cache(response)

    # ── [Step 1] Decode refresh token (for user/jti/exp if single-logout) ─────
    try:
        decoded = jwt.decode(
            payload.refresh_token,
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["sub", "jti", "exp"]},
        )
        user_id = UUID(str(decoded.get("sub")))
        jti = str(decoded.get("jti"))
        exp = int(decoded.get("exp"))
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    session_key = f"session:{user_id}"
    rc = _rc()

    if payload.revoke_all:
        # ── [Step 2A] Revoke ALL: compute per-token TTLs from DB ──────────────
        now_utc = datetime.now(timezone.utc)
        rows = (
            await db.execute(
                select(RefreshToken).where(
                    RefreshToken.user_id == user_id,
                    RefreshToken.is_revoked.is_(False),
                )
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

        await log_audit_event(db, action=AuditEvent.LOGOUT, user=await db.get(User, user_id), status="SUCCESS", request=request)
        return MessageResponse(message="Logged out from all sessions")

    else:
        # ── [Step 2B] Revoke ONLY the presented token ─────────────────────────
        ttl = max(0, exp - int(datetime.now(timezone.utc).timestamp()))
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

        await log_audit_event(db, action=AuditEvent.LOGOUT, user=await db.get(User, user_id), status="SUCCESS", request=request)
        return MessageResponse(message="Logged out successfully")


__all__ = ["router", "refresh_token_route", "revoke_token", "logout"]
