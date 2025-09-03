"""
MoviesNow · Admin Sessions & Token Rotation
===========================================

Admin/SUPERUSER-scoped session utilities:
- POST /admin/refresh                  : Rotate refresh token, mint new access (optional Idempotency-Key)
- GET  /admin/sessions                 : List own sessions (paginate)
- POST /admin/sessions/revoke          : Revoke a session by JTI
- POST /admin/sessions/revoke-others   : Revoke all except current
- POST /admin/sessions/revoke-all      : Global sign-out

Security & Ops Practices
------------------------
- Enforced ADMIN/SUPERUSER role + MFA (`mfa_authenticated=True`)
- Centralized JWT helpers and DB-backed refresh tokens
- Redis idempotency (best-effort) & session metadata; safe fail-open when appropriate
- Concurrency safety: Redis locks around rotation & targeted revocations
- Sensitive cache control on token-bearing responses
- SlowAPI rate limits per endpoint and best-effort audit logs
"""

from typing import Optional, List, Dict
from uuid import UUID
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import rate_limit
from app.core.jwt import decode_token, get_bearer_token
from app.core.security import create_access_token, create_refresh_token, get_current_user
from app.core.config import settings
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.db.models.user import User
from app.db.models.token import RefreshToken
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event, AuditEvent
from app.services.token_service import store_refresh_token, revoke_all_refresh_tokens
from app.dependencies.admin import (
    is_admin as _is_admin,
    ensure_admin as _ensure_admin,
    ensure_mfa as _ensure_mfa,
)

# Reuse session metadata helper from login service (keeps parity)
from app.services.auth.login_service import _register_session_and_meta  # type: ignore


# ── [Router] ─────────────────────────────────────────────────────────────────────────────
router = APIRouter(tags=["Admin Sessions"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Helpers
# ─────────────────────────────────────────────────────────────────────────────
 


async def _redis_sismember(key: str, member: str) -> bool:
    try:
        return bool(await redis_wrapper.client.sismember(key, member))  # type: ignore[attr-defined]
    except Exception:
        return False


async def _redis_srem(key: str, member: str) -> None:
    try:
        await redis_wrapper.client.srem(key, member)  # type: ignore[attr-defined]
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# 🔄 Rotate Refresh Token & Mint Access (optional Idempotency-Key)
# ─────────────────────────────────────────────────────────────────────────────
class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., description="Valid refresh token")


@router.post(
    "/refresh",
    response_model=Dict[str, str],  # TokenResponse-like shape (access_token, refresh_token, token_type)
    summary="Rotate refresh token and mint new access",
)
@rate_limit("20/minute")
async def admin_refresh(
    payload: RefreshTokenRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
) -> Dict[str, str]:
    """Admin-only token rotation using a valid refresh token.

    Steps
    -----
    0) Cache hardening
    1) Decode refresh JWT; extract `sub` (user_id), `jti`, `session_id`
    2) Load user & enforce ADMIN/SUPERUSER
    3) Concurrency guard (Redis lock per `jti`)
    4) Validate refresh row (exists, belongs to user, not revoked)
    5) (Optional) Idempotency replay via `Idempotency-Key`
    6) Revoke old refresh; mint & persist a rotated refresh (same session_id)
    7) Mint access (mfa_authenticated=True), register session metadata
    8) Audit & return (and snapshot if idempotent)
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Decode refresh JWT ─────────────────────────────────────────
    try:
        decoded = await decode_token(payload.refresh_token, expected_types=["refresh"])  # type: ignore[arg-type]
        user_id = UUID(str(decoded.get("sub")))
        jti = str(decoded.get("jti"))
        session_id = decoded.get("session_id") or jti
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # ── [Step 2] Load user & enforce role ───────────────────────────────────
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await _ensure_admin(user)

    # ── [Step 3] Concurrency guard ──────────────────────────────────────────
    lock_key = f"lock:refresh:rotate:{jti}"
    async with redis_wrapper.lock(lock_key, timeout=10, blocking_timeout=3):
        # ── [Step 4] Validate token row ─────────────────────────────────────
        token_row = (
            await db.execute(
                select(RefreshToken).where(RefreshToken.jti == jti, RefreshToken.user_id == user.id)
            )
        ).scalar_one_or_none()
        if not token_row or getattr(token_row, "is_revoked", False):
            await log_audit_event(
                db, user=user, action=AuditEvent.REFRESH_TOKEN, status="REUSE_OR_REVOKED", request=request, meta_data={"jti": jti}
            )
            raise HTTPException(status_code=401, detail="Invalid or revoked refresh token")

        # ── [Step 5] Idempotency (best-effort) ──────────────────────────────
        idem_hdr = request.headers.get("Idempotency-Key")
        idem_key = f"idemp:admin:refresh:{jti}:{idem_hdr}" if idem_hdr else None
        if idem_key:
            snap = await redis_wrapper.idempotency_get(idem_key)
            if snap:
                return snap  # type: ignore[return-value]

        # ── [Step 6] Revoke old & mint rotated refresh ─────────────────────
        await db.execute(update(RefreshToken).where(RefreshToken.jti == jti).values(is_revoked=True))
        await db.commit()

        refresh_data = await create_refresh_token(user_id=user.id, parent_jti=jti, session_id=session_id)
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

        # ── [Step 7] Mint access & audit ────────────────────────────────────
        access_token = await create_access_token(user_id=user.id, session_id=session_id, mfa_authenticated=True)
        await log_audit_event(
            db, user=user, action=AuditEvent.REFRESH_TOKEN, status="SUCCESS", request=request,
            meta_data={"old_jti": jti, "new_jti": refresh_data["jti"], "session_id": session_id}
        )

        body: Dict[str, str] = {
            "access_token": access_token,
            "refresh_token": refresh_data["token"],
            "token_type": "bearer",
        }
        # ── [Step 8] Idempotent snapshot (best-effort) ─────────────────────
        if idem_key:
            try:
                await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
            except Exception:
                pass
        return body


# ─────────────────────────────────────────────────────────────────────────────
# 📋 List Own Sessions (admin-only)
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/sessions", summary="List own sessions (admin-only)")
@rate_limit("30/minute")
async def list_sessions(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    """Return the caller's refresh-token sessions with basic metadata."""
    # ── [Step 0] Security gates & cache ──────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # Best-effort resolution of the current session id (for UI highlighting)
    try:
        claims = await decode_token(get_bearer_token(request), expected_types=["access"], verify_revocation=False)
        current_session = claims.get("session_id")
    except Exception:
        current_session = None

    # Order by creation if available; otherwise by expiry descending
    order_col = getattr(RefreshToken, "created_at", getattr(RefreshToken, "expires_at"))
    stmt = (
        select(RefreshToken)
        .where(RefreshToken.user_id == current_user.id)
        .order_by(order_col.desc())
        .offset(offset)
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all() or []

    items: List[Dict[str, object]] = []
    for r in rows:
        sid = getattr(r, "session_id", getattr(r, "jti", None))
        items.append(
            {
                "jti": getattr(r, "jti", None),
                "session_id": sid,
                "is_revoked": bool(getattr(r, "is_revoked", False)),
                "expires_at": getattr(r, "expires_at", None),
                "created_at": getattr(r, "created_at", None),
                "current": bool(current_session and current_session == sid),
            }
        )

    await log_audit_event(
        db, user=current_user, action=AuditEvent.SESSIONS_LIST, status="SUCCESS", request=request, meta_data={"returned": len(items)}
    )
    return items


# ─────────────────────────────────────────────────────────────────────────────
# ❌ Revoke a Session by JTI
# ─────────────────────────────────────────────────────────────────────────────
class RevokeSessionRequest(BaseModel):
    jti: str = Field(..., description="Refresh token JTI to revoke")


@router.post("/sessions/revoke", summary="Revoke a session by JTI")
@rate_limit("10/minute")
async def revoke_session(
    payload: RevokeSessionRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """Revoke a single refresh token owned by the caller."""
    # ── [Step 0] Security ───────────────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    jti = payload.jti

    # Concurrency safety: one revocation per JTI at a time
    async with redis_wrapper.lock(f"lock:session:revoke:{jti}", timeout=10, blocking_timeout=3):
        row = (
            await db.execute(
                select(RefreshToken).where(RefreshToken.jti == jti, RefreshToken.user_id == current_user.id)
            )
        ).scalar_one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Session not found")
        if getattr(row, "is_revoked", False):
            return {"revoked": 0, "message": "Already revoked"}

        await db.execute(update(RefreshToken).where(RefreshToken.jti == jti).values(is_revoked=True))
        await db.commit()

    await _redis_srem(f"session:{current_user.id}", jti)
    await log_audit_event(
        db, user=current_user, action=AuditEvent.SESSION_REVOKE, status="SUCCESS", request=request, meta_data={"jti": jti}
    )
    return {"revoked": 1}


# ─────────────────────────────────────────────────────────────────────────────
# 🔒 Revoke All Other Sessions (keep current)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/sessions/revoke-others", summary="Revoke all other sessions (keep current)")
@rate_limit("10/minute")
async def revoke_other_sessions(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """Revoke all sessions for the caller **except** the current session (if known)."""
    # ── [Step 0] Security ───────────────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # Determine current session id from access token (best-effort)
    try:
        claims = await decode_token(get_bearer_token(request), expected_types=["access"], verify_revocation=False)
        keep = claims.get("session_id")
    except Exception:
        keep = None

    # Prefer revoking by session_id if the column exists; fall back to JTI
    col_session = getattr(RefreshToken, "session_id", None)
    cond = (RefreshToken.user_id == current_user.id)

    if keep:
        if col_session is not None:
            cond = and_(cond, col_session != keep)
        else:
            cond = and_(cond, RefreshToken.jti != keep)

    await db.execute(update(RefreshToken).where(cond).values(is_revoked=True))
    await db.commit()

    await log_audit_event(
        db, user=current_user, action=AuditEvent.SESSIONS_REVOKE_OTHERS, status="SUCCESS", request=request, meta_data={"kept": keep}
    )
    return {"revoked": "others" if keep else "all"}


# ─────────────────────────────────────────────────────────────────────────────
# 🧨 Global Sign-out (revoke all sessions)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/sessions/revoke-all", summary="Global sign-out (revoke all sessions)")
@rate_limit("10/minute")
async def revoke_all_sessions(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """Revoke **all** refresh tokens for the caller."""
    # ── [Step 0] Security ───────────────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    await revoke_all_refresh_tokens(db=db, user_id=current_user.id)
    await log_audit_event(db, user=current_user, action=AuditEvent.SESSIONS_REVOKE_ALL, status="SUCCESS", request=request)
    return {"revoked": "all"}
