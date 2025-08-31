from __future__ import annotations

"""
Admin Sessions & Token Rotation
===============================

Admin/SUPERUSER-scoped session utilities:
- POST /admin/refresh            : Rotate refresh token, mint new access
- GET  /admin/sessions          : List own sessions (paginate)
- POST /admin/sessions/revoke   : Revoke a session by JTI
- POST /admin/sessions/revoke-others : Revoke all except current
- POST /admin/sessions/revoke-all    : Global sign-out

Practices
---------
- Enforced ADMIN/SUPERUSER role
- Centralized JWT helpers and DB-backed refresh tokens
- Redis idempotency/session metadata and safe fail-open where appropriate
- Sensitive cache control on token-bearing responses
- SlowAPI rate limits per endpoint and best-effort audit logs
"""

from typing import Optional, List, Dict
from uuid import UUID
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from sqlalchemy import select, update
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
from app.schemas.auth import RefreshTokenRequest, TokenResponse

# Reuse session metadata helper from login service
from app.services.auth.login_service import _register_session_and_meta  # type: ignore


router = APIRouter(tags=["Admin Sessions"])


def _is_admin(user: User) -> bool:
    try:
        from app.schemas.enums import OrgRole
        return getattr(user, "role", None) in {OrgRole.ADMIN, OrgRole.SUPERUSER}
    except Exception:
        return bool(getattr(user, "is_superuser", False))


async def _ensure_admin(user: User) -> None:
    if not _is_admin(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")


async def _ensure_mfa(request: Request) -> None:
    """Require `mfa_authenticated=True` on the current access token (admin-only ops)."""
    try:
        claims = await decode_token(get_bearer_token(request), expected_types=["access"], verify_revocation=True)
        if not bool(claims.get("mfa_authenticated")):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MFA required")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token")


async def _redis_sismember(key: str, member: str) -> bool:
    try:
        return bool(await redis_wrapper.client.sismember(key, member))  # type: ignore
    except Exception:
        return False


async def _redis_srem(key: str, member: str) -> None:
    try:
        await redis_wrapper.client.srem(key, member)  # type: ignore
    except Exception:
        pass


@router.post("/refresh", response_model=TokenResponse, summary="Rotate refresh token and mint new access")
@rate_limit("20/minute")
async def admin_refresh(
    payload: RefreshTokenRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
) -> TokenResponse:
    """Admin-only token rotation using a valid refresh token."""
    set_sensitive_cache(response)

    # Decode refresh token and ensure admin subject
    decoded = await decode_token(payload.refresh_token, expected_types=["refresh"])  # type: ignore[arg-type]
    user_id = UUID(str(decoded.get("sub")))
    jti = str(decoded.get("jti"))
    session_id = decoded.get("session_id") or jti

    # Load user and ensure ADMIN/SUPERUSER
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await _ensure_admin(user)

    # Ensure token exists and is not revoked
    token_row = (await db.execute(select(RefreshToken).where(RefreshToken.jti == jti))).scalar_one_or_none()
    if not token_row or getattr(token_row, "is_revoked", False):
        await log_audit_event(db, user=user, action=AuditEvent.REFRESH_TOKEN, status="REUSE_OR_REVOKED", request=request, meta_data={"jti": jti})
        raise HTTPException(status_code=401, detail="Invalid or revoked refresh token")

    # Revoke old refresh and mint new pair
    await db.execute(update(RefreshToken).where(RefreshToken.jti == jti).values(is_revoked=True))
    await db.commit()

    # Mint new refresh
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

    # Access token
    access_token = await create_access_token(user_id=user.id, session_id=session_id, mfa_authenticated=True)

    await log_audit_event(db, user=user, action=AuditEvent.REFRESH_TOKEN, status="SUCCESS", request=request, meta_data={"old_jti": jti, "new_jti": refresh_data["jti"]})

    return TokenResponse(access_token=access_token, refresh_token=refresh_data["token"], token_type="bearer")


@router.get("/sessions", summary="List own sessions (admin-only)")
@rate_limit("30/minute")
async def list_sessions(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    try:
        claims = await decode_token(get_bearer_token(request), expected_types=["access"], verify_revocation=False)
        current_session = claims.get("session_id")
    except Exception:
        current_session = None

    stmt = (
        select(RefreshToken)
        .where(RefreshToken.user_id == current_user.id)
        .order_by(RefreshToken.created_at.desc() if hasattr(RefreshToken, "created_at") else RefreshToken.expires_at.desc())
        .offset(offset)
        .limit(limit)
    )
    res = await db.execute(stmt)
    rows = res.scalars().all() or []

    items: List[Dict[str, object]] = []
    for r in rows:
        meta = {"jti": getattr(r, "jti", None), "is_revoked": bool(getattr(r, "is_revoked", False))}
        meta["expires_at"] = getattr(r, "expires_at", None)
        meta["created_at"] = getattr(r, "created_at", None)
        meta["current"] = bool(current_session and current_session == getattr(r, "session_id", getattr(r, "jti", None)))
        items.append(meta)

    await log_audit_event(db, user=current_user, action=AuditEvent.SESSIONS_LIST, status="SUCCESS", request=request, meta_data={"returned": len(items)})
    return items


@router.post("/sessions/revoke", summary="Revoke a session by JTI")
@rate_limit("10/minute")
async def revoke_session(
    payload: Dict[str, str],
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    jti = (payload or {}).get("jti")
    if not jti:
        raise HTTPException(status_code=400, detail="Missing jti")

    stmt = select(RefreshToken).where(RefreshToken.jti == jti, RefreshToken.user_id == current_user.id)
    row = (await db.execute(stmt)).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    if getattr(row, "is_revoked", False):
        return {"revoked": 0, "message": "Already revoked"}

    await db.execute(update(RefreshToken).where(RefreshToken.jti == jti).values(is_revoked=True))
    await db.commit()

    await _redis_srem(f"session:{current_user.id}", jti)
    await log_audit_event(db, user=current_user, action=AuditEvent.SESSION_REVOKE, status="SUCCESS", request=request, meta_data={"jti": jti})
    return {"revoked": 1}


@router.post("/sessions/revoke-others", summary="Revoke all other sessions (keep current)")
@rate_limit("10/minute")
async def revoke_other_sessions(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    try:
        claims = await decode_token(get_bearer_token(request), expected_types=["access"], verify_revocation=False)
        keep = claims.get("session_id")
    except Exception:
        keep = None

    # Mark all tokens revoked except the kept session
    if keep:
        await db.execute(update(RefreshToken).where(RefreshToken.user_id == current_user.id, RefreshToken.jti != keep).values(is_revoked=True))
        await db.commit()
        await log_audit_event(db, user=current_user, action=AuditEvent.SESSIONS_REVOKE_OTHERS, status="SUCCESS", request=request, meta_data={"kept": keep})
        return {"revoked": "others"}
    else:
        # No known current session; revoke all
        await db.execute(update(RefreshToken).where(RefreshToken.user_id == current_user.id).values(is_revoked=True))
        await db.commit()
        await log_audit_event(db, user=current_user, action=AuditEvent.SESSIONS_REVOKE_OTHERS, status="SUCCESS", request=request, meta_data={"kept": None})
        return {"revoked": "all"}


@router.post("/sessions/revoke-all", summary="Global sign-out (revoke all sessions)")
@rate_limit("10/minute")
async def revoke_all_sessions(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    await revoke_all_refresh_tokens(db=db, user_id=current_user.id)
    await log_audit_event(db, user=current_user, action=AuditEvent.SESSIONS_REVOKE_ALL, status="SUCCESS", request=request)
    return {"revoked": "all"}

