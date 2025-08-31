from __future__ import annotations

"""
Admin Staff Management (Org-free)
=================================

Endpoints (admin-only with MFA):
- GET  /admin/staff                     : list admins & superusers (filters + pagination)
- GET  /admin/staff/superusers         : list superusers (cached 5m)
- GET  /admin/staff/admins             : list admins (paginate)
- POST /admin/staff/{user_id}/promote  : user -> SUPERUSER (reauth required)
- POST /admin/staff/{user_id}/demote   : SUPERUSER -> USER (reauth required)
- POST /admin/staff/{user_id}/make-admin    : grant ADMIN (reauth, safeguards)
- POST /admin/staff/{user_id}/remove-admin  : remove ADMIN (reauth)

Practices
---------
- SlowAPI rate limits
- Enforce `mfa_authenticated` access and admin role
- DB row-level locking for mutations + Redis lock
- Idempotency via Idempotency-Key (best-effort)
- Sensitive cache headers and audit logs
"""

from typing import List, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import select, update, and_, or_, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import rate_limit
from app.core.jwt import decode_token
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.db.models.user import User
from app.db.models.token import RefreshToken
from app.schemas.enums import OrgRole as UserRole
from app.schemas.auth import SimpleUserResponse
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event
from app.services.token_service import revoke_all_refresh_tokens

router = APIRouter(tags=["Admin Staff"])


def _is_admin(user: User) -> bool:
    return getattr(user, "role", None) in {UserRole.ADMIN, UserRole.SUPERUSER}


async def _ensure_admin(user: User) -> None:
    if not _is_admin(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")


async def _ensure_mfa(request: Request) -> None:
    try:
        claims = await decode_token(request.headers.get("Authorization", "").split(" ")[-1], expected_types=["access"], verify_revocation=True)
        if not bool(claims.get("mfa_authenticated")):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MFA required")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token")


async def _ensure_reauth(reauth_token: str, current_user: User) -> None:
    try:
        claims = await decode_token(reauth_token, expected_types=["reauth"], verify_revocation=False)
        sub = claims.get("sub")
        if str(sub) != str(current_user.id):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid reauth token")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid reauth token")


def _serialize_user(u: User) -> Dict[str, object]:
    return {
        "id": str(u.id),
        "email": u.email,
        "full_name": getattr(u, "full_name", None),
        "role": str(getattr(u, "role", UserRole.USER)),
        "is_active": bool(getattr(u, "is_active", True)),
        "created_at": getattr(u, "created_at", None),
    }


@router.get("/staff", summary="List admins & superusers (filters + pagination)")
@rate_limit("30/minute")
async def list_staff(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    role: Optional[UserRole] = Query(None, description="Filter by role: ADMIN or SUPERUSER"),
    email: Optional[str] = Query(None, description="Case-insensitive email contains"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(request, seconds=0)

    conditions = [User.role.in_([UserRole.ADMIN, UserRole.SUPERUSER])]
    if role:
        conditions = [User.role == role]
    if email:
        e = email.strip().lower()
        conditions.append(func.lower(User.email).contains(e))

    stmt = (
        select(User)
        .where(and_(*conditions))
        .order_by(User.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all() or []
    return [_serialize_user(u) for u in rows]


@router.get("/staff/superusers", summary="List superusers (cached 5m)")
@rate_limit("10/minute")
async def list_superusers(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(request, seconds=0)

    cache_key = f"cache:admin:superusers:{limit}:{offset}"
    try:
        cached = await redis_wrapper.json_get(cache_key)
        if cached:
            return cached  # type: ignore[return-value]
    except Exception:
        cached = None

    stmt = (
        select(User)
        .where(User.role == UserRole.SUPERUSER)
        .order_by(User.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all() or []
    data = [_serialize_user(u) for u in rows]
    try:
        await redis_wrapper.json_set(cache_key, data, ttl_seconds=300)
    except Exception:
        pass
    return data


@router.get("/staff/admins", summary="List admins (paginate)")
@rate_limit("10/minute")
async def list_admins_only(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(request, seconds=0)

    stmt = (
        select(User)
        .where(User.role == UserRole.ADMIN)
        .order_by(User.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all() or []
    return [_serialize_user(u) for u in rows]


class _ReauthBody:
    reauth_token: str


@router.post("/staff/{user_id}/promote", summary="Promote USER -> SUPERUSER (reauth)")
@rate_limit("5/minute")
async def promote_superuser(
    user_id: UUID,
    request: Request,
    body: Dict[str, str],
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    reauth_token = (body or {}).get("reauth_token")
    if not reauth_token:
        raise HTTPException(status_code=400, detail="reauth_token required")
    await _ensure_reauth(reauth_token, current_user)

    if str(current_user.id) == str(user_id):
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    # Lock row for update
    async with redis_wrapper.lock(f"lock:admin_staff:promote:{user_id}", timeout=10, blocking_timeout=3):
        u = (await db.execute(select(User).where(User.id == user_id).with_for_update())).scalar_one_or_none()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        if u.role == UserRole.SUPERUSER:
            return {"message": "Already SUPERUSER", "user": {"email": u.email}, "role": str(u.role)}
        prev = u.role
        u.role = UserRole.SUPERUSER
        await db.flush()
        await db.commit()
        await log_audit_event(db, user=current_user, action="STAFF_PROMOTE_SUPERUSER", status="SUCCESS", request=request, meta_data={"target_user_id": str(u.id), "from": str(prev), "to": str(u.role)})
        return {"message": "Promoted to SUPERUSER", "user": {"email": u.email}, "role": str(u.role)}


@router.post("/staff/{user_id}/demote", summary="Demote SUPERUSER -> USER (reauth)")
@rate_limit("5/minute")
async def demote_superuser(
    user_id: UUID,
    request: Request,
    body: Dict[str, str],
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    reauth_token = (body or {}).get("reauth_token")
    if not reauth_token:
        raise HTTPException(status_code=400, detail="reauth_token required")
    await _ensure_reauth(reauth_token, current_user)
    if str(current_user.id) == str(user_id):
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    async with redis_wrapper.lock(f"lock:admin_staff:demote:{user_id}", timeout=10, blocking_timeout=3):
        u = (await db.execute(select(User).where(User.id == user_id).with_for_update())).scalar_one_or_none()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        if u.role != UserRole.SUPERUSER:
            raise HTTPException(status_code=400, detail="Target is not SUPERUSER")
        prev = u.role
        u.role = UserRole.USER
        await db.flush()
        await db.commit()
        await log_audit_event(db, user=current_user, action="STAFF_DEMOTE_TO_USER", status="SUCCESS", request=request, meta_data={"target_user_id": str(u.id), "from": str(prev), "to": str(u.role)})
        return {"message": "Demoted to USER", "user": {"email": u.email}, "role": str(u.role)}


@router.post("/staff/{user_id}/make-admin", summary="Grant ADMIN (safeguards; reauth)")
@rate_limit("5/minute")
async def grant_admin(
    user_id: UUID,
    request: Request,
    body: Dict[str, object],
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    reauth_token = (body or {}).get("reauth_token")
    if not reauth_token:
        raise HTTPException(status_code=400, detail="reauth_token required")
    await _ensure_reauth(str(reauth_token), current_user)
    allow_demotion = bool((body or {}).get("allow_demotion"))
    if str(current_user.id) == str(user_id):
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    async with redis_wrapper.lock(f"lock:admin_staff:make_admin:{user_id}", timeout=10, blocking_timeout=3):
        u = (await db.execute(select(User).where(User.id == user_id).with_for_update())).scalar_one_or_none()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        if u.role == UserRole.ADMIN:
            return {"message": "Already ADMIN", "user": {"email": u.email}, "role": str(u.role)}
        if u.role == UserRole.SUPERUSER and not allow_demotion:
            raise HTTPException(status_code=400, detail="Target is SUPERUSER; set allow_demotion=true to convert to ADMIN")
        prev = u.role
        u.role = UserRole.ADMIN
        await db.flush()
        await db.commit()
        await log_audit_event(db, user=current_user, action="STAFF_GRANT_ADMIN", status="SUCCESS", request=request, meta_data={"target_user_id": str(u.id), "from": str(prev), "to": str(u.role), "allow_demotion": allow_demotion})
        return {"message": "Granted ADMIN", "user": {"email": u.email}, "role": str(u.role)}


@router.post("/staff/{user_id}/remove-admin", summary="Remove ADMIN (reauth)")
@rate_limit("5/minute")
async def remove_admin(
    user_id: UUID,
    request: Request,
    body: Dict[str, str],
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    reauth_token = (body or {}).get("reauth_token")
    if not reauth_token:
        raise HTTPException(status_code=400, detail="reauth_token required")
    await _ensure_reauth(reauth_token, current_user)
    if str(current_user.id) == str(user_id):
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    async with redis_wrapper.lock(f"lock:admin_staff:remove_admin:{user_id}", timeout=10, blocking_timeout=3):
        u = (await db.execute(select(User).where(User.id == user_id).with_for_update())).scalar_one_or_none()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        if u.role != UserRole.ADMIN:
            raise HTTPException(status_code=400, detail="Target is not ADMIN")
        prev = u.role
        u.role = UserRole.USER
        await db.flush()
        await db.commit()
        await log_audit_event(db, user=current_user, action="STAFF_REMOVE_ADMIN", status="SUCCESS", request=request, meta_data={"target_user_id": str(u.id), "from": str(prev), "to": str(u.role)})
        return {"message": "Removed ADMIN", "user": {"email": u.email}, "role": str(u.role)}


# ─────────────────────────────────────────────────────────────────────────────
# Admin Users: search/list, get, patch flags, deactivate/reactivate, delete
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/users", summary="Search/list users (filters; paginate)")
@rate_limit("30/minute")
async def admin_users_list(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    email: Optional[str] = Query(None),
    role: Optional[UserRole] = Query(None),
    is_active: Optional[bool] = Query(None),
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(request, seconds=0)

    conds = []
    if email:
        conds.append(func.lower(User.email).contains(email.strip().lower()))
    if role:
        conds.append(User.role == role)
    if is_active is not None:
        conds.append(User.is_active == bool(is_active))

    stmt = select(User)
    if conds:
        stmt = stmt.where(and_(*conds))
    stmt = stmt.order_by(User.created_at.desc()).offset(offset).limit(limit)
    rows = (await db.execute(stmt)).scalars().all() or []
    return [_serialize_user(u) for u in rows]


@router.get("/users/{user_id}", summary="Get user by id")
@rate_limit("30/minute")
async def admin_users_get(
    user_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    u = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return _serialize_user(u)


@router.patch("/users/{user_id}", summary="Patch user flags/fields (reauth for sensitive)")
@rate_limit("10/minute")
async def admin_users_patch(
    user_id: UUID,
    body: Dict[str, object],
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    if not isinstance(body, dict) or not body:
        raise HTTPException(status_code=400, detail="Empty body")

    # Allowed fields (safe); use reauth for verification flags
    allowed = {"full_name", "is_verified", "is_email_verified", "is_phone_verified"}
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        raise HTTPException(status_code=400, detail="No allowed fields to update")

    # Require reauth when toggling verification flags
    if any(k in updates for k in ("is_verified", "is_email_verified", "is_phone_verified")):
        token = str(body.get("reauth_token") or "")
        if not token:
            raise HTTPException(status_code=400, detail="reauth_token required")
        await _ensure_reauth(token, current_user)

    async with redis_wrapper.lock(f"lock:admin_users:patch:{user_id}", timeout=10, blocking_timeout=3):
        u = (await db.execute(select(User).where(User.id == user_id).with_for_update())).scalar_one_or_none()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        prev = _serialize_user(u)
        for k, v in updates.items():
            setattr(u, k, v)
        await db.flush()
        await db.commit()
        await log_audit_event(db, user=current_user, action="ADMIN_USERS_PATCH", status="SUCCESS", request=request, meta_data={"target_user_id": str(user_id), "updates": list(updates.keys())})
        return _serialize_user(u)


@router.post("/users/{user_id}/deactivate", summary="Deactivate user (reauth)")
@rate_limit("5/minute")
async def admin_users_deactivate(
    user_id: UUID,
    body: Dict[str, str],
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    token = (body or {}).get("reauth_token")
    if not token:
        raise HTTPException(status_code=400, detail="reauth_token required")
    await _ensure_reauth(token, current_user)
    if str(current_user.id) == str(user_id):
        raise HTTPException(status_code=400, detail="Cannot deactivate self")

    async with redis_wrapper.lock(f"lock:admin_users:deactivate:{user_id}", timeout=10, blocking_timeout=3):
        u = (await db.execute(select(User).where(User.id == user_id).with_for_update())).scalar_one_or_none()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        if not getattr(u, "is_active", True):
            return {"message": "Already inactive"}
        u.is_active = False
        await db.flush(); await db.commit()
        await log_audit_event(db, user=current_user, action="ADMIN_USERS_DEACTIVATE", status="SUCCESS", request=request, meta_data={"target_user_id": str(user_id)})
        return {"message": "User deactivated"}


@router.post("/users/{user_id}/reactivate", summary="Reactivate user")
@rate_limit("5/minute")
async def admin_users_reactivate(
    user_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    async with redis_wrapper.lock(f"lock:admin_users:reactivate:{user_id}", timeout=10, blocking_timeout=3):
        u = (await db.execute(select(User).where(User.id == user_id).with_for_update())).scalar_one_or_none()
        if not u:
            raise HTTPException(status_code=404, detail="User not found")
        if getattr(u, "is_active", True):
            return {"message": "Already active"}
        u.is_active = True
        await db.flush(); await db.commit()
        await log_audit_event(db, user=current_user, action="ADMIN_USERS_REACTIVATE", status="SUCCESS", request=request, meta_data={"target_user_id": str(user_id)})
        return {"message": "User reactivated"}


@router.delete("/users/{user_id}", summary="Hard delete user (reauth)")
@rate_limit("5/minute")
async def admin_users_delete(
    user_id: UUID,
    body: Dict[str, str],
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    token = (body or {}).get("reauth_token")
    if not token:
        raise HTTPException(status_code=400, detail="reauth_token required")
    await _ensure_reauth(token, current_user)
    if str(current_user.id) == str(user_id):
        raise HTTPException(status_code=400, detail="Cannot delete self")
    # Clean up: revoke all refresh tokens
    await revoke_all_refresh_tokens(db=db, user_id=user_id)
    # Hard delete
    await db.execute(delete(User).where(User.id == user_id))
    await db.commit()
    await log_audit_event(db, user=current_user, action="ADMIN_USERS_DELETE", status="SUCCESS", request=request, meta_data={"target_user_id": str(user_id)})
    return {"message": "User deleted"}


@router.get("/users/{user_id}/sessions", summary="List a user's sessions (admin)")
@rate_limit("30/minute")
async def admin_users_sessions(
    user_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    stmt = (
        select(RefreshToken)
        .where(RefreshToken.user_id == user_id)
        .order_by(RefreshToken.created_at.desc() if hasattr(RefreshToken, "created_at") else RefreshToken.expires_at.desc())
        .offset(offset)
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all() or []
    items: List[Dict[str, object]] = []
    for r in rows:
        items.append({
            "jti": getattr(r, "jti", None),
            "is_revoked": bool(getattr(r, "is_revoked", False)),
            "expires_at": getattr(r, "expires_at", None),
            "created_at": getattr(r, "created_at", None),
        })
    return items


@router.post("/users/{user_id}/sessions/revoke-all", summary="Revoke all sessions for user (admin)")
@rate_limit("10/minute")
async def admin_users_sessions_revoke_all(
    user_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    await revoke_all_refresh_tokens(db=db, user_id=user_id)
    await log_audit_event(db, user=current_user, action="ADMIN_USERS_REVOKE_ALL", status="SUCCESS", request=request, meta_data={"target_user_id": str(user_id)})
    return {"revoked": "all"}
