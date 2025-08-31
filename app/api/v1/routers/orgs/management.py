
"""
User Management (Org-free)
==========================

Operations for managing users without any organization or tenant context:
- Update a user's role (USER/ADMIN/SUPERUSER) with strict checks
- Deactivate/reactivate accounts (soft lifecycle)

Practices
---------
- MFA-enforced caller auth (`get_current_user_with_mfa`)
- SlowAPI route limits + Redis-backed per-actor budgets
- Optional Redis idempotency (via `Idempotency-Key` header)
- Distributed Redis locks + row-level DB locks for safety
- Sensitive cache headers and structured audit logs
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import exc as sa_exc

from app.db.models.user import User
from app.db.session import get_async_db
from app.schemas.enums import OrgRole as UserRole
from app.schemas.auth import MessageResponse, RoleUpdateRequest
from app.core.dependencies import get_current_user_with_mfa as get_current_user
from app.core.limiter import rate_limit
from app.core.redis_client import redis_wrapper
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event, AuditEvent
from app.utils.redis_utils import enforce_rate_limit


router = APIRouter(tags=["User Management"])


# ─────────────────────────────────────────────────────────────────────────────
# Update a user's role (org-free)
# ─────────────────────────────────────────────────────────────────────────────
@router.put(
    "/{user_id}/role",
    response_model=MessageResponse,
    summary="Change a user's role",
    tags=["User Management"],
)
@rate_limit("5/minute")
async def update_user_role(
    request: Request,
    user_id: UUID,
    payload: RoleUpdateRequest,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> MessageResponse:
    """Set a user's role to the requested value.

    Rules
    -----
    - Caller must be ADMIN or SUPERUSER.
    - Only SUPERUSER can assign/demote SUPERUSER.
    - No self role change.
    """
    set_sensitive_cache(request)

    # Per-actor hourly budget
    await enforce_rate_limit(
        key_suffix=f"role-update:{current_user.id}", seconds=3600, max_calls=10,
        error_message="Too many role changes; please try again later.",
    )

    # Authorization
    if current_user.role not in {UserRole.ADMIN, UserRole.SUPERUSER}:
        await log_audit_event(
            db, user=current_user, action="USER_ROLE_CHANGED", status="FORBIDDEN", request=request,
            meta_data={"target_user_id": str(user_id), "reason": "insufficient_permissions"},
        )
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    if current_user.id == user_id:
        await log_audit_event(
            db, user=current_user, action="USER_ROLE_CHANGED", status="DENIED_SELF_CHANGE", request=request,
            meta_data={"target_user_id": str(user_id)},
        )
        raise HTTPException(status_code=400, detail="You cannot change your own role")
    if payload.role == UserRole.SUPERUSER and current_user.role != UserRole.SUPERUSER:
        await log_audit_event(
            db, user=current_user, action="USER_ROLE_CHANGED", status="FORBIDDEN_SUPERUSER_ASSIGN", request=request,
            meta_data={"target_user_id": str(user_id), "requested_role": str(payload.role)},
        )
        raise HTTPException(status_code=403, detail="Only SUPERUSER can assign SUPERUSER")

    # Idempotency (optional): repeated same change returns cached result
    raw_idemp = request.headers.get("Idempotency-Key")
    idemp_key = (
        f"idemp:user-role:{current_user.id}:{user_id}:{payload.role}:{raw_idemp.strip()}"
        if raw_idemp
        else None
    )
    if idemp_key:
        try:
            cached = await redis_wrapper.idempotency_get(idemp_key)
        except Exception:
            cached = None
        if cached:
            return MessageResponse(**cached)

    lock_name = f"lock:user_management:role:{user_id}"
    try:
        async with redis_wrapper.lock(lock_name, timeout=10, blocking_timeout=3):
            try:
                stmt = select(User).where(User.id == user_id).with_for_update()
                res = await db.execute(stmt)
                target: Optional[User] = res.scalar_one_or_none()
                if not target:
                    raise HTTPException(status_code=404, detail="User not found")

                # SUPERUSER demotion restriction
                if target.role == UserRole.SUPERUSER and current_user.role != UserRole.SUPERUSER:
                    await log_audit_event(
                        db, user=current_user, action="USER_ROLE_CHANGED", status="FORBIDDEN_SUPERUSER_MODIFY", request=request,
                        meta_data={"target_user_id": str(user_id)},
                    )
                    raise HTTPException(status_code=403, detail="Only SUPERUSER can modify SUPERUSER")

                if target.role == payload.role:
                    return MessageResponse(message="User already has the requested role")

                previous = target.role
                target.role = payload.role
                await db.flush()
                await db.commit()

                await log_audit_event(
                    db, user=current_user, action="USER_ROLE_CHANGED", status="SUCCESS", request=request,
                    meta_data={
                        "target_user_id": str(target.id),
                        "from_role": str(previous),
                        "to_role": str(target.role),
                    },
                )

                response = MessageResponse(message="User role updated successfully")
                if idemp_key:
                    try:
                        await redis_wrapper.idempotency_set(idemp_key, response.model_dump(), ttl_seconds=600)
                    except Exception:
                        pass
                return response

            except HTTPException:
                raise
            except sa_exc.SQLAlchemyError as e:
                await db.rollback()
                await log_audit_event(
                    db, user=current_user, action="USER_ROLE_CHANGED", status="DB_ERROR", request=request,
                    meta_data={"target_user_id": str(user_id), "error": str(e)},
                )
                raise HTTPException(status_code=500, detail="Database error while updating role") from e
            except Exception as e:
                await db.rollback()
                await log_audit_event(
                    db, user=current_user, action="USER_ROLE_CHANGED", status="ERROR", request=request,
                    meta_data={"target_user_id": str(user_id), "error": str(e)},
                )
                raise HTTPException(status_code=500, detail="Unexpected error while updating role") from e
    except TimeoutError:
        raise HTTPException(status_code=429, detail="Busy processing a similar request; retry")


# ─────────────────────────────────────────────────────────────────────────────
# Deactivate a user (soft)
# ─────────────────────────────────────────────────────────────────────────────
@router.put(
    "/{user_id}/deactivate",
    response_model=MessageResponse,
    summary="Deactivate a user account",
    tags=["User Management"],
)
@rate_limit("5/minute")
async def deactivate_user(
    request: Request,
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> MessageResponse:
    """Mark the user as inactive and set `deactivated_at`.

    Only ADMIN or SUPERUSER may deactivate; cannot deactivate self.
    """
    set_sensitive_cache(request)
    await enforce_rate_limit(
        key_suffix=f"deactivate:{current_user.id}", seconds=1800, max_calls=10,
        error_message="Too many deactivations; please try again later.",
    )

    if current_user.role not in {UserRole.ADMIN, UserRole.SUPERUSER}:
        await log_audit_event(
            db, user=current_user, action=AuditEvent.DEACTIVATE_USER, status="FORBIDDEN", request=request,
            meta_data={"target_user_id": str(user_id)},
        )
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    if current_user.id == user_id:
        await log_audit_event(
            db, user=current_user, action=AuditEvent.DEACTIVATE_USER, status="DENIED_SELF", request=request,
            meta_data={"target_user_id": str(user_id)},
        )
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account")

    lock_name = f"lock:user_management:deactivate:{user_id}"
    try:
        async with redis_wrapper.lock(lock_name, timeout=10, blocking_timeout=3):
            try:
                stmt = select(User).where(User.id == user_id).with_for_update()
                res = await db.execute(stmt)
                target: Optional[User] = res.scalar_one_or_none()
                if not target:
                    raise HTTPException(status_code=404, detail="User not found")

                if not getattr(target, "is_active", True):
                    return MessageResponse(message="User is already inactive")

                target.is_active = False
                if hasattr(target, "deactivated_at"):
                    from datetime import datetime, timezone
                    target.deactivated_at = datetime.now(timezone.utc)
                await db.flush()
                await db.commit()

                await log_audit_event(
                    db, user=current_user, action=AuditEvent.DEACTIVATE_USER, status="SUCCESS", request=request,
                    meta_data={"target_user_id": str(target.id)},
                )
                return MessageResponse(message="User deactivated successfully")

            except HTTPException:
                raise
            except sa_exc.SQLAlchemyError as e:
                await db.rollback()
                await log_audit_event(
                    db, user=current_user, action=AuditEvent.DEACTIVATE_USER, status="DB_ERROR", request=request,
                    meta_data={"target_user_id": str(user_id), "error": str(e)},
                )
                raise HTTPException(status_code=500, detail="Database error while deactivating user") from e
            except Exception as e:
                await db.rollback()
                await log_audit_event(
                    db, user=current_user, action=AuditEvent.DEACTIVATE_USER, status="ERROR", request=request,
                    meta_data={"target_user_id": str(user_id), "error": str(e)},
                )
                raise HTTPException(status_code=500, detail="Unexpected error while deactivating user") from e
    except TimeoutError:
        raise HTTPException(status_code=429, detail="Busy processing a similar request; retry")


# ─────────────────────────────────────────────────────────────────────────────
# Reactivate a user (soft)
# ─────────────────────────────────────────────────────────────────────────────
@router.put(
    "/{user_id}/reactivate",
    response_model=MessageResponse,
    summary="Reactivate a user account",
    tags=["User Management"],
)
@rate_limit("5/minute")
async def reactivate_user(
    request: Request,
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> MessageResponse:
    """Mark the user as active and clear `deactivated_at` if present.

    Only ADMIN or SUPERUSER may reactivate.
    """
    set_sensitive_cache(request)
    await enforce_rate_limit(
        key_suffix=f"reactivate:{current_user.id}", seconds=1800, max_calls=10,
        error_message="Too many reactivations; please try again later.",
    )

    if current_user.role not in {UserRole.ADMIN, UserRole.SUPERUSER}:
        await log_audit_event(
            db, user=current_user, action=AuditEvent.REACTIVATE_USER, status="FORBIDDEN", request=request,
            meta_data={"target_user_id": str(user_id)},
        )
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    lock_name = f"lock:user_management:reactivate:{user_id}"
    try:
        async with redis_wrapper.lock(lock_name, timeout=10, blocking_timeout=3):
            try:
                stmt = select(User).where(User.id == user_id).with_for_update()
                res = await db.execute(stmt)
                target: Optional[User] = res.scalar_one_or_none()
                if not target:
                    raise HTTPException(status_code=404, detail="User not found")

                if getattr(target, "is_active", True):
                    return MessageResponse(message="User is already active")

                target.is_active = True
                if hasattr(target, "deactivated_at"):
                    target.deactivated_at = None
                await db.flush()
                await db.commit()

                await log_audit_event(
                    db, user=current_user, action=AuditEvent.REACTIVATE_USER, status="SUCCESS", request=request,
                    meta_data={"target_user_id": str(target.id)},
                )
                return MessageResponse(message="User reactivated successfully")

            except HTTPException:
                raise
            except sa_exc.SQLAlchemyError as e:
                await db.rollback()
                await log_audit_event(
                    db, user=current_user, action=AuditEvent.REACTIVATE_USER, status="DB_ERROR", request=request,
                    meta_data={"target_user_id": str(user_id), "error": str(e)},
                )
                raise HTTPException(status_code=500, detail="Database error while reactivating user") from e
            except Exception as e:
                await db.rollback()
                await log_audit_event(
                    db, user=current_user, action=AuditEvent.REACTIVATE_USER, status="ERROR", request=request,
                    meta_data={"target_user_id": str(user_id), "error": str(e)},
                )
                raise HTTPException(status_code=500, detail="Unexpected error while reactivating user") from e
    except TimeoutError:
        raise HTTPException(status_code=429, detail="Busy processing a similar request; retry")
