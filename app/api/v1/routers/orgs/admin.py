
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ MoviesNow · Admin Actions (Org-free)                                     ║
# ║                                                                          ║
# ║ Endpoints (ADMIN + MFA enforced):                                        ║
# ║  - PUT  /{user_id}/assign-ADMIN     → Promote user to ADMIN              ║
# ║  - PUT  /{user_id}/revoke-ADMIN     → Demote user to USER                ║
# ║  - GET  /admins                     → List ADMIN users (paginated)       ║
# ╠──────────────────────────────────────────────────────────────────────────╣
# ║ Security & Ops                                                           ║
# ║  - Caller must be ADMIN and MFA-authenticated (dependency).              ║
# ║  - SlowAPI route limits + Redis per-actor budgets.                       ║
# ║  - Idempotency via `Idempotency-Key` header (10 min snapshots).          ║
# ║  - Distributed Redis locks + DB row-level `FOR UPDATE`.                  ║
# ║  - Cache-Control: no-store on all responses.                              ║
# ║  - Rich audit logs; neutral error messages.                               ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
User-centric ADMIN role management using shared primitives.

- Enum roles via `OrgRole` (aliased to `UserRole`)
- MFA-enforced caller auth (`get_current_user_with_mfa`)
- Rate limiting (SlowAPI) and per-actor Redis budgets
- Idempotency snapshots (Idempotency-Key)
- Distributed locks + row-level DB locks
- Sensitive cache headers and extensive audit logging
"""

from typing import List
from uuid import UUID

from fastapi import (
    APIRouter,
    HTTPException,
    status,
    Depends,
    Request,
    Query,
    Response,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import exc as sa_exc

from app.db.models.user import User
from app.schemas.enums import OrgRole as UserRole
from app.schemas.auth import (
    AssignADMINResponse,
    RevokeADMINResponse,
    AdminUserItem,
    SimpleUserResponse,
)
from app.services.audit_log_service import log_audit_event
from app.core.limiter import rate_limit
from app.db.session import get_async_db
from app.core.dependencies import get_current_user_with_mfa as get_current_user
from app.core.redis_client import redis_wrapper
from app.security_headers import set_sensitive_cache
from app.utils.redis_utils import enforce_rate_limit


router = APIRouter(tags=["Admin Actions"])


# ─────────────────────────────────────────────────────────────────────────────
# Assign ADMIN role to a user
# ─────────────────────────────────────────────────────────────────────────────
@router.put(
    "/{user_id}/assign-ADMIN",
    response_model=AssignADMINResponse,
    status_code=status.HTTP_200_OK,
    summary="Assign ADMIN role to a user",
    tags=["User Management"],
)
@rate_limit("3/minute")
async def assign_ADMIN_route(
    request: Request,
    response: Response,
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    """
    Promote a user to ADMIN with concurrency + idempotency guards.

    Requirements
    ------------
    - Caller must be `UserRole.ADMIN` and MFA-authenticated.
    - Target user must exist and be different from the caller.

    Behaviors
    ---------
    - Honors `Idempotency-Key` header; on success, snapshots for 10 minutes.
    - Uses Redis distributed lock and DB row lock (`FOR UPDATE`) to avoid races.

    Steps
    -----
    1) Apply sensitive `no-store` headers
    2) Enforce per-actor budget (defense-in-depth)
    3) Short-circuit on idempotency snapshot if provided
    4) Authorization & self-promotion checks
    5) Acquire Redis lock → select `FOR UPDATE` → mutate role → commit
    6) Cache idempotent response & audit log
    """
    # 1) No-store cache headers (sensitive admin mutation)
    set_sensitive_cache(response)

    # 2) Per-actor budget (hourly)
    try:
        await enforce_rate_limit(
            key_suffix=f"assign-admin:{current_user.id}",
            seconds=3600,
            max_calls=5,
            error_message="Too many admin role changes; please try again later.",
        )
    except HTTPException:
        await log_audit_event(
            db,
            user=current_user,
            action="ASSIGN_ADMIN",
            status="RATE_LIMITED",
            request=request,
            meta_data={"target_user_id": str(user_id)},
        )
        raise

    # 3) Idempotency snapshot
    raw_idemp = request.headers.get("Idempotency-Key")
    actor_id = getattr(current_user, "id", None)
    idemp_key = (
        f"idemp:admin:assign:{actor_id}:{user_id}:{raw_idemp.strip()}"
        if raw_idemp and actor_id
        else None
    )
    if idemp_key:
        try:
            cached = await redis_wrapper.idempotency_get(idemp_key)
        except Exception:
            cached = None
        if cached:
            return AssignADMINResponse(**cached)

    # 4) Authorization checks
    if current_user.role != UserRole.ADMIN:
        await log_audit_event(
            db,
            user=current_user,
            action="ASSIGN_ADMIN",
            status="FORBIDDEN",
            request=request,
            meta_data={"target_user_id": str(user_id)},
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    if current_user.id == user_id:
        await log_audit_event(
            db,
            user=current_user,
            action="ASSIGN_ADMIN",
            status="FAILED",
            request=request,
            meta_data={"reason": "self_promotion_blocked", "target_user_id": str(user_id)},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Self-promotion is not allowed")

    # 5) Acquire lock → mutate
    lock_name = f"lock:role_assign_admin:{user_id}"
    try:
        async with redis_wrapper.lock(lock_name, timeout=10, blocking_timeout=3):
            try:
                stmt = select(User).where(User.id == user_id).with_for_update()
                result = await db.execute(stmt)
                target = result.scalar_one_or_none()

                if not target:
                    await log_audit_event(
                        db,
                        user=current_user,
                        action="ASSIGN_ADMIN",
                        status="NOT_FOUND",
                        request=request,
                        meta_data={"target_user_id": str(user_id)},
                    )
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found")

                if target.role == UserRole.ADMIN:
                    # Already admin; idempotent success
                    resp_model = AssignADMINResponse(
                        message="User already has ADMIN role",
                        user=SimpleUserResponse(email=target.email),
                        role=str(target.role),
                    )
                    if idemp_key:
                        try:
                            await redis_wrapper.idempotency_set(idemp_key, resp_model.model_dump(), ttl_seconds=600)
                        except Exception:
                            pass
                    return resp_model

                prev = target.role
                target.role = UserRole.ADMIN
                await db.flush()
                await db.commit()
                try:
                    await db.refresh(target, attribute_names=["role"])
                except Exception:
                    pass

                resp_model = AssignADMINResponse(
                    message="Role updated to ADMIN",
                    user=SimpleUserResponse(email=target.email),
                    role=str(target.role),
                )

                # 6) Persist idempotency snapshot + audit log
                if idemp_key:
                    try:
                        await redis_wrapper.idempotency_set(idemp_key, resp_model.model_dump(), ttl_seconds=600)
                    except Exception:
                        pass

                await log_audit_event(
                    db,
                    user=current_user,
                    action="ASSIGN_ADMIN",
                    status="SUCCESS",
                    request=request,
                    meta_data={
                        "target_user_id": str(target.id),
                        "from_role": str(prev),
                        "to_role": str(target.role),
                        "idempotency": bool(idemp_key is not None),
                    },
                )
                return resp_model

            except HTTPException:
                raise
            except sa_exc.SQLAlchemyError as e:
                await db.rollback()
                await log_audit_event(
                    db,
                    user=current_user,
                    action="ASSIGN_ADMIN",
                    status="DB_ERROR",
                    request=request,
                    meta_data={"target_user_id": str(user_id), "error": str(e)},
                )
                raise HTTPException(status_code=500, detail="Database error while assigning ADMIN") from e
            except Exception as e:
                await db.rollback()
                await log_audit_event(
                    db,
                    user=current_user,
                    action="ASSIGN_ADMIN",
                    status="ERROR",
                    request=request,
                    meta_data={"target_user_id": str(user_id), "error": str(e)},
                )
                raise HTTPException(status_code=500, detail="Unexpected error during role assignment") from e
    except TimeoutError:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Busy processing a similar request; retry")


# ─────────────────────────────────────────────────────────────────────────────
# Revoke ADMIN role from a user (demote to USER)
# ─────────────────────────────────────────────────────────────────────────────
@router.put(
    "/{user_id}/revoke-ADMIN",
    response_model=RevokeADMINResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke ADMIN role from a user",
    tags=["User Management"],
)
@rate_limit("3/minute")
async def revoke_ADMIN_route(
    request: Request,
    response: Response,
    user_id: UUID,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    """
    Demote a user from ADMIN to USER with concurrency + idempotency guards.

    Requirements
    ------------
    - Caller must be `UserRole.ADMIN` and MFA-authenticated.
    - Target user must exist and be different from the caller.
    - Target must currently be `UserRole.ADMIN`.

    Steps
    -----
    1) Apply sensitive `no-store` headers
    2) Enforce per-actor budget
    3) Short-circuit on idempotency snapshot if provided
    4) Authorization & self-demotion checks
    5) Acquire lock → select `FOR UPDATE` → mutate → commit
    6) Cache idempotent response & audit log
    """
    # 1) No-store cache headers
    set_sensitive_cache(response)

    # 2) Per-actor budget (hourly)
    try:
        await enforce_rate_limit(
            key_suffix=f"revoke-admin:{current_user.id}",
            seconds=3600,
            max_calls=5,
            error_message="Too many admin role changes; please try again later.",
        )
    except HTTPException:
        await log_audit_event(
            db,
            user=current_user,
            action="REVOKE_ADMIN",
            status="RATE_LIMITED",
            request=request,
            meta_data={"target_user_id": str(user_id)},
        )
        raise

    # 3) Idempotency snapshot
    raw_idemp = request.headers.get("Idempotency-Key")
    actor_id = getattr(current_user, "id", None)
    idemp_key = (
        f"idemp:admin:revoke:{actor_id}:{user_id}:{raw_idemp.strip()}"
        if raw_idemp and actor_id
        else None
    )
    if idemp_key:
        try:
            cached = await redis_wrapper.idempotency_get(idemp_key)
        except Exception:
            cached = None
        if cached:
            return RevokeADMINResponse(**cached)

    # 4) Authorization checks
    if current_user.role != UserRole.ADMIN:
        await log_audit_event(
            db,
            user=current_user,
            action="REVOKE_ADMIN",
            status="FORBIDDEN",
            request=request,
            meta_data={"target_user_id": str(user_id)},
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    if current_user.id == user_id:
        await log_audit_event(
            db,
            user=current_user,
            action="REVOKE_ADMIN",
            status="FAILED",
            request=request,
            meta_data={"reason": "self_demotion_blocked", "target_user_id": str(user_id)},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Self-demotion is not allowed")

    # 5) Acquire lock → mutate
    lock_name = f"lock:role_revoke_admin:{user_id}"
    try:
        async with redis_wrapper.lock(lock_name, timeout=10, blocking_timeout=3):
            try:
                stmt = select(User).where(User.id == user_id).with_for_update()
                result = await db.execute(stmt)
                target = result.scalar_one_or_none()

                if not target:
                    await log_audit_event(
                        db,
                        user=current_user,
                        action="REVOKE_ADMIN",
                        status="NOT_FOUND",
                        request=request,
                        meta_data={"target_user_id": str(user_id)},
                    )
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found")

                if target.role != UserRole.ADMIN:
                    await log_audit_event(
                        db,
                        user=current_user,
                        action="REVOKE_ADMIN",
                        status="ALREADY",
                        request=request,
                        meta_data={"target_user_id": str(user_id)},
                    )
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is not ADMIN")

                prev = target.role
                target.role = UserRole.USER
                await db.flush()
                await db.commit()
                try:
                    await db.refresh(target, attribute_names=["role"])
                except Exception:
                    pass

                resp_model = RevokeADMINResponse(
                    message="Role updated to USER",
                    user=SimpleUserResponse(email=target.email),
                    role=str(target.role),
                )

                if idemp_key:
                    try:
                        await redis_wrapper.idempotency_set(idemp_key, resp_model.model_dump(), ttl_seconds=600)
                    except Exception:
                        pass

                await log_audit_event(
                    db,
                    user=current_user,
                    action="REVOKE_ADMIN",
                    status="SUCCESS",
                    request=request,
                    meta_data={
                        "target_user_id": str(target.id),
                        "from_role": str(prev),
                        "to_role": str(target.role),
                        "idempotency": bool(idemp_key is not None),
                    },
                )
                return resp_model

            except HTTPException:
                raise
            except sa_exc.SQLAlchemyError as e:
                await db.rollback()
                await log_audit_event(
                    db,
                    user=current_user,
                    action="REVOKE_ADMIN",
                    status="DB_ERROR",
                    request=request,
                    meta_data={"target_user_id": str(user_id), "error": str(e)},
                )
                raise HTTPException(status_code=500, detail="Database error while revoking ADMIN") from e
            except Exception as e:
                await db.rollback()
                await log_audit_event(
                    db,
                    user=current_user,
                    action="REVOKE_ADMIN",
                    status="ERROR",
                    request=request,
                    meta_data={"target_user_id": str(user_id), "error": str(e)},
                )
                raise HTTPException(status_code=500, detail="Unexpected error during role revocation") from e
    except TimeoutError:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Busy processing a similar request; retry")


# ─────────────────────────────────────────────────────────────────────────────
# List ADMIN users (org-free)
# ─────────────────────────────────────────────────────────────────────────────
@router.get(
    "/admins",
    response_model=List[AdminUserItem],
    summary="List ADMIN users",
    tags=["User Management"],
)
@rate_limit("10/minute")
async def list_admins(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """
    Return a paginated list of users with ADMIN role.

    Requirements
    ------------
    - Caller must be `UserRole.ADMIN` and MFA-authenticated.

    Notes
    -----
    - Sets `Cache-Control: no-store` (sensitive listing).
    """
    set_sensitive_cache(response, seconds=0)

    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    stmt = (
        select(User)
        .where(User.role == UserRole.ADMIN)
        .order_by(User.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    res = await db.execute(stmt)
    users = res.scalars().all() or []

    return [
        AdminUserItem(
            id=u.id,
            email=u.email,
            full_name=getattr(u, "full_name", None),
            is_active=bool(getattr(u, "is_active", True)),
            role=str(getattr(u, "role", UserRole.USER)),
        )
        for u in users
    ]
