from __future__ import annotations

"""
Account deletion API — hardened, production-grade
================================================

Endpoints
---------
POST  /request-deletion-otp
    Issue a one-time email OTP for **account deletion** (for non-MFA users).

DELETE /delete-user
    Delete the authenticated user's account after verifying MFA/OTP or a
    short-lived **reauth** token minted by `/reauth/*`.

Design & Security
-----------------
- **No plaintext OTP at rest** (peppered HMAC digest only; generated via shared helper).
- **Strict Redis rate limits** (issuance + destructive attempts).
- **Cache hardening** with `Cache-Control: no-store` on all responses.
- **Non-blocking** email + audit using `BackgroundTasks`.
- **Single source of truth**: All factor checks (reauth/TOTP/OTP) are handled
  by `app.services.auth.account_service.delete_user(reauth_validated=...)`.

Step-Up (Reauth) integration
----------------------------
If the caller presents a valid **reauth** bearer (JWT with `token_type=reauth`),
this route passes `reauth_validated=True` to the service and **does not**
require `mfa_token`/`code` again. If no/invalid reauth is present, the service
falls back to legacy MFA (TOTP) or email-OTP paths.
"""

from datetime import datetime, timedelta, timezone
import logging
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Request, Response
from jose import jwt, JWTError
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import get_current_user
from app.db.models.otp import OTP
from app.db.models.user import User
from app.db.session import get_async_db
from app.schemas.auth import MFAProtectedActionRequest, MessageResponse
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import AuditEvent, log_audit_event
from app.services.auth.account_service import delete_user as service_delete_user
from app.services.auth.password_reset_service import _hash_otp, generate_otp
import app.utils.redis_utils as redis_utils
from app.utils.email_utils import send_password_reset_otp

router = APIRouter(tags=["Account"])
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# 🔧 Helpers (no duplication of business logic)
# ─────────────────────────────────────────────────────────────

def _invalidate_user_caches_safe(user_id) -> None:
    """Best-effort invalidation of user-scoped caches; never raises."""
    tags = [f"user:{user_id}", f"user:{user_id}:auth", f"user:{user_id}:profile"]
    try:
        try:
            from app.utils.cache import cache_invalidate_tags  # type: ignore
        except Exception:
            cache_invalidate_tags = None  # type: ignore
        if cache_invalidate_tags:
            maybe_coro = cache_invalidate_tags(*tags)
            if hasattr(maybe_coro, "__await__"):
                import asyncio
                asyncio.create_task(maybe_coro)
            return
        try:
            from app.utils.cache import cache_invalidation_tags as _alt  # type: ignore
        except Exception:
            _alt = None  # type: ignore
        if _alt:
            maybe_coro = _alt(*tags)
            if hasattr(maybe_coro, "__await__"):
                import asyncio
                asyncio.create_task(maybe_coro)
    except Exception:
        pass


def _has_valid_reauth_bearer(request: Request) -> bool:
    """
    Best-effort: return True iff `Authorization: Bearer <jwt>` decodes and
    carries `token_type=reauth`. We intentionally do not raise here; the
    service can still fall back to MFA/OTP validation.
    """
    try:
        authz = request.headers.get("authorization") or request.headers.get("Authorization")
        if not authz or not authz.lower().startswith("bearer "):
            return False
        token = authz.split(" ", 1)[1].strip()
        claims = jwt.decode(
            token,
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["sub", "exp"]},
        )
        tok_typ = (claims.get("token_type") or claims.get("typ") or "").lower()
        return tok_typ == "reauth"
    except JWTError:
        return False
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
# 📩 Request deletion OTP (non-MFA users)
# ─────────────────────────────────────────────────────────────
@router.post(
    "/request-deletion-otp",
    response_model=MessageResponse,
    summary="Send OTP for account deletion (non-MFA users)",
)
async def request_deletion_otp(
    background_tasks: BackgroundTasks,
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """
    Send a one-time email OTP for **account deletion** (non-MFA users only).

    Steps
    -----
    0) Mark response **no-store**.
    1) If user has MFA, return a gentle hint to use authenticator (no OTP).
    2) Enforce **3/min** issuance rate limit per user (Redis).
    3) Delete any unused prior deletion OTPs for this user.
    4) Generate a 6-digit OTP → store **peppered HMAC** digest only.
    5) Email the plaintext OTP (asynchronously); log an audit event (async).
    """
    # [Step 0] Sensitive cache headers
    set_sensitive_cache(response)

    # [Step 1] Refuse when MFA is enabled (prefer authenticator)
    if current_user.mfa_enabled:
        return MessageResponse(message="MFA is enabled. Use your authenticator app.")

    try:
        # [Step 2] Per-user throttle (3/min)
        await redis_utils.enforce_rate_limit(
            key_suffix=f"delete-otp:{current_user.id}",
            seconds=60,
            max_calls=3,
            error_message="Please wait before requesting another OTP.",
        )

        # [Step 3] Clear any unused prior deletion OTPs
        await db.execute(
            delete(OTP).where(
                OTP.user_id == current_user.id,
                OTP.purpose == "delete_account",
                OTP.used == False,  # noqa: E712
            )
        )

        # [Step 4] Persist only a **digest** (no plaintext at rest)
        otp_plain = generate_otp(6)
        otp_hmac = _hash_otp(otp_plain, user_id=str(current_user.id), purpose="delete_account")

        db.add(
            OTP(
                user_id=current_user.id,
                code=otp_hmac,
                purpose="delete_account",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
                used=False,
            )
        )
        await db.commit()

        # [Step 5] Fire-and-forget email + audit
        background_tasks.add_task(send_password_reset_otp, current_user.email, otp_plain)
        background_tasks.add_task(
            log_audit_event,
            db=db,
            user=current_user,
            action=AuditEvent.REQUEST_DELETION_OTP,
            status="SUCCESS",
            request=request,
            meta_data={"email": current_user.email},
            commit=False,
        )

        return MessageResponse(message="OTP has been sent to your email.")

    except HTTPException:
        # Neutral audit on expected errors
        background_tasks.add_task(
            log_audit_event,
            db=db,
            user=current_user,
            action=AuditEvent.REQUEST_DELETION_OTP,
            status="FAILURE",
            request=request,
            meta_data={"reason": "HTTPException"},
            commit=False,
        )
        raise
    except Exception:
        await db.rollback()
        background_tasks.add_task(
            log_audit_event,
            db=db,
            user=current_user,
            action=AuditEvent.REQUEST_DELETION_OTP,
            status="FAILURE",
            request=request,
            meta_data={"error": "internal_error"},
            commit=False,
        )
        logger.exception("❌ Failed to send deletion OTP")
        raise HTTPException(status_code=500, detail="Failed to send deletion OTP.")


# ─────────────────────────────────────────────────────────────
# 🧨 Delete current user (reauth OR MFA/OTP; service handles checks)
# ─────────────────────────────────────────────────────────────
@router.delete(
    "/delete-user",
    response_model=MessageResponse,
    summary="Delete the authenticated user's account",
)
async def delete_user_account(
    background_tasks: BackgroundTasks,
    request: Request,
    response: Response,
    payload: MFAProtectedActionRequest = Body(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """
    Delete the authenticated user's account using **one** of the following:

    - **Step-Up (preferred):** Present a valid **reauth** bearer (from `/reauth/*`);
      `mfa_token`/`code` are not required.
    - **Legacy MFA:** Provide `mfa_token` + TOTP code if MFA is enabled.
    - **Email OTP (non-MFA users):** Provide the OTP sent to the account email.

    Implementation notes
    --------------------
    - This route **does not** duplicate any factor verification logic. It simply
      detects a reauth bearer (if any) and passes `reauth_validated` to the service,
      which performs the correct checks and state changes.
    - Destructive attempts are rate-limited (3 per 30s per user).
    - Cache is marked **no-store**; email/audit are queued asynchronously.
    """
    # [Step 0] Sensitive cache headers
    set_sensitive_cache(response)

    # [Step 1] Guard against automated hammering
    await redis_utils.enforce_rate_limit(
        key_suffix=f"delete-user:{current_user.id}",
        seconds=30,
        max_calls=3,
        error_message="Please wait before attempting another delete.",
    )

    # [Step 2] Best-effort detect a valid **reauth** bearer
    reauth_ok = _has_valid_reauth_bearer(request)

    try:
        # [Step 3] Delegate to the service (single source of truth)
        result = await service_delete_user(
            current_user=current_user,
            mfa_token=payload.mfa_token,
            code=payload.code,
            db=db,
            request=request,
            background_tasks=background_tasks,
            reauth_validated=reauth_ok,
        )

        # [Step 4] Best-effort cache invalidation + async audit
        _invalidate_user_caches_safe(current_user.id)
        background_tasks.add_task(
            log_audit_event,
            db=db,
            user=current_user,
            action=AuditEvent.DELETE_USER,
            status="SUCCESS",
            request=request,
            meta_data={"message": result["message"], "reauth": reauth_ok},
            commit=False,
        )

        return MessageResponse(message=result["message"])

    except HTTPException as e:
        await db.rollback()
        background_tasks.add_task(
            log_audit_event,
            db=db,
            user=current_user,
            action=AuditEvent.DELETE_USER,
            status="FAILURE",
            request=request,
            meta_data={"error": str(e.detail)},
            commit=False,
        )
        raise
    except Exception:
        await db.rollback()
        background_tasks.add_task(
            log_audit_event,
            db=db,
            user=current_user,
            action=AuditEvent.DELETE_USER,
            status="FAILURE",
            request=request,
            meta_data={"error": "internal_error"},
            commit=False,
        )
        logger.exception("❌ Failed to delete user")
        raise HTTPException(status_code=500, detail="Failed to delete user.")


__all__ = ["router"]
