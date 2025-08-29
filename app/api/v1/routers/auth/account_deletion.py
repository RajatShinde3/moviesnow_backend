# app/api/v1/account/delete_account.py
from __future__ import annotations

"""
Account Deletion API — hardened, production‑grade (MoviesNow, org‑free)
=====================================================================

Endpoints
---------
POST  `/request-deletion-otp`
    Issue a one‑time email OTP for **account deletion** (for non‑MFA users).

DELETE `/delete-user`
    Delete the authenticated user's account after verifying MFA/OTP or a
    short‑lived **reauth** token minted by `/reauth/*`.

Design & Security
-----------------
- **No plaintext OTP at rest** (peppered HMAC digest only; shared helper).
- **Strict Redis rate limits** (issuance + destructive attempts).
- **Cache hardening** with `Cache-Control: no-store` on all responses.
- **Non‑blocking** email + audit using `BackgroundTasks` (best‑effort).
- **Single source of truth**: all factor checks (reauth/TOTP/OTP) are delegated
  to `app.services.auth.account_service.delete_user(reauth_validated=...)`.

Step‑Up (Reauth) integration
----------------------------
If the caller presents a valid **reauth** bearer (JWT with `token_type=reauth`),
this route passes `reauth_validated=True` to the service and **does not**
require `mfa_token`/`code` again. If no/invalid reauth is present, the service
falls back to legacy MFA (TOTP) or email‑OTP paths.
"""

from datetime import datetime, timedelta, timezone
import logging
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.limiter import rate_limit
from app.core.jwt import get_bearer_token, decode_token
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

router = APIRouter(prefix="/account", tags=["Account"])  # grouped under Account
logger = logging.getLogger("moviesnow.account.delete")


# ─────────────────────────────────────────────────────────────
# 🔧 Helpers (no duplication of business logic)
# ─────────────────────────────────────────────────────────────

def _invalidate_user_caches_safe(user_id) -> None:
    """Best‑effort invalidation of user‑scoped caches; never raises."""
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
    """Return True if Authorization bearer decodes and has `token_type=reauth`.

    Uses centralized JWT helpers and **never raises**; callers can still fall
    back to MFA/OTP validation when this returns False.
    """
    try:
        token = get_bearer_token(request)
        if not token:
            return False
        claims = awaitable_decode(token)
        tok_typ = (claims.get("token_type") or claims.get("typ") or "").lower()
        return tok_typ == "reauth"
    except Exception:
        return False


async def awaitable_decode(token: str) -> dict:
    """Small wrapper to allow calling `decode_token` in both sync/async contexts."""
    decoded = await decode_token(token)
    # Some decoders may return pydantic models; normalize to dict
    return dict(decoded) if not isinstance(decoded, dict) else decoded


# ─────────────────────────────────────────────────────────────
# 📩 Request deletion OTP (non‑MFA users)
# ─────────────────────────────────────────────────────────────
@router.post(
    "/request-deletion-otp",
    response_model=MessageResponse,
    summary="Send OTP for account deletion (non‑MFA users)",
)
@rate_limit("6/minute")
async def request_deletion_otp(
    background_tasks: BackgroundTasks,
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """Send a one‑time email OTP for **account deletion** (non‑MFA users only).

    Steps
    -----
    0) Mark response **no‑store**.
    1) If user has MFA, return a gentle hint to use authenticator (no OTP).
    2) Enforce **3/min** issuance rate limit per user (Redis).
    3) Delete any unused prior deletion OTPs for this user.
    4) Generate a 6‑digit OTP → store **peppered HMAC** digest only.
    5) Email the plaintext OTP (asynchronously); enqueue an audit event.
    """
    # [Step 0] Sensitive cache headers
    set_sensitive_cache(response)

    # [Step 1] Refuse when MFA is enabled (prefer authenticator)
    if getattr(current_user, "mfa_enabled", False):
        return MessageResponse(message="MFA is enabled. Use your authenticator app.")

    try:
        # [Step 2] Per‑user throttle (3/min)
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

        # [Step 5] Fire‑and‑forget email + audit
        background_tasks.add_task(send_password_reset_otp, current_user.email, otp_plain)
        background_tasks.add_task(
            log_audit_event,
            db=db,
            user=current_user,
            action=getattr(AuditEvent, "REQUEST_DELETION_OTP", "REQUEST_DELETION_OTP"),
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
            action=getattr(AuditEvent, "REQUEST_DELETION_OTP", "REQUEST_DELETION_OTP"),
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
            action=getattr(AuditEvent, "REQUEST_DELETION_OTP", "REQUEST_DELETION_OTP"),
            status="FAILURE",
            request=request,
            meta_data={"error": "internal_error"},
            commit=False,
        )
        logger.exception("Failed to send deletion OTP")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to send deletion OTP.")


# ─────────────────────────────────────────────────────────────
# 🧨 Delete current user (reauth OR MFA/OTP; service handles checks)
# ─────────────────────────────────────────────────────────────
@router.delete(
    "/delete-user",
    response_model=MessageResponse,
    summary="Delete the authenticated user's account",
)
@rate_limit("6/minute")
async def delete_user_account(
    background_tasks: BackgroundTasks,
    request: Request,
    response: Response,
    payload: MFAProtectedActionRequest = Body(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """Delete the authenticated user's account using **one** of the following:

    - **Step‑Up (preferred):** Present a valid **reauth** bearer (from `/reauth/*`);
      `mfa_token`/`code` are not required.
    - **Legacy MFA:** Provide `mfa_token` + TOTP code if MFA is enabled.
    - **Email OTP (non‑MFA users):** Provide the OTP sent to the account email.

    Implementation notes
    --------------------
    - This route **does not** duplicate any factor verification logic. It simply
      detects a reauth bearer (if any) and passes `reauth_validated` to the service,
      which performs the correct checks and state changes.
    - Destructive attempts are rate‑limited (3 per 30s per user).
    - Cache is marked **no‑store**; email/audit are queued asynchronously.
    """
    # [Step 0] Sensitive cache headers
    set_sensitive_cache(response)

    # [Step 1] Guard against automated hammering (per user)
    await redis_utils.enforce_rate_limit(
        key_suffix=f"delete-user:{current_user.id}",
        seconds=30,
        max_calls=3,
        error_message="Please wait before attempting another delete.",
    )

    # [Step 2] Best‑effort detect a valid **reauth** bearer
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

        # [Step 4] Best‑effort cache invalidation + async audit
        _invalidate_user_caches_safe(current_user.id)
        background_tasks.add_task(
            log_audit_event,
            db=db,
            user=current_user,
            action=AuditEvent.DELETE_USER,
            status="SUCCESS",
            request=request,
            meta_data={"message": result.get("message"), "reauth": reauth_ok},
            commit=False,
        )

        return MessageResponse(message=result.get("message", "Account deleted"))

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
        logger.exception("Failed to delete user")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete user.")


__all__ = ["router", "request_deletion_otp", "delete_user_account"]
