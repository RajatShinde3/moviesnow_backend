# app/api/v1/account/delete_account.py

"""
Account Deletion API (v1/Auth)
==============================

This module exposes two endpoints (mounted under `/api/v1/auth` by your
versioned router) to safely **issue an OTP** for account deletion and to
**delete the authenticated user** after verifying *one* of several factors
(step-up reauth, TOTP, or email OTP).

Endpoints
---------
POST  /request-deletion-otp
    Issue a one-time email OTP for **account deletion** (non-MFA users only).

DELETE /delete-user
    Delete the authenticated user's account after verifying **one** of:
    - a valid **reauth** bearer (preferred),
    - a valid **TOTP** (for MFA users),
    - a valid **email OTP** (for non-MFA users).

Design Goals & Protections
--------------------------
- **No plaintext OTP at rest:** we persist only a peppered HMAC digest.
- **Dual rate limits:**
  - Redis per-user throttle for OTP issuance (3/min).
  - Redis per-user throttle for destructive delete attempts (3/30s).
- **Strict caching policy:** every response is marked `Cache-Control: no-store`.
- **Clear responsibility boundaries:**
  - *This router* handles HTTP concerns, throttling, cache headers, and
    lightweight input plumbing.
  - **All factor checks** and the actual user deletion happen in
    `app.services.auth.account_service.delete_user(...)` — the single source
    of truth for auth flows.
- **Observability:** all code paths are audited (success/failure), with minimal
  PII (email only where necessary).

Behavioral Notes
----------------
- If the caller presents a valid **reauth** bearer (JWT claim `token_type=reauth`),
  we pass `reauth_validated=True` into the service and do **not** require
  `mfa_token`/`code` again.
- For OTP issuance, we **await** both the email send and the audit write so
  tests can deterministically assert effects. For deletion, we **do not pass**
  `BackgroundTasks` into the service (matches test expectations that no
  reactivation email is sent by the route).

Example Responses
-----------------
- 200 OK `{ "message": "OTP has been sent to your email." }`
- 200 OK `{ "message": "Account deleted" }`
- 400/401/403 for invalid factor inputs (surfaced from the service).
- 429 on rate limits with a helpful message.

"""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

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

router = APIRouter(tags=["Auth"])
logger = logging.getLogger("moviesnow.account.delete")


# ─────────────────────────────────────────────────────────────
# 🔧 Helpers (no duplication of business logic)
# ─────────────────────────────────────────────────────────────

async def _has_valid_reauth_bearer(request: Request) -> bool:
    """
    Return True iff Authorization bearer exists and decodes to a JWT with
    `token_type` (or `typ`) == "reauth". Never raises; returns False on error.
    """
    try:
        token = get_bearer_token(request)
        if not token:
            return False
        claims = await decode_token(token)  # may return pydantic model or dict
        if not isinstance(claims, dict):
            claims = dict(claims)  # normalize
        tok_typ = (claims.get("token_type") or claims.get("typ") or "").lower()
        return tok_typ == "reauth"
    except Exception:
        return False


def _invalidate_user_caches_safe(user_id: Any) -> None:
    """
    Best-effort invalidation of user-scoped caches; never raises.
    Tries both `cache_invalidate_tags` and a legacy alias `cache_invalidation_tags`.
    """
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
        # swallow on purpose
        pass


# ─────────────────────────────────────────────────────────────
# 📩 Request deletion OTP (non-MFA users)
# ─────────────────────────────────────────────────────────────

@router.post(
    "/request-deletion-otp",
    response_model=MessageResponse,
    summary="Send OTP for account deletion (non-MFA users)",
)
@rate_limit("6/minute")
async def request_deletion_otp(
    background_tasks: BackgroundTasks,
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """
    Send a one-time **email OTP** to the authenticated user for **account deletion**.

    Steps
    -----
    0) Mark response `no-store`.
    1) If user has MFA enabled, return a hint to use the authenticator (no OTP created).
    2) Enforce **3/min** per-user issuance rate limit (Redis).
    3) Delete any **unused** prior deletion OTPs for this user.
    4) Generate a 6-digit OTP → persist **peppered HMAC digest** only (no plaintext at rest).
    5) **Await** email send and audit write (deterministic for tests).

    Returns
    -------
    200 OK with a generic message on success.
    429 if rate-limited; 5xx on unexpected errors.
    """
    # [Step 0] Sensitive cache headers
    set_sensitive_cache(response)

    # [Step 1] Prefer authenticator for MFA users (compat path returns 200)
    if getattr(current_user, "mfa_enabled", False):
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
        otp_plain = generate_otp()  # 6 digits by default
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

        # [Step 5] Send email + audit (awaited so tests see the calls)
        await send_password_reset_otp(current_user.email, otp_plain)
        await log_audit_event(
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
        # Rate limit & other HTTPException: neutral audit, then bubble up
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send deletion OTP.",
        )


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
    """
    Delete the authenticated user's account using **one** of the following factors:

    Preferred
    ---------
    - **Step-Up (reauth):** Provide a valid **reauth** bearer (JWT with `token_type=reauth`);
      `mfa_token`/`code` are not required in this case.

    Alternatives
    -----------
    - **Legacy MFA:** Provide `mfa_token` + a valid TOTP code if MFA is enabled.
    - **Email OTP (non-MFA users):** Provide the OTP sent to the account email.

    Implementation Notes
    --------------------
    - The router sets `no-store`, applies a per-user delete throttle (3/30s),
      and delegates all factor verification to the **account service**.
    - We **do not pass** `BackgroundTasks` into the service (tests expect
      that no reactivation email is scheduled by the route).

    Returns
    -------
    200 with a success message, or an HTTP error from the service (400/401/403),
    or 429 on rate limit.
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

    # [Step 2] Best-effort detect a valid **reauth** bearer
    reauth_ok = await _has_valid_reauth_bearer(request)

    try:
        # [Step 3] Delegate to the service (single source of truth)
        result: Dict[str, Any] = await service_delete_user(
            current_user=current_user,
            mfa_token=payload.mfa_token,
            code=payload.code,
            db=db,
            request=request,
            # IMPORTANT: do NOT pass background_tasks to the service (tests expect this)
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user.",
        )


__all__ = ["router", "request_deletion_otp", "delete_user_account"]
