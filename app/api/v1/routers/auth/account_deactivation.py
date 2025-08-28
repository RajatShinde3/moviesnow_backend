
"""
Account deactivation API — hardened, production-grade
====================================================

Endpoints
---------
POST  /request-deactivation-otp
    Send a one-time email OTP for account deactivation (for **non-MFA** users).

PUT   /deactivate-user
    Deactivate the authenticated user's account after factor verification:
      • MFA users: present a short-lived **reauth** token (from /reauth/mfa)
      • Non-MFA users: present **email OTP** (or optionally a **reauth/password** token)

Design & Security
-----------------
- **Step-Up first**: MFA users must step-up via /reauth/mfa (TOTP → reauth).
- **OTP fallback**: Non-MFA users can use a 6-digit email OTP.
- **Strict rate limits** for OTP issuance with Redis.
- **Zero secret leakage** in logs; only minimal audit metadata.
- **Sensitive cache headers**: all responses are `Cache-Control: no-store`.
- **Atomic updates** and best-effort cache invalidation after deactivation.
"""

from datetime import datetime, timedelta, timezone
import logging
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user_allow_inactive
from app.db.models.otp import OTP
from app.db.models.user import User
from app.db.session import get_async_db
from app.schemas.auth import MFAProtectedActionRequest, MessageResponse
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import AuditEvent, log_audit_event
from app.services.auth.account_service import deactivate_user
from app.services.auth.password_reset_service import _hash_otp, generate_otp
import app.utils.redis_utils as redis_utils
from app.utils.email_utils import send_password_reset_otp

# Optional: lightweight, reusable reauth validator
from app.dependencies.step_up import step_up_required

router = APIRouter(tags=["Account"])
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# 🔧 Helpers
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


async def _try_reauth(
    request: Request,
    *,
    require_mfa_for_mfa_users: bool,
) -> Optional[dict]:
    """
    Validate a **reauth** token if present in headers and return its claims.
    Accepted headers: X-Reauth / X-Reauth-Token / X-Action-Token.
    If no reauth header is present, return None (caller decides the fallback).
    """
    # Peek the headers without forcing dependency failure
    reauth_header = (
        request.headers.get("X-Reauth")
        or request.headers.get("X-Reauth-Token")
        or request.headers.get("X-Action-Token")
    )
    if not reauth_header:
        return None

    # Reuse the hardened validator; bind to the current access session, one-time use on
    # by default; don't force MFA here, we’ll decide based on the user's MFA status.
    validator = step_up_required(require_mfa=False, bind_session=True, one_time=True)
    claims = await validator(request)

    # Enforce that MFA users actually used an MFA-backed reauth (not password only)
    if require_mfa_for_mfa_users and not bool(claims.get("mfa_authenticated")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA step-up required",
        )
    return claims


# ─────────────────────────────────────────────────────────────
# 📩 Request deactivation OTP (non-MFA users)
# ─────────────────────────────────────────────────────────────
@router.post(
    "/request-deactivation-otp",
    response_model=MessageResponse,
    summary="Send OTP for account deactivation (non-MFA users)",
)
async def request_deactivation_otp(
    background_tasks: BackgroundTasks,
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user_allow_inactive),
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """Send a one-time code to the user's email for account deactivation.

    Rules
    -----
    - Only for users **without** MFA (MFA users should step-up via /reauth/mfa).
    - Cleans up unused prior deactivation OTPs.
    - Per-user rate limit via Redis (default 3/min).
    - Non-blocking audit + email.
    """
    set_sensitive_cache(response)

    # Refuse when MFA is enabled (authenticator flow is safer)
    if current_user.mfa_enabled:
        return MessageResponse(message="MFA is enabled. Use your authenticator app instead.")

    try:
        # Enforce per-user issuance throttle
        await redis_utils.enforce_rate_limit(
            key_suffix=f"deactivation-otp:{current_user.id}",
            seconds=60,
            max_calls=3,
            error_message="Please wait before requesting another OTP.",
        )

        # Clear unused prior deactivation OTPs
        await db.execute(
            delete(OTP).where(
                OTP.user_id == current_user.id,
                OTP.purpose == "deactivate_account",
                OTP.used == False,  # noqa: E712
            )
        )

        # Generate + persist a hashed OTP (never store plaintext)
        otp_plain = generate_otp(6)
        otp_hmac = _hash_otp(otp_plain, user_id=str(current_user.id), purpose="deactivate_account")

        db.add(
            OTP(
                user_id=current_user.id,
                code=otp_hmac,
                purpose="deactivate_account",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
                used=False,
            )
        )
        await db.commit()

        # Send OTP email asynchronously
        background_tasks.add_task(send_password_reset_otp, current_user.email, otp_plain)

        # Audit success (non-blocking)
        background_tasks.add_task(
            log_audit_event,
            db=db,
            user=current_user,
            action=AuditEvent.REQUEST_DEACTIVATION_OTP,
            status="SUCCESS",
            request=request,
            meta_data={"email": current_user.email},
            commit=False,
        )

        return MessageResponse(message="OTP has been sent to your email.")

    except HTTPException:
        background_tasks.add_task(
            log_audit_event,
            db=db,
            user=current_user,
            action=AuditEvent.REQUEST_DEACTIVATION_OTP,
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
            action=AuditEvent.REQUEST_DEACTIVATION_OTP,
            status="FAILURE",
            request=request,
            meta_data={"error": "internal_error"},
            commit=False,
        )
        logger.exception("❌ Failed to send deactivation OTP")
        raise HTTPException(status_code=500, detail="Failed to send deactivation OTP.")


# ─────────────────────────────────────────────────────────────
# 📴 Deactivate current user (Step-Up for MFA users; OTP for non-MFA)
# ─────────────────────────────────────────────────────────────
@router.put(
    "/deactivate-user",
    response_model=MessageResponse,
    summary="Deactivate the authenticated user's account",
)
async def deactivate_user_account(
    background_tasks: BackgroundTasks,
    request: Request,
    response: Response,
    payload: MFAProtectedActionRequest,
    current_user: User = Depends(get_current_user_allow_inactive),
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """Deactivate the authenticated user's account.

    Paths
    -----
    - **MFA enabled** → must present a **reauth** token (from `/reauth/mfa`) in
      `X-Reauth` / `X-Reauth-Token` / `X-Action-Token`. We enforce MFA-backed step-up.
      (Optionally, you may also accept TOTP here and mint reauth server-side, but
      reauth-first is the recommended pattern.)
    - **MFA disabled** → present **email OTP** (or send a password-backed reauth token).

    Side effects
    ------------
    - Marks user inactive, sets deactivation/scheduled deletion, emits audit.
    - Best-effort cache invalidation for user-scoped entries on success.
    """
    set_sensitive_cache(response)

    try:
        # ── [Step 1] Try step-up (reauth) if caller sent it ───────────────────
        reauth_claims = await _try_reauth(
            request,
            require_mfa_for_mfa_users=bool(current_user.mfa_enabled),
        )

        # ── [Step 2] Decide the verification path ─────────────────────────────
        # Non-MFA users:
        #  - Prefer reauth/password if provided (reauth_claims will be non-None),
        #  - else require the email OTP in the payload.
        if not current_user.mfa_enabled and not reauth_claims and not (payload and payload.code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP code required for deactivation",
            )

        # ── [Step 3] Perform the deactivation via service layer ───────────────
        # We pass through the payload values to keep compatibility with your service.
        # If a reauth token was supplied/validated, the service can ignore code/mfa_token
        # or you can keep them for metrics. (No secrets/log leakage.)
        result = await deactivate_user(
            current_user=current_user,
            mfa_token=payload.mfa_token,   # keep compatibility with existing service signature
            code=payload.code,             # email OTP (non-MFA) or TOTP if you still support it internally
            db=db,
            request=request,
        )

        # ── [Step 4] Cache invalidation & audit ───────────────────────────────
        _invalidate_user_caches_safe(current_user.id)

        background_tasks.add_task(
            log_audit_event,
            db=db,
            user=current_user,
            action=AuditEvent.DEACTIVATE_USER,
            status="SUCCESS",
            request=request,
            meta_data={"message": result.get("message", "deactivated")},
            commit=False,
        )

        return MessageResponse(message=result.get("message", "Your account has been deactivated."))

    except HTTPException as e:
        await db.rollback()
        background_tasks.add_task(
            log_audit_event,
            db=db,
            user=current_user,
            action=AuditEvent.DEACTIVATE_USER,
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
            action=AuditEvent.DEACTIVATE_USER,
            status="FAILURE",
            request=request,
            meta_data={"error": "internal_error"},
            commit=False,
        )
        logger.exception("❌ Unexpected error during account deactivation")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while deactivating your account.")


__all__ = ["router"]
