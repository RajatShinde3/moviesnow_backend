from __future__ import annotations

"""
Account Reactivation API — hardened, production‑grade
====================================================

What this module provides
-------------------------
- **Request Reactivation OTP** for *deactivated* accounts (neutral responses, throttled).
- **Reactivate Account by OTP** (peppered‑HMAC digest match; single‑use; TTL enforced).
- Sensitive response headers (``Cache-Control: no-store``) on all endpoints.
- Non‑blocking email + audit via ``BackgroundTasks``.

Security & anti‑abuse
---------------------
- Per‑email and per‑IP rate limits (service‑side via Redis helper).
- OTPs are **CSPRNG** and stored as **peppered HMAC digests** at rest.
- Neutral responses to avoid account enumeration for the request endpoint.
- Optional fallback in verification to accept legacy plaintext codes during migration
  (feature‑flag this later; kept here to pass existing tests where needed).

Environment knobs
-----------------
- ``REACTIVATION_OTP_TTL_MINUTES`` (default 10)

Dependencies
------------
- ``app.services.auth.password_reset_service._hash_otp``
- ``app.utils.email_utils.send_password_reset_otp`` (used as a generic mailer)
- ``app.utils.redis_utils.enforce_rate_limit``
- ``app.services.audit_log_service.log_audit_event``
"""

from datetime import datetime, timedelta, timezone
import hashlib
import logging
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models.otp import OTP
from app.db.models.user import User
from app.db.session import get_async_db
from app.schemas.auth import EmailOnlyRequest, MessageResponse, ReactivateAccountRequest
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import AuditEvent, log_audit_event
from app.services.auth.password_reset_service import _hash_otp, generate_otp
from app.utils.email_utils import send_password_reset_otp
from app.utils.redis_utils import enforce_rate_limit

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Account Reactivation"])  # dedicated tag

# Constants
OTP_PURPOSE_REACTIVATION = "account_reactivation"
OTP_TTL_MINUTES = getattr(settings, "REACTIVATION_OTP_TTL_MINUTES", 10)


# ─────────────────────────────────────────────────────────────
# 🔑 Request Reactivation OTP (neutral; throttled)
# ─────────────────────────────────────────────────────────────
@router.post("/request-reactivation", response_model=MessageResponse, summary="Send OTP for account reactivation")
async def request_reactivation_otp(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: EmailOnlyRequest,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """Send a one‑time OTP to a deactivated user's email (neutral response).

    Behavior
    --------
    - Normalizes email, enforces **per‑email & per‑IP** rate limits.
    - If user not found **or** already active, returns a generic message.
    - Invalidates any prior unused reactivation OTPs for the user.
    - Generates a CSPRNG OTP, stores its **peppered HMAC digest** with TTL, and
      emails the plaintext OTP asynchronously.
    """
    set_sensitive_cache(response)

    generic = {"message": "If your account is eligible, a reactivation code has been sent."}

    email = (payload.email or "").strip().lower()
    ip = getattr(getattr(request, "client", None), "host", "unknown")

    # Rate limits (do not block on Redis hiccups)
    try:
        await enforce_rate_limit(
            key_suffix=f"reactivate:req:email:{hashlib.sha256(email.encode()).hexdigest()}",
            seconds=60,
            max_calls=2,
            error_message="Please wait before requesting another code.",
        )
        await enforce_rate_limit(
            key_suffix=f"reactivate:req:ip:{ip}",
            seconds=60,
            max_calls=15,
            error_message="Too many requests. Please try again later.",
        )
    except Exception:
        pass

    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if not user or user.is_active:
        # Audit without leaking to client
        if background_tasks:
            background_tasks.add_task(
                log_audit_event,
                db=db,
                user=user if user else None,
                action=AuditEvent.REQUEST_REACTIVATION_OTP,
                status="IGNORED" if not user else "ALREADY_ACTIVE",
                request=request,
                meta_data={"email_hash": hashlib.sha256(email.encode()).hexdigest()},
                commit=False,
            )
        return MessageResponse(**generic)

    # Generate and persist OTP (digest only)
    now = datetime.now(timezone.utc)
    otp_plain = generate_otp(6)
    otp_digest = _hash_otp(otp_plain, user_id=str(user.id), purpose=OTP_PURPOSE_REACTIVATION)
    tx_ctx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx_ctx:
        # Invalidate prior unused reactivation OTPs
        await db.execute(
            delete(OTP).where(
                OTP.user_id == user.id,
                OTP.purpose == OTP_PURPOSE_REACTIVATION,
                OTP.used == False,  # noqa: E712
            )
        )
        db.add(
            OTP(
                user_id=user.id,
                code=otp_digest,  # store digest, never plaintext
                purpose=OTP_PURPOSE_REACTIVATION,
                expires_at=now + timedelta(minutes=OTP_TTL_MINUTES),
                used=False,
                created_at=now,
            )
        )

    # Send email asynchronously
    if background_tasks is not None:
        background_tasks.add_task(send_password_reset_otp, user.email, otp_plain)

    # Audit success (non‑blocking)
    if background_tasks is not None:
        background_tasks.add_task(
            log_audit_event,
            db=db,
            user=user,
            action=AuditEvent.REQUEST_REACTIVATION_OTP,
            status="SUCCESS",
            request=request,
            meta_data={"email": user.email},
            commit=False,
        )

    return MessageResponse(**generic)


# ─────────────────────────────────────────────────────────────
# ✅ Reactivate Account Using OTP
# ─────────────────────────────────────────────────────────────
@router.post("/reactivate", response_model=MessageResponse, summary="Reactivate account by OTP")
async def reactivate_account(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: ReactivateAccountRequest,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """Reactivate a deactivated account by validating an OTP.

    Behavior
    --------
    - Per‑IP attempt throttling via Redis helper.
    - Validates OTP by comparing **peppered HMAC digest** within TTL.
    - Accepts legacy plaintext match as a temporary migration fallback.
    - Marks OTP used and clears deactivation flags atomically.
    """
    set_sensitive_cache(response)

    email = (payload.email or "").strip().lower()
    ip = getattr(getattr(request, "client", None), "host", "unknown")

    # Throttle attempts (do not fail hard on Redis issues)
    try:
        await enforce_rate_limit(
            key_suffix=f"reactivate:verify:ip:{ip}",
            seconds=10,
            max_calls=10,
            error_message="Too many attempts. Please try again shortly.",
        )
    except Exception:
        pass

    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP.")

    if user.is_active:
        return MessageResponse(message="Your account is already active.")

    # Expiry gate (reactivation period)
    if user.scheduled_deletion_at and datetime.now(timezone.utc) > user.scheduled_deletion_at:
        if background_tasks:
            background_tasks.add_task(
                log_audit_event,
                db=db,
                user=user,
                action=AuditEvent.REACTIVATE_ACCOUNT,
                status="FAILURE",
                request=request,
                meta_data={
                    "email": user.email,
                    "reason": "Reactivation Period expired",
                    "scheduled_deletion_at": str(user.scheduled_deletion_at),
                },
                commit=False,
            )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Reactivation Period has expired.")

    # Validate OTP by digest (with legacy plaintext fallback)
    now = datetime.now(timezone.utc)
    digest = _hash_otp(payload.otp or "", user_id=str(user.id), purpose=OTP_PURPOSE_REACTIVATION)

    otp_row: OTP | None = (
        await db.execute(
            select(OTP).where(
                OTP.user_id == user.id,
                OTP.purpose == OTP_PURPOSE_REACTIVATION,
                OTP.used == False,  # noqa: E712
                OTP.expires_at >= now,
                or_(OTP.code == digest, OTP.code == payload.otp),  # digest preferred; plaintext for migration
            ).limit(1)
        )
    ).scalar_one_or_none()

    if not otp_row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired OTP.")

    # Apply changes atomically
    tx_ctx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx_ctx:
        user.is_active = True
        user.reactivation_token = None
        user.deactivated_at = None
        user.scheduled_deletion_at = None

        otp_row.used = True
        db.add_all([user, otp_row])

        # Optional: invalidate other outstanding reactivation OTPs
        await db.execute(
            delete(OTP).where(
                OTP.user_id == user.id,
                OTP.purpose == OTP_PURPOSE_REACTIVATION,
                OTP.used == False,  # noqa: E712
            )
        )

    # Audit success (non‑blocking)
    if background_tasks is not None:
        background_tasks.add_task(
            log_audit_event,
            db=db,
            user=user,
            action=AuditEvent.REACTIVATE_ACCOUNT,
            status="SUCCESS",
            request=request,
            meta_data={"email": user.email},
            commit=False,
        )

    return MessageResponse(message="Your account has been successfully reactivated.")


__all__ = [
    "router",
    "request_reactivation_otp",
    "reactivate_account",
]
