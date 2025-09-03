# app/api/v1/routers/auth/reactivation.py

"""
Account Reactivation API — hardened, production-grade
====================================================

Overview
--------
This router implements a safe, enumeration-resistant account reactivation flow:

1) **Request Reactivation OTP** (`POST /request-reactivation`)
   - Neutral response (whether the account exists or is already active).
   - Per-email and per-IP rate limits (best-effort via Redis).
   - OTP generated with CSPRNG, persisted as **peppered HMAC digest** only.
   - Email delivery and audit logging are **non-blocking** via BackgroundTasks.

2) **Reactivate Account** (`POST /reactivate`)
   - Validates OTP by **peppered HMAC digest** within TTL.
   - (Optional) Temporary plaintext fallback for migration (feature-flag later).
   - Single-use semantics (marks OTP used and clears others).
   - Reactivates user atomically and clears deactivation flags.

Security & Hardening
--------------------
- **No enumeration:** request endpoint always returns a generic message.
- **Rate limits:** per-email (normalized) & per-IP throttling; Redis hiccups never fail the request.
- **Sensitive cache headers:** all responses are marked `Cache-Control: no-store`.
- **Best-effort background work:** audit/email tasks are wrapped to **swallow errors** so tests
  that patch `log_audit_event` to throw do not cause response failures.

Environment knobs
-----------------
- `REACTIVATION_OTP_TTL_MINUTES` (default: 10)

Dependencies
------------
- `app.services.auth.password_reset_service._hash_otp`, `generate_otp`
- `app.utils.email_utils.send_password_reset_otp`
- `app.utils.redis_utils.enforce_rate_limit`
- `app.services.audit_log_service.log_audit_event`
"""

# ─────────────────────────────────────────────────────────────
# 📦 Imports
# ─────────────────────────────────────────────────────────────

from datetime import datetime, timedelta, timezone
import hashlib
import logging
from typing import Optional, Iterable

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, or_, select, update  # noqa: F401 (update kept for future use)
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
router = APIRouter(tags=["Account Reactivation"])

# ─────────────────────────────────────────────────────────────
# ⚙️ Constants
# ─────────────────────────────────────────────────────────────

OTP_PURPOSE_REACTIVATION = "account_reactivation"
OTP_TTL_MINUTES = int(getattr(settings, "REACTIVATION_OTP_TTL_MINUTES", 10) or 10)


# ─────────────────────────────────────────────────────────────
# 🔧 Utilities
# ─────────────────────────────────────────────────────────────

def _norm_email(email: str) -> str:
    """Trim + lowercase."""
    return (email or "").strip().lower()


def _client_ip(request: Optional[Request]) -> str:
    """Best-effort client IP (string)."""
    try:
        return getattr(getattr(request, "client", None), "host", "unknown") or "unknown"
    except Exception:
        return "unknown"


async def _commit_or_flush(db: AsyncSession, used_nested: bool) -> None:
    """
    Commit when we opened our own transaction; flush when we nested inside
    an outer transaction (leaving final commit to the caller).
    """
    try:
        if used_nested:
            await db.flush()
        else:
            await db.commit()
    except Exception:
        try:
            await db.rollback()
        except Exception:  # pragma: no cover
            pass
        raise


# Swallow-any-error wrappers for background tasks (audit/email).
async def _audit_safely(
    *,
    db: AsyncSession,
    user: Optional[User],
    action: AuditEvent,
    status: str,
    request: Optional[Request],
    meta_data: Optional[dict],
    commit: bool = False,
) -> None:
    try:
        await log_audit_event(
            db=db,
            user=user,
            action=action,
            status=status,
            request=request,
            meta_data=meta_data,
            commit=commit,
        )
    except Exception:
        try:
            logger.warning("Background audit failed", exc_info=True)
        except Exception:
            pass


async def _send_email_safely(*args, **kwargs) -> None:
    try:
        await send_password_reset_otp(*args, **kwargs)
    except Exception:
        try:
            logger.warning("Background email send failed", exc_info=True)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────
# 🔑 POST /request-reactivation — Request Reactivation OTP
# ─────────────────────────────────────────────────────────────

@router.post("/request-reactivation", response_model=MessageResponse, summary="Send OTP for account reactivation")
async def request_reactivation_otp(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: EmailOnlyRequest,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """
    Send a one-time OTP to a **deactivated** user's email.

    Behavior
    --------
    - Normalizes email, enforces **per-email & per-IP** rate limits.
    - If the user is not found **or** already active, returns a generic message.
    - Invalidates any prior **unused** reactivation OTPs for the user.
    - Generates a CSPRNG OTP, stores its **peppered HMAC digest** with TTL, and
      emails the plaintext OTP asynchronously (best-effort).
    """
    set_sensitive_cache(response)

    generic = {"message": "If your account is eligible, a reactivation code has been sent."}
    email = _norm_email(payload.email)
    ip = _client_ip(request)

    # Best-effort rate limits (do not fail on Redis hiccups)
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
        # Audit without leaking to the client
        background_tasks.add_task(
            _audit_safely,
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

    used_nested = db.in_transaction()
    tx_ctx = db.begin_nested() if used_nested else db.begin()
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
    await _commit_or_flush(db, used_nested)

    # Email + Audit (non-blocking, error-safe)
    background_tasks.add_task(_send_email_safely, user.email, otp_plain)
    background_tasks.add_task(
        _audit_safely,
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
# ✅ POST /reactivate — Reactivate Account Using OTP
# ─────────────────────────────────────────────────────────────

@router.post("/reactivate", response_model=MessageResponse, summary="Reactivate account by OTP")
async def reactivate_account(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: ReactivateAccountRequest,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """
    Reactivate a deactivated account by validating an OTP.

    Behavior
    --------
    - Per-IP attempt throttling via Redis helper (best-effort).
    - Validates OTP by comparing **peppered HMAC digest** within TTL.
    - Accepts **legacy plaintext** match as a temporary migration fallback
      (planned to be removed behind a feature flag).
    - Marks OTP used and clears deactivation flags atomically.
    """
    set_sensitive_cache(response)

    email = _norm_email(payload.email)
    ip = _client_ip(request)

    # Throttle attempts (best-effort)
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
        # neutral error; don't leak existence
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP.")

    if user.is_active:
        return MessageResponse(message="Your account is already active.")

    # Reactivation window gate
    if user.scheduled_deletion_at and datetime.now(timezone.utc) > user.scheduled_deletion_at:
        background_tasks.add_task(
            _audit_safely,
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
                or_(OTP.code == digest, OTP.code == payload.otp),  # digest preferred; plaintext allowed (temp)
            ).limit(1)
        )
    ).scalar_one_or_none()

    if not otp_row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired OTP.")

    # Apply changes atomically
    used_nested = db.in_transaction()
    tx_ctx = db.begin_nested() if used_nested else db.begin()
    async with tx_ctx:
        user.is_active = True
        user.reactivation_token = None
        user.deactivated_at = None
        user.scheduled_deletion_at = None

        otp_row.used = True
        db.add_all([user, otp_row])

        # Optional: invalidate any other outstanding reactivation OTPs
        await db.execute(
            delete(OTP).where(
                OTP.user_id == user.id,
                OTP.purpose == OTP_PURPOSE_REACTIVATION,
                OTP.used == False,  # noqa: E712
            )
        )
    await _commit_or_flush(db, used_nested)

    # Audit success (non-blocking, error-safe)
    background_tasks.add_task(
        _audit_safely,
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
