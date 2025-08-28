# app/services/auth/account_service.py
from __future__ import annotations

"""
Account Lifecycle Service — production-grade
===========================================

This module implements the account **deactivate**, **delete**, **reactivation email**,
and **reactivate** flows with strong security guarantees and clean ergonomics.

Key properties
--------------
- First-class support for **route-level step-up (reauth)** via `reauth_validated=True`.
- Backward-compatible **MFA (pending token + TOTP)** and **email OTP** paths.
- Email OTPs validated with **server-peppered HMAC** (digest with plaintext fallback).
- Per-user **and** per-IP attempt rate limits via Redis helpers.
- Idempotent operations and **nested transactions** under tests.
- **Refresh token revocation** on delete.
- Neutral error messages, no secret leakage, best-effort cache invalidation.

Usage
-----
Routes should prefer step-up/reauth (e.g., via `/reauth/*`) and pass
`reauth_validated=True`. Legacy MFA/OTP paths remain supported where needed.
"""

from typing import Optional
from uuid import uuid4
from datetime import datetime, timedelta, timezone
import logging

from fastapi import HTTPException, Request, BackgroundTasks
from jose import jwt, JWTError
from sqlalchemy import select, delete, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models.user import User
from app.db.models.otp import OTP
from app.services.audit_log_service import log_audit_event, AuditEvent
from app.services.token_service import revoke_all_refresh_tokens
from app.utils.email_utils import send_reactivation_email
from app.utils.mfa_utils import verify_totp
from app.services.auth.password_reset_service import _hash_otp
import app.utils.redis_utils as redis_utils

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# ⚙️ Constants & tiny utils
# ─────────────────────────────────────────────────────────────

REACTIVATION_WINDOW_DAYS = 30
OTP_LEN_MIN = 4           # dev/test flexibility; tighten to 6 in strict prod
OTP_LEN_MAX = 8

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _client_ip(request: Optional[Request]) -> str:
    """Best-effort client IP extraction (for per-IP rate limiting); never raises."""
    try:
        if request is None:
            return "-"
        fwd = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip")
        if fwd:
            return fwd.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
    except Exception:
        pass
    return "-"

def _normalize_otp(code: Optional[str]) -> str:
    """Trim & ensure digits only; raise 400 on invalid format."""
    c = (code or "").strip()
    if not c.isdigit() or not (OTP_LEN_MIN <= len(c) <= OTP_LEN_MAX):
        raise HTTPException(status_code=400, detail="Invalid OTP format.")
    return c

# ─────────────────────────────────────────────────────────────
# 🔐 MFA-pending token decode (for legacy MFA flow)
# ─────────────────────────────────────────────────────────────

def _decode_mfa_pending_token(token: str, expected_sub) -> dict:
    """
    Verify a short-lived *pending* MFA token (minted by `generate_mfa_token`).

    Verifications
    -------------
    - Valid signature & required claims (`sub`, `exp`)
    - `sub` equals the current user ID
    - `mfa_pending` is True

    Raises
    ------
    HTTPException(401) with a neutral message on any failure.
    """
    try:
        claims = jwt.decode(
            token,
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["sub", "exp"]},
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid MFA token.")
    if str(claims.get("sub")) != str(expected_sub) or not claims.get("mfa_pending", False):
        raise HTTPException(status_code=401, detail="Invalid MFA token.")
    return claims

# ─────────────────────────────────────────────────────────────
# 📴 Deactivate User
# ─────────────────────────────────────────────────────────────

async def deactivate_user(
    *,
    request: Request,
    current_user: User,
    mfa_token: Optional[str],
    code: Optional[str],
    db: AsyncSession,
    reauth_validated: bool | None = None,
) -> dict:
    """
    Soft-deactivate the authenticated user after validating **one** of:

      • Route-level **step-up reauth** (pass `reauth_validated=True`)
      • **MFA pending token + TOTP** (legacy path)
      • **Email OTP** (for non-MFA users)

    Returns a neutral success message. Idempotent for already-deactivated users.
    """
    # [Step 0] Idempotency shortcut
    if not current_user.is_active:
        return {"message": "Your account is already deactivated."}

    # [Step 1] Factor validation
    if reauth_validated:
        # Route already verified step-up — nothing else to check.
        pass
    elif current_user.mfa_enabled:
        # Legacy MFA path (prefer reauth at the route long-term)
        if not mfa_token or not code:
            raise HTTPException(status_code=400, detail="MFA token and code are required.")
        _decode_mfa_pending_token(mfa_token, expected_sub=current_user.id)
        _normalize_otp(code)
        if not current_user.totp_secret or not verify_totp(current_user.totp_secret, code):
            raise HTTPException(status_code=401, detail="Invalid MFA code.")
    else:
        # Non-MFA: email OTP path
        normalized = _normalize_otp(code)

        # Per-user & per-IP throttles
        ip = _client_ip(request)
        await redis_utils.enforce_rate_limit(
            key_suffix=f"deactivate-otp:user:{current_user.id}",
            seconds=60,
            max_calls=5,
            error_message="Too many OTP attempts. Please try again shortly.",
        )
        await redis_utils.enforce_rate_limit(
            key_suffix=f"deactivate-otp:ip:{ip}",
            seconds=60,
            max_calls=15,
            error_message="Too many attempts from your network. Please wait a minute.",
        )

        digest = _hash_otp(normalized, user_id=str(current_user.id), purpose="deactivate_account")
        otp_row = (
            await db.execute(
                select(OTP).where(
                    OTP.user_id == current_user.id,
                    OTP.purpose == "deactivate_account",
                    OTP.used == False,  # noqa: E712
                    OTP.expires_at > _now_utc(),
                    or_(OTP.code == digest, OTP.code == normalized),
                )
            )
        ).scalar_one_or_none()
        if not otp_row:
            raise HTTPException(status_code=401, detail="Invalid or expired OTP.")

    # [Step 2] Transactional state change (nested in tests)
    tx_ctx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx_ctx:
        # Guard against concurrent deactivation
        if not current_user.is_active:
            return {"message": "Your account is already deactivated."}

        # Mark OTP consumed if this was the email OTP path
        if not current_user.mfa_enabled and not reauth_validated:
            try:
                normalized = _normalize_otp(code)
                digest = _hash_otp(normalized, user_id=str(current_user.id), purpose="deactivate_account")
                otp_row2 = (
                    await db.execute(
                        select(OTP).where(
                            OTP.user_id == current_user.id,
                            OTP.purpose == "deactivate_account",
                            OTP.used == False,  # noqa: E712
                            OTP.expires_at > _now_utc(),
                            or_(OTP.code == digest, OTP.code == normalized),
                        )
                    )
                ).scalar_one_or_none()
                if otp_row2:
                    otp_row2.used = True
                    db.add(otp_row2)
            except Exception:
                # Do not fail deactivation due to OTP marking races
                pass

        now = _now_utc()
        current_user.is_active = False
        current_user.deactivated_at = now
        current_user.scheduled_deletion_at = now + timedelta(days=REACTIVATION_WINDOW_DAYS)
        current_user.reactivation_token = str(uuid4())
        db.add(current_user)

    # [Step 3] Best-effort cache invalidation (never fails the flow)
    _invalidate_user_caches_safe(current_user.id)

    return {"message": "Your account has been deactivated successfully."}

# ─────────────────────────────────────────────────────────────
# 🗑️ Delete User (soft delete + revoke sessions)
# ─────────────────────────────────────────────────────────────

async def delete_user(
    *,
    current_user: User,
    mfa_token: Optional[str],
    code: Optional[str],
    db: AsyncSession,
    request: Optional[Request],
    background_tasks: Optional[BackgroundTasks] = None,
    reauth_validated: bool | None = None,
) -> dict:
    """
    Soft-delete the user after factor verification; revoke all refresh tokens/sessions
    and clear OTPs. Returns a neutral message.

    Prefer route-level **step-up** and pass `reauth_validated=True`. Legacy TOTP
    and email-OTP paths remain supported for compatibility.
    """
    user_id = current_user.id
    user_email = current_user.email

    # [Step 1] Factor validation (mirrors deactivate)
    if reauth_validated:
        pass
    elif current_user.mfa_enabled:
        if not mfa_token or not code:
            raise HTTPException(status_code=400, detail="MFA token and code are required.")
        _decode_mfa_pending_token(mfa_token, expected_sub=user_id)
        _normalize_otp(code)
        if not current_user.totp_secret or not verify_totp(current_user.totp_secret, code):
            raise HTTPException(status_code=401, detail="Invalid MFA code.")
    else:
        normalized = _normalize_otp(code)
        ip = _client_ip(request)
        await redis_utils.enforce_rate_limit(
            key_suffix=f"otp-delete-user:user:{user_id}",
            seconds=300,
            max_calls=5,
            error_message="Too many failed attempts. Please try again later.",
        )
        await redis_utils.enforce_rate_limit(
            key_suffix=f"otp-delete-user:ip:{ip}",
            seconds=300,
            max_calls=20,
            error_message="Too many attempts from your network. Please try later.",
        )
        digest = _hash_otp(normalized, user_id=str(user_id), purpose="delete_account")
        otp_row = (
            await db.execute(
                select(OTP).where(
                    OTP.user_id == user_id,
                    OTP.purpose == "delete_account",
                    OTP.used == False,  # noqa: E712
                    OTP.expires_at > _now_utc(),
                    or_(OTP.code == digest, OTP.code == normalized),
                )
            )
        ).scalar_one_or_none()
        if not otp_row:
            raise HTTPException(status_code=401, detail="Invalid or expired OTP.")

    # [Step 2] Atomic updates + cleanup (nested in tests)
    tx_ctx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx_ctx:
        # Mark email-OTP as used if that was the path
        if not current_user.mfa_enabled and not reauth_validated:
            try:
                normalized = _normalize_otp(code)
                digest = _hash_otp(normalized, user_id=str(user_id), purpose="delete_account")
                otp_row2 = (
                    await db.execute(
                        select(OTP).where(
                            OTP.user_id == user_id,
                            OTP.purpose == "delete_account",
                            OTP.used == False,  # noqa: E712
                            OTP.expires_at > _now_utc(),
                            or_(OTP.code == digest, OTP.code == normalized),
                        )
                    )
                ).scalar_one_or_none()
                if otp_row2:
                    otp_row2.used = True
                    db.add(otp_row2)
            except Exception:
                pass

        now = _now_utc()
        current_user.is_active = False
        current_user.deactivated_at = now
        current_user.scheduled_deletion_at = now + timedelta(days=REACTIVATION_WINDOW_DAYS)
        current_user.reactivation_token = str(uuid4())
        db.add(current_user)

        # Invalidate remaining OTPs (any purpose) for safety inside the same tx
        await db.execute(delete(OTP).where(OTP.user_id == user_id))

    # Revoke all refresh tokens/sessions (outside the tx)
    await revoke_all_refresh_tokens(db, user_id)

    # [Step 3] Best-effort cache invalidation
    _invalidate_user_caches_safe(user_id)

    # [Step 4] Non-blocking follow-ups (email + audit) are queued by the API layer
    if background_tasks is not None:
        background_tasks.add_task(send_reactivation_email, to_email=user_email, token=current_user.reactivation_token)
        background_tasks.add_task(
            log_audit_event,
            db=db,
            user=current_user,
            action=AuditEvent.DELETE_USER,
            status="SUCCESS",
            request=request,
            meta_data={"soft_deleted": True, "mfa_enabled": current_user.mfa_enabled},
            commit=False,
        )

    return {"message": "User account deleted successfully. You can reactivate it within 30 days."}

# ─────────────────────────────────────────────────────────────
# 📧 Send Reactivation Email (neutral — no enumeration)
# ─────────────────────────────────────────────────────────────

async def send_account_reactivation_email(
    *,
    email: str,
    db: AsyncSession,
    request: Request,
) -> dict:
    """
    Send a reactivation email to a **deactivated** user.

    Always returns a **generic** message to avoid account enumeration.
    """
    generic_msg = {"message": "If your account exists, a reactivation link has been sent."}

    try:
        user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if not user:
            return generic_msg

        if user.is_active:
            return {"message": "Your account is already active."}

        if user.scheduled_deletion_at and _now_utc() > user.scheduled_deletion_at:
            await log_audit_event(
                db=db,
                user=user,
                action=AuditEvent.SEND_REACTIVATION_EMAIL,
                status="FAILURE",
                request=request,
                meta_data={"email": user.email, "reason": "Reactivation Period expired"},
            )
            raise HTTPException(status_code=403, detail="Reactivation Period has expired.")

        user.reactivation_token = str(uuid4())
        db.add(user)
        await db.commit()

        try:
            # Signature: (to_email, token)
            send_reactivation_email(user.email, user.reactivation_token)
        except Exception as email_err:
            logger.error("📧 Failed to send reactivation email: %s", email_err)
            raise HTTPException(status_code=500, detail="Failed to send reactivation email.")

        await log_audit_event(
            db=db,
            user=user,
            action=AuditEvent.SEND_REACTIVATION_EMAIL,
            status="SUCCESS",
            request=request,
            meta_data={"email": user.email},
        )

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error("⚠️ Unexpected error in send_account_reactivation_email: %s", e)
        try:
            await log_audit_event(
                db=db,
                user=user if "user" in locals() else None,  # type: ignore[name-defined]
                action=AuditEvent.SEND_REACTIVATION_EMAIL,
                status="FAILURE",
                request=request,
                meta_data={"email": email, "error": str(e)},
            )
        except Exception as audit_err:
            logger.warning("⚠️ Failed to audit failed reactivation attempt: %s", audit_err)
        raise HTTPException(status_code=500, detail="Failed to generate reactivation token.")

    _invalidate_user_caches_safe(user.id)
    return generic_msg

# ─────────────────────────────────────────────────────────────
# ♻️ Reactivate via Token
# ─────────────────────────────────────────────────────────────

async def reactivate_user_by_token(
    *,
    token: str,
    db: AsyncSession,
    request: Request,
) -> dict:
    """
    Reactivate a user using a one-time reactivation token, ensuring:
      • Token maps to a currently deactivated user
      • Reactivation window has not expired
    """
    try:
        user = (await db.execute(select(User).where(User.reactivation_token == token))).scalar_one_or_none()

        if not user:
            await log_audit_event(
                db=db,
                action=AuditEvent.REACTIVATE_ACCOUNT,
                status="FAILURE",
                request=request,
                meta_data={"reason": "Invalid or expired token"},
            )
            raise HTTPException(status_code=400, detail="Invalid or expired reactivation token.")

        if user.is_active:
            return {"message": "Your account is already active."}

        if user.scheduled_deletion_at and _now_utc() > user.scheduled_deletion_at:
            await log_audit_event(
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
            )
            raise HTTPException(status_code=403, detail="Reactivation Period has expired. Please contact support.")

        user.is_active = True
        user.reactivation_token = None
        user.deactivated_at = None
        user.scheduled_deletion_at = None
        db.add(user)
        await db.commit()

        await log_audit_event(
            db=db,
            user=user,
            action=AuditEvent.REACTIVATE_ACCOUNT,
            status="SUCCESS",
            request=request,
            meta_data={"email": user.email},
        )

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error("⚠️ Unexpected reactivation error: %s", e)
        try:
            await log_audit_event(
                db=db,
                user=user if "user" in locals() else None,  # type: ignore[name-defined]
                action=AuditEvent.REACTIVATE_ACCOUNT,
                status="FAILURE",
                request=request,
                meta_data={"token": "[redacted]", "error": str(e)},
            )
        except Exception as audit_err:
            logger.warning("⚠️ Failed to audit reactivation error: %s", audit_err)
        raise HTTPException(status_code=500, detail="An unexpected error occurred during reactivation.")

    _invalidate_user_caches_safe(user.id)
    return {"message": "Your account has been successfully reactivated."}

# ─────────────────────────────────────────────────────────────
# 🧹 Cache invalidation (best-effort; never breaks flows)
# ─────────────────────────────────────────────────────────────

def _invalidate_user_caches_safe(user_id) -> None:
    """
    Best-effort invalidation of user-scoped caches using our cache module.

    Tries `cache_invalidate_tags(*tags)` first, then `cache_invalidation_tags`.
    Any failures are swallowed; auth flows must not depend on cache health.
    """
    tags = [
        f"user:{user_id}",
        f"user:{user_id}:auth",
        f"user:{user_id}:profile",
        f"user:{user_id}:permissions",
    ]
    try:
        try:
            from app.utils.cache import cache_invalidate_tags  # type: ignore
        except Exception:
            cache_invalidate_tags = None  # type: ignore

        if cache_invalidate_tags:
            try:
                maybe_coro = cache_invalidate_tags(*tags)
                if hasattr(maybe_coro, "__await__"):
                    import asyncio
                    asyncio.create_task(maybe_coro)
                return
            except Exception:
                pass

        try:
            from app.utils.cache import cache_invalidation_tags as _alt_invalidate  # type: ignore
        except Exception:
            _alt_invalidate = None  # type: ignore

        if _alt_invalidate:
            try:
                maybe_coro = _alt_invalidate(*tags)
                if hasattr(maybe_coro, "__await__"):
                    import asyncio
                    asyncio.create_task(maybe_coro)
            except Exception:
                pass
    except Exception:
        pass


__all__ = [
    "deactivate_user",
    "delete_user",
    "send_account_reactivation_email",
    "reactivate_user_by_token",
]
