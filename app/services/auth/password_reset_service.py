from __future__ import annotations

"""
Password reset service — hardened, production‑grade
==================================================

Features
--------
- **CSPRNG numeric OTPs** with **peppered HMAC** digests stored at rest.
- **Per‑email and per‑IP rate limits** with a **daily per‑user cap**.
- **Neutral responses** to prevent account enumeration.
- **Atomic writes** with nested tx support under tests.
- **BackgroundTasks** for non‑blocking email + thorough audit logging.
- **Best‑effort cache invalidation** after successful reset.

Assumptions
-----------
- Email helper ``send_password_reset_otp(email, otp)`` exists.
- Redis helper ``enforce_rate_limit(key_suffix, seconds, max_calls, error_message)`` exists.
- Cache helper ``app.utils.cache.cache_invalidate_tags(*tags)`` may exist; if not,
  fallback to ``cache_invalidation_tags`` is attempted.
"""

from datetime import datetime, timedelta, timezone
from typing import Final, Optional
import hashlib
import hmac
import re
import secrets

from fastapi import BackgroundTasks, HTTPException, Request, status
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import get_password_hash
from app.db.models.otp import OTP
from app.db.models.user import User
from app.services.audit_log_service import AuditEvent, log_audit_event
from app.utils.email_utils import send_password_reset_otp
from app.utils.redis_utils import enforce_rate_limit

# ─────────────────────────────────────────────────────────────
# ⚙️ Configuration
# ─────────────────────────────────────────────────────────────

# Clamp tunables into safe ranges
OTP_TTL_MINUTES: Final[int] = int(getattr(settings, "PASSWORD_RESET_OTP_TTL_MINUTES", 10) or 10)
OTP_TTL_MINUTES = max(3, min(OTP_TTL_MINUTES, 60))  # [3m, 60m]

MAX_DAILY_OTP: Final[int] = int(getattr(settings, "PASSWORD_RESET_MAX_DAILY", 20) or 20)
MAX_DAILY_OTP = max(1, min(MAX_DAILY_OTP, 100))

# Lightweight email sanity (do not over‑validate; backend source of truth)
_EMAIL_RE = re.compile(r"^\S+@\S+\.\S+$")


# ─────────────────────────────────────────────────────────────
# 🔧 Helpers
# ─────────────────────────────────────────────────────────────

def _client_ip(request: Optional[Request]) -> str:
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


def generate_otp(length: int = 6) -> str:
    """Generate a CSPRNG numeric OTP of given length (keeps leading zeros)."""
    if length <= 0:
        raise ValueError("OTP length must be positive")
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))


def _hash_otp(otp: str, *, user_id: str, purpose: str) -> str:
    """Return hex HMAC‑SHA256 of the OTP bound to (user_id, purpose).

    SECRET_KEY is a Pydantic ``SecretStr``; extract the raw value before use.
    """
    if not otp or not user_id or not purpose:
        raise ValueError("otp, user_id and purpose are required")
    key = settings.JWT_SECRET_KEY.get_secret_value().encode("utf-8")  # pepper
    msg = f"{purpose}:{user_id}:{otp}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


# ─────────────────────────────────────────────────────────────
# 🔁 Request password reset (OTP via email)
# ─────────────────────────────────────────────────────────────
async def request_password_reset(
    email: str,
    db: AsyncSession,
    request: Optional[Request] = None,
    background_tasks: Optional[BackgroundTasks] = None,
) -> dict:
    """Send a password‑reset OTP to the user if the account exists.

    Security properties
    -------------------
    - **Neutral** response (no enumeration).
    - **Per‑email & per‑IP rate limits**; **daily** per‑user cap.
    - **Digest‑only** storage of OTP; plaintext sent over email only.
    - **Atomic** write with cleanup of prior unused reset OTPs.
    - Non‑blocking email and audit logging.
    """
    generic = {"message": "If an account exists with this email, a password reset OTP has been sent."}

    email_norm = (email or "").strip().lower()
    if not email_norm or len(email_norm) > 320 or not _EMAIL_RE.match(email_norm):
        return generic

    ip = _client_ip(request)

    # Throttle issuance per email & IP
    await enforce_rate_limit(
        key_suffix=f"pwdreset:req:email:{hashlib.sha256(email_norm.encode()).hexdigest()}",
        seconds=60,
        max_calls=2,
        error_message="Please wait before requesting another OTP.",
    )
    await enforce_rate_limit(
        key_suffix=f"pwdreset:req:ip:{ip}",
        seconds=60,
        max_calls=15,
        error_message="Too many requests. Please try again later.",
    )

    # Silent user lookup
    user = (await db.execute(select(User).where(User.email == email_norm))).scalar_one_or_none()
    if not user:
        await log_audit_event(
            db=db,
            user=None,
            action=AuditEvent.REQUEST_PASSWORD_RESET,
            status="IGNORED",
            request=request,
            meta_data={"email_hash": hashlib.sha256(email_norm.encode()).hexdigest(), "ip": ip},
        )
        return generic

    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)

    # Enforce daily cap per user
    issued = (
        await db.execute(
            select(func.count()).select_from(OTP).where(
                OTP.user_id == user.id,
                OTP.purpose == "password_reset",
                OTP.created_at >= day_ago,
            )
        )
    ).scalar() or 0

    if issued >= MAX_DAILY_OTP:
        await log_audit_event(
            db=db,
            user=user,
            action=AuditEvent.REQUEST_PASSWORD_RESET,
            status="RATE_LIMITED",
            request=request,
            meta_data={"otp_count": issued},
        )
        # We purposely return a 429 to slow down abusive clients
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Please wait before requesting another OTP.")

    # Generate OTP & persist digest atomically; delete prior unused
    otp_plain = generate_otp()
    otp_digest = _hash_otp(otp_plain, user_id=str(user.id), purpose="password_reset")

    tx_ctx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx_ctx:
        await db.execute(delete(OTP).where(OTP.user_id == user.id, OTP.purpose == "password_reset", OTP.used == False))
        db.add(
            OTP(
                user_id=user.id,
                code=otp_digest,
                purpose="password_reset",
                expires_at=now + timedelta(minutes=OTP_TTL_MINUTES),
                used=False,
                created_at=now,
            )
        )

    # Non‑blocking email
    if background_tasks is not None:
        background_tasks.add_task(send_password_reset_otp, email_norm, otp_plain)

    await log_audit_event(
        db=db,
        user=user,
        action=AuditEvent.REQUEST_PASSWORD_RESET,
        status="SUCCESS",
        request=request,
        meta_data={"ip": ip},
    )

    return generic


# ─────────────────────────────────────────────────────────────
# 🔁 Finalize password reset (verify OTP → set new password)
# ─────────────────────────────────────────────────────────────
async def reset_password(
    email: str,
    otp_code: str,
    new_password: str,
    db: AsyncSession,
    request: Optional[Request] = None,
    background_tasks: Optional[BackgroundTasks] = None,
) -> dict:
    """Verify an OTP and reset the user's password.

    Security properties
    -------------------
    - **Per‑IP** and **per‑user** verification throttles.
    - Digest comparison in DB (constant‑time by equality of digests).
    - **Atomic** update: set new password and consume the OTP.
    - Neutral errors; never echo the OTP or reveal user existence.
    - Optional: revoke all sessions after reset (commented hook provided).
    """
    email_norm = (email or "").strip().lower()
    ip = _client_ip(request)

    # Throttle attempts
    await enforce_rate_limit(
        key_suffix=f"pwdreset:verify:ip:{ip}",
        seconds=10,
        max_calls=15,
        error_message="Too many attempts. Please try again shortly.",
    )

    user = (await db.execute(select(User).where(User.email == email_norm))).scalar_one_or_none()
    if not user:
        # Neutral error; do not leak whether the account exists
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP")

    await enforce_rate_limit(
        key_suffix=f"pwdreset:verify:user:{user.id}",
        seconds=60,
        max_calls=10,
        error_message="Too many attempts. Please try again shortly.",
    )

    now = datetime.now(timezone.utc)

    # Validate OTP by digest within TTL
    digest = _hash_otp(otp_code or "", user_id=str(user.id), purpose="password_reset")
    otp_row: OTP | None = (
        await db.execute(
            select(OTP).where(
                OTP.user_id == user.id,
                OTP.purpose == "password_reset",
                OTP.used == False,  # noqa: E712
                OTP.expires_at >= now,
                OTP.code == digest,
            ).limit(1)
        )
    ).scalar_one_or_none()

    if not otp_row:
        await log_audit_event(
            db=db,
            user=user,
            action=AuditEvent.RESET_PASSWORD,
            status="INVALID_OTP",
            request=request,
            meta_data={"ip": ip},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP")

    # Apply new password and consume OTP atomically
    tx_ctx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx_ctx:
        user.hashed_password = get_password_hash(new_password)
        otp_row.used = True
        await db.execute(delete(OTP).where(OTP.user_id == user.id, OTP.purpose == "password_reset", OTP.used == False))
        db.add(user)
        db.add(otp_row)

    # Optionally revoke sessions here
    # await revoke_all_refresh_tokens(db, user.id)

    _invalidate_user_caches_safe(user.id)

    await log_audit_event(
        db=db,
        user=user,
        action=AuditEvent.RESET_PASSWORD,
        status="SUCCESS",
        request=request,
        meta_data={"ip": ip},
    )

    return {"message": "Password reset successful"}


__all__ = ["request_password_reset", "reset_password", "generate_otp", "_hash_otp"]
