from __future__ import annotations

"""
Reactivation by OTP — hardened, production-grade service
=======================================================

What this service does
----------------------
- **Neutral** reactivation request flow (no account enumeration).
- CSPRNG OTPs with **peppered HMAC** digests stored at rest (no plaintext).
- **Per-email** and **per-IP** throttles via Redis (atomic Lua under the hood).
- Single-use, **TTL-bound** OTPs; cleanup of stale/unused codes.
- Atomic reactivation (clears deactivation flags in one tx).
- Thorough audit logging; best-effort cache invalidation.
- Emits an `ACCOUNT_REACTIVATED` event into the Redis activity ring buffer.

Environment knobs
-----------------
- ``REACTIVATION_OTP_TTL_MINUTES`` (default 10; clamped to [3, 60])
- ``ACTIVITY_RING_MAX`` (size of `audit:recent:{user_id}` ring buffer)

Dependencies
------------
- `generate_otp`, `_hash_otp` from `app.services.auth.password_reset_service`
- `enforce_rate_limit` from `app.utils.redis_utils`
- `send_password_reset_otp` as a generic email OTP sender
- `log_audit_event` + `AuditEvent` for auditing
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
import hashlib
import json
from uuid import uuid4

from fastapi import BackgroundTasks, HTTPException, Request, status
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.redis_client import redis_wrapper
from app.db.models.otp import OTP
from app.db.models.user import User
from app.services.audit_log_service import AuditEvent, log_audit_event
from app.utils.email_utils import send_password_reset_otp
from app.utils.redis_utils import enforce_rate_limit
from app.services.auth.password_reset_service import generate_otp, _hash_otp

# ─────────────────────────────────────────────────────────────
# ⚙️ Configuration
# ─────────────────────────────────────────────────────────────
OTP_PURPOSE = "account_reactivation"
OTP_TTL_MINUTES = int(getattr(settings, "REACTIVATION_OTP_TTL_MINUTES", 10) or 10)
OTP_TTL_MINUTES = max(3, min(OTP_TTL_MINUTES, 60))  # clamp to [3m, 60m]
ACTIVITY_RING_MAX = int(getattr(settings, "ACTIVITY_RING_MAX", 200) or 200)


# ─────────────────────────────────────────────────────────────
# 🔧 Helpers
# ─────────────────────────────────────────────────────────────
def _client_ip(request: Optional[Request]) -> str:
    """Best-effort client IP (X-Forwarded-For aware)."""
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
    """Best-effort invalidation of user-scoped caches; never raises."""
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
            maybe_coro = cache_invalidate_tags(*tags)
            if hasattr(maybe_coro, "__await__"):
                import asyncio
                asyncio.create_task(maybe_coro)  # fire-and-forget
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
        # Never let cache issues impact auth flows
        pass


async def _push_activity_event(user_id, action: str, status_str: str, request: Optional[Request], meta: Optional[dict] = None) -> None:
    """Best-effort activity ring push (never raises)."""
    try:
        evt = {
            "id": str(uuid4()),
            "at": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "status": status_str,
            "ip": _client_ip(request),
            "user_agent": request.headers.get("User-Agent") if request else None,
            "meta": meta or {},
        }
        key = f"audit:recent:{user_id}"
        r = redis_wrapper.client
        await r.rpush(key, json.dumps(evt))
        await r.ltrim(key, -ACTIVITY_RING_MAX, -1)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────
# 🔑 Request reactivation OTP (neutral)
# ─────────────────────────────────────────────────────────────
async def request_reactivation_otp(
    email: str,
    db: AsyncSession,
    request: Optional[Request],
    background_tasks: Optional[BackgroundTasks],
) -> dict:
    """Send a one-time OTP to a **deactivated** account (neutral response).

    Security properties
    -------------------
    - **Neutral** response (no enumeration): generic body for missing/active users.
    - **Per-email & per-IP** throttles via Redis (atomic Lua).
    - **Digest-only** storage of OTP (peppered HMAC) with TTL; plaintext is emailed.
    - **Atomic** write with cleanup of prior unused reactivation OTPs.
    - Non-blocking email and audit logging.
    """
    # ── [Step 0] Normalize inputs ────────────────────────────────────────────
    generic = {"message": "If your account is eligible, a reactivation code has been sent."}
    email_norm = (email or "").strip().lower()
    if not email_norm or len(email_norm) > 320:
        return generic

    ip = _client_ip(request)

    # ── [Step 1] Throttle per email & IP ─────────────────────────────────────
    await enforce_rate_limit(
        key_suffix=f"reactivate:req:email:{hashlib.sha256(email_norm.encode()).hexdigest()}",
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

    # ── [Step 2] Silent user lookup (no enumeration) ─────────────────────────
    user = (await db.execute(select(User).where(User.email == email_norm))).scalar_one_or_none()
    if not user or user.is_active:
        # Audit but return neutral response
        await log_audit_event(
            db=db,
            user=user if user else None,
            action=AuditEvent.REQUEST_REACTIVATION_OTP,
            status="IGNORED" if not user else "ALREADY_ACTIVE",
            request=request,
            meta_data={"email_hash": hashlib.sha256(email_norm.encode()).hexdigest(), "ip": ip},
        )
        return generic

    # ── [Step 3] Create OTP (digest-only) & persist atomically ───────────────
    now = datetime.now(timezone.utc)
    otp_plain = generate_otp(6)
    otp_digest = _hash_otp(otp_plain, user_id=str(user.id), purpose=OTP_PURPOSE)

    tx_ctx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx_ctx:
        # Invalidate prior unused reactivation OTPs
        await db.execute(
            delete(OTP).where(
                OTP.user_id == user.id,
                OTP.purpose == OTP_PURPOSE,
                OTP.used == False,  # noqa: E712
            )
        )
        db.add(
            OTP(
                user_id=user.id,
                code=otp_digest,  # store digest, never plaintext
                purpose=OTP_PURPOSE,
                expires_at=now + timedelta(minutes=OTP_TTL_MINUTES),
                used=False,
                created_at=now,
            )
        )

    # ── [Step 4] Email + audit (non-blocking) ────────────────────────────────
    if background_tasks is not None:
        background_tasks.add_task(send_password_reset_otp, user.email, otp_plain)

    await log_audit_event(
        db=db,
        user=user,
        action=AuditEvent.REQUEST_REACTIVATION_OTP,
        status="SUCCESS",
        request=request,
        meta_data={"email": user.email, "ttl_minutes": OTP_TTL_MINUTES},
    )

    # ── [Step 5] Respond (neutral) ───────────────────────────────────────────
    return generic


# ─────────────────────────────────────────────────────────────
# ✅ Verify OTP → Reactivate (and emit activity event)
# ─────────────────────────────────────────────────────────────
async def reactivate_account_by_otp(
    email: str,
    otp_code: str,
    db: AsyncSession,
    request: Optional[Request],
    background_tasks: Optional[BackgroundTasks],
) -> dict:
    """Verify OTP and **reactivate** the account (single-use, TTL-bound).

    Also emits an `ACCOUNT_REACTIVATED` event into the Redis activity ring buffer
    (`audit:recent:{user_id}`) for the user's `/activity` feed.
    """
    # ── [Step 0] Normalize + throttle attempts ───────────────────────────────
    email_norm = (email or "").strip().lower()
    ip = _client_ip(request)

    await enforce_rate_limit(
        key_suffix=f"reactivate:verify:ip:{ip}",
        seconds=10,
        max_calls=10,
        error_message="Too many attempts. Please try again shortly.",
    )

    # ── [Step 1] Resolve user neutrally ──────────────────────────────────────
    user = (await db.execute(select(User).where(User.email == email_norm))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP.")

    if user.is_active:
        return {"message": "Your account is already active."}

    # Reactivation window must not be expired
    if user.scheduled_deletion_at and datetime.now(timezone.utc) > user.scheduled_deletion_at:
        await log_audit_event(
            db=db,
            user=user,
            action=AuditEvent.REACTIVATE_ACCOUNT,
            status="FAILURE",
            request=request,
            meta_data={"reason": "Reactivation Period expired", "scheduled_deletion_at": str(user.scheduled_deletion_at)},
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Reactivation Period has expired.")

    # ── [Step 2] Validate OTP by **peppered digest** (legacy plaintext fallback) ──
    now = datetime.now(timezone.utc)
    digest = _hash_otp(otp_code or "", user_id=str(user.id), purpose=OTP_PURPOSE)

    otp_row: OTP | None = (
        await db.execute(
            select(OTP).where(
                OTP.user_id == user.id,
                OTP.purpose == OTP_PURPOSE,
                OTP.used == False,  # noqa: E712
                OTP.expires_at >= now,
                or_(OTP.code == digest, OTP.code == otp_code),  # fallback supports old plaintext rows
            ).limit(1)
        )
    ).scalar_one_or_none()

    if not otp_row:
        await log_audit_event(
            db=db,
            user=user,
            action=AuditEvent.REACTIVATE_ACCOUNT,
            status="INVALID_OTP",
            request=request,
            meta_data={"ip": ip},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired OTP.")

    # ── [Step 3] Reactivate atomically & consume OTP ─────────────────────────
    tx_ctx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx_ctx:
        user.is_active = True
        user.reactivation_token = None
        user.deactivated_at = None
        user.scheduled_deletion_at = None

        otp_row.used = True
        db.add_all([user, otp_row])

        # Optional: remove any other outstanding reactivation OTPs
        await db.execute(
            delete(OTP).where(
                OTP.user_id == user.id,
                OTP.purpose == OTP_PURPOSE,
                OTP.used == False,  # noqa: E712
            )
        )

    # ── [Step 4] Cache invalidation + audit ──────────────────────────────────
    _invalidate_user_caches_safe(user.id)

    await log_audit_event(
        db=db,
        user=user,
        action=AuditEvent.REACTIVATE_ACCOUNT,
        status="SUCCESS",
        request=request,
        meta_data={"email": user.email},
    )

    # ── [Step 5] Activity ring push (best-effort) ────────────────────────────
    await _push_activity_event(
        user_id=user.id,
        action="ACCOUNT_REACTIVATED",
        status_str="SUCCESS",
        request=request,
        meta={"method": "OTP"},
    )

    # ── [Step 6] Respond ────────────────────────────────────────────────────
    return {"message": "Your account has been successfully reactivated."}


__all__ = ["request_reactivation_otp", "reactivate_account_by_otp"]
