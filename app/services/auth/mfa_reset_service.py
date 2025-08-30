# app/services/auth/mfa_reset_service.py
from __future__ import annotations

"""
MFA Reset Service — hardened, production-grade
=============================================

Overview
--------
This service implements a two-step, email-based MFA reset flow:

1) **Request reset** (`request_mfa_reset`)
   - No account enumeration (always returns a generic message).
   - Per-email and per-IP Redis rate limits.
   - CSPRNG token; DB stores **peppered HMAC digest** only (never plaintext).
   - Prior unused tokens are cleared before issuing a new one.
   - Email + audit are queued via `BackgroundTasks` (best-effort).

2) **Confirm reset** (`confirm_mfa_reset`)
   - Validates token by **digest** within TTL (single-use semantics).
   - On success: **disable MFA**, **consume token**, and **invalidate recovery codes**.
   - Best-effort cache invalidation (user-scoped tags).

Security Properties
-------------------
- **No enumeration** on request.
- **Scoped rate limits** (per normalized email + per IP).
- **Short TTL**, **single-use** tokens; previous tokens are revoked on issuance.
- **Digest-only storage** (peppered HMAC-SHA256).
- **Background safety**: audit/email failures do not break responses.

Assumptions
-----------
- Email helper: `send_email(to, subject, body)`
- Redis limiter: `enforce_rate_limit(key_suffix, seconds, max_calls, error_message)`
- Optional cache invalidation helpers:
  `app.utils.cache.cache_invalidate_tags` or `cache_invalidation_tags`
"""

# ─────────────────────────────────────────────────────────────
# 📦 Imports
# ─────────────────────────────────────────────────────────────

from datetime import datetime, timedelta, timezone
from typing import Optional
import hashlib
import hmac
import logging
import re
import secrets

from fastapi import BackgroundTasks, HTTPException, Request, status
from sqlalchemy import delete, select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.email import send_email
from app.core.redis_client import redis_wrapper
from app.db.models.mfa_reset_token import MFAResetToken
from app.db.models.user import User
from app.schemas.auth import MFAResetConfirm, MFAResetRequest
from app.services.audit_log_service import AuditEvent, log_audit_event
from app.utils.redis_utils import enforce_rate_limit

logger = logging.getLogger("moviesnow.auth.mfa_reset")

# ─────────────────────────────────────────────────────────────
# ⚙️ Configuration / constants
# ─────────────────────────────────────────────────────────────

# Token TTL (minutes), constrained to a safe range
MFA_RESET_TTL_MINUTES: int = int(getattr(settings, "MFA_RESET_TTL_MINUTES", 30) or 30)
MFA_RESET_TTL_MINUTES = max(5, min(MFA_RESET_TTL_MINUTES, 60 * 24))  # [5m, 24h]

# Frontend base used to craft the reset link
FRONTEND_BASE: str = str(getattr(settings, "FRONTEND_URL", "http://localhost:3000"))

# URL-safe token regex (secrets.token_urlsafe → base64url). Accept 16..512 chars.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,512}$")


# ─────────────────────────────────────────────────────────────
# 🔧 Helpers
# ─────────────────────────────────────────────────────────────

def _norm_email(email: str) -> str:
    """Return trimmed, lower-cased email."""
    return (email or "").strip().lower()


def _token_digest(token: str) -> str:
    """Hex HMAC-SHA256 digest of token with server-side pepper (JWT_SECRET_KEY)."""
    if not token:
        raise ValueError("token required")
    key = settings.JWT_SECRET_KEY.get_secret_value().encode("utf-8")
    msg = f"mfa_reset:{token}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _client_ip(request: Optional[Request]) -> str:
    """Best-effort client IP for throttling/auditing."""
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


async def _invalidate_recovery_codes(user_id) -> None:
    """
    Best-effort invalidation of any existing **recovery code** batch
    so stale codes cannot be redeemed after an email-based MFA reset.

    Key layout:
      recov:{user_id}:batch  — batch metadata (hash)
      recov:{user_id}:codes  — active digests (set)
      recov:{user_id}:used   — consumed digests (set)
    """
    try:
        rc = getattr(redis_wrapper, "client", None)
        if not rc:
            return
        keys = [f"recov:{user_id}:batch", f"recov:{user_id}:codes", f"recov:{user_id}:used"]
        if hasattr(rc, "unlink"):
            await rc.unlink(*keys)  # non-blocking deletion
        else:
            for k in keys:
                try:
                    await rc.delete(k)
                except Exception:
                    pass
    except Exception:
        # non-fatal; continue
        pass


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


# Background wrappers that **never bubble** exceptions back into Starlette.
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


async def _send_email_safely(*, to: str, subject: str, body: str) -> None:
    try:
        await send_email(to=to, subject=subject, body=body)
    except Exception:
        try:
            logger.warning("Background email send failed", exc_info=True)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────
# 🔁 Request MFA Reset (Send Email Link)
# ─────────────────────────────────────────────────────────────

async def request_mfa_reset(
    payload: MFAResetRequest,
    db: AsyncSession,
    request: Optional[Request],
    background_tasks: Optional[BackgroundTasks],
) -> dict:
    """
    Initiate an MFA reset: create a one-time token and email a link.

    Security
    --------
    - **No enumeration**: always returns a generic message.
    - Rate-limited per normalized email and per IP.
    - CSPRNG token; only **digest** stored at rest.
    - Clears old unused tokens for the user on issuance.
    - Non-blocking email + audit dispatch via `BackgroundTasks`.
    """
    # [1] Normalize + rate-limit
    ip = _client_ip(request)
    email_norm = _norm_email(payload.email)

    await enforce_rate_limit(
        key_suffix=f"mfa-reset:req:email:{hashlib.sha256(email_norm.encode()).hexdigest()}",
        seconds=60,
        max_calls=2,
        error_message="Please wait before requesting another MFA reset.",
    )
    await enforce_rate_limit(
        key_suffix=f"mfa-reset:req:ip:{ip}",
        seconds=60,
        max_calls=10,
        error_message="Too many attempts. Please try again later.",
    )

    # [2] Silent lookup (no enumeration)
    user = (await db.execute(select(User).where(User.email == email_norm))).scalar_one_or_none()
    generic = {"message": "If an account with that email exists, an MFA reset link has been sent."}

    # User missing OR MFA not enabled → generic 200 OK (audit as NOT_FOUND)
    if not user or not getattr(user, "mfa_enabled", False):
        if background_tasks:
            background_tasks.add_task(
                _audit_safely,
                db=db,
                user=None,
                action=AuditEvent.MFA_RESET_REQUESTED,
                status="NOT_FOUND",
                request=request,
                meta_data={
                    "email_hash": hashlib.sha256(email_norm.encode()).hexdigest(),
                    "ip": ip,
                },
                commit=False,
            )
        return generic

    # [3] Generate token + digest
    token = secrets.token_urlsafe(32)
    digest = _token_digest(token)
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(minutes=MFA_RESET_TTL_MINUTES)

    # [4] Persist atomically: clear prior unused, insert new
    used_nested = db.in_transaction()
    tx_ctx = db.begin_nested() if used_nested else db.begin()
    async with tx_ctx:
        await db.execute(
            delete(MFAResetToken).where(
                MFAResetToken.user_id == user.id,
                MFAResetToken.used == False,  # noqa: E712
            )
        )
        db.add(
            MFAResetToken(
                user_id=user.id,
                token=digest,
                created_at=created_at,   # ensure DB row uses the same base time
                expires_at=expires_at,   # guaranteed > created_at
                used=False,
            )
        )


    # [5] Send email + audit (background, error-safe)
    if background_tasks is not None:
        reset_url = f"{FRONTEND_BASE.rstrip('/')}/reset-mfa?token={token}"
        background_tasks.add_task(
            _send_email_safely,
            to=user.email,
            subject="🔐 MFA Reset Request",
            body=(
                "You requested to reset your MFA settings.\n\n"
                f"Click the link below to continue:\n{reset_url}\n\n"
                f"⚠️ This link will expire in {MFA_RESET_TTL_MINUTES} minutes.\n"
                "If you did not make this request, you can ignore this email."
            ),
        )
        background_tasks.add_task(
            _audit_safely,
            db=db,
            user=user,
            action=AuditEvent.MFA_RESET_REQUESTED,
            status="SUCCESS",
            request=request,
            meta_data={"expires_at": expires_at.isoformat(), "ip": ip},
            commit=False,
        )

    # [6] Always neutral response
    return generic


# ─────────────────────────────────────────────────────────────
# ✅ Confirm MFA Reset (Token Verification)
# ─────────────────────────────────────────────────────────────

async def confirm_mfa_reset(
    payload: MFAResetConfirm,
    db: AsyncSession,
    request: Optional[Request],
    background_tasks: Optional[BackgroundTasks],
) -> dict:
    """
    Confirm an MFA reset via token; disable MFA and mark token used.

    Security
    --------
    - Per-IP rate limit on verification.
    - Peppered digest match (no plaintext token at rest).
    - **Atomic** update: disables MFA, consumes the token.
    - **Invalidates recovery codes** so stale codes can’t be used post-reset.
    """
    # [1] Rate-limit verification
    ip = _client_ip(request)
    await enforce_rate_limit(
        key_suffix=f"mfa-reset:confirm:{ip}",
        seconds=10,
        max_calls=10,
        error_message="Too many attempts. Please try again shortly.",
    )

    # [2] Token sanity
    token_str = (payload.token or "").strip()
    if not token_str or not _TOKEN_RE.match(token_str):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")

    # [3] Lookup by digest with TTL (legacy plaintext tolerated)
    digest = _token_digest(token_str)
    now = datetime.now(timezone.utc)

    reset_row: MFAResetToken | None = (
        await db.execute(
            select(MFAResetToken).where(
                MFAResetToken.used == False,  # noqa: E712
                MFAResetToken.expires_at > now,
                or_(MFAResetToken.token == digest, MFAResetToken.token == token_str),  # legacy/plain fallback
            )
        )
    ).scalar_one_or_none()

    if not reset_row:
        if background_tasks:
            background_tasks.add_task(
                _audit_safely,
                db=db,
                user=None,
                action=AuditEvent.MFA_RESET_CONFIRMED,
                status="FAILURE",
                request=request,
                meta_data={"reason": "invalid_or_expired", "ip": ip},
                commit=False,
            )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")

    # [4] Fetch user
    user: User | None = (await db.execute(select(User).where(User.id == reset_row.user_id))).scalar_one_or_none()
    if not user:
        if background_tasks:
            background_tasks.add_task(
                _audit_safely,
                db=db,
                user=None,
                action=AuditEvent.MFA_RESET_CONFIRMED,
                status="FAILURE",
                request=request,
                meta_data={"reason": "user_not_found", "user_id": str(reset_row.user_id), "ip": ip},
                commit=False,
            )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid or expired token")

    # [5] Atomically disable MFA and consume token (+ clear other unused)
    used_nested = db.in_transaction()
    tx_ctx = db.begin_nested() if used_nested else db.begin()
    async with tx_ctx:
        user.totp_secret = None
        user.mfa_enabled = False
        reset_row.used = True
        db.add_all([user, reset_row])
        await db.execute(
            delete(MFAResetToken).where(
                MFAResetToken.user_id == user.id,
                MFAResetToken.used == False,  # noqa: E712
            )
        )
    await _commit_or_flush(db, used_nested)

    # [6] Invalidate recovery codes (best-effort)
    await _invalidate_recovery_codes(user.id)

    # [7] Best-effort cache invalidation
    _invalidate_user_caches_safe(user.id)

    # (Optional) Revoke sessions/trusted devices here if desired.
    # from app.core.sessions import revoke_all_sessions_for_user
    # await revoke_all_sessions_for_user(user.id)

    # [8] Audit success (background)
    if background_tasks:
        background_tasks.add_task(
            _audit_safely,
            db=db,
            user=user,
            action=AuditEvent.MFA_RESET_CONFIRMED,
            status="SUCCESS",
            request=request,
            meta_data={"ip": ip},
            commit=False,
        )

    # [9] Respond
    return {
        "message": "MFA has been reset. Please reconfigure your authenticator and generate new recovery codes.",
    }


__all__ = ["request_mfa_reset", "confirm_mfa_reset"]
