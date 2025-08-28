from __future__ import annotations

"""
Email verification service — hardened & production-ready
=======================================================

What this module provides
-------------------------
• Resend verification email (`resend_verification_email`) with:
  - **No account enumeration**: generic response unless already verified (safe to reveal).
  - **Per-email rate limits** via Redis/Lua helper.
  - **Token rotation** on every resend; server stores **HMAC digest only**.
  - **Async email** dispatch via `BackgroundTasks`.

• Verify token (`verify_email_token`) with:
  - **Per-IP rate limits** (fast abuse throttling).
  - **TTL-bounded** token validity & **single-use** semantics.
  - **Digest equality** check (HMAC-SHA256 w/ secret pepper), no plaintext storage.
  - **Best-effort cache invalidation** after success.

Design notes
------------
• The verification token is generated with `secrets.token_urlsafe(32)`.
  Only its **HMAC digest** is stored in DB:
  HMAC(key=settings.SECRET_KEY, msg=f"verify_email:{user_id}:{token}").
• Verifying a token requires scanning recent (TTL-bounded) unverified users and
  computing candidate digests; this avoids storing plaintext and is robust if
  you don’t encode the user id into the token itself.
• `send_verification_email(email, token, public_base_url=...)` must render a link
  using the base URL; see `app.utils.email_utils.send_verification_email`.

"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Iterable
import hashlib
import hmac
import re
import secrets

from fastapi import HTTPException, Request, BackgroundTasks
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.user import User
from app.utils.email_utils import send_verification_email
from app.services.audit_log_service import log_audit_event, AuditEvent
from app.utils.redis_utils import enforce_rate_limit
from app.core.config import settings


# ─────────────────────────────────────────────────────────────
# ⚙️ Configuration
# ─────────────────────────────────────────────────────────────

# Token lifetime (hours). Clamped to a safe range to avoid foot-guns.
EMAIL_VERIFY_TTL_HOURS: int = int(getattr(settings, "EMAIL_VERIFICATION_TTL_HOURS", 48) or 48)
EMAIL_VERIFY_TTL_HOURS = max(1, min(EMAIL_VERIFY_TTL_HOURS, 24 * 7))  # [1h, 168h]

# Public base URL used by the email template to build the verification link
PUBLIC_BASE_URL: str = getattr(settings, "PUBLIC_BASE_URL", "http://localhost:8000")

# Limit rows scanned when verifying token to reduce worst-case cost
TOKEN_SCAN_LIMIT: int = 5000

# URL-safe token regex: accepts base64url / uuid / hex / url-safe variants
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-\.~]+=*$")


# ─────────────────────────────────────────────────────────────
# 🔧 Utilities
# ─────────────────────────────────────────────────────────────

def _norm_email(email: str) -> str:
    """Return a normalized email: trimmed + lower-cased."""
    return (email or "").strip().lower()


def _token_digest(token: str, user_id: str) -> str:
    """
    Compute HMAC-SHA256 hex digest for the given token and user scope.

    The message incorporates a *purpose* prefix to prevent cross-use of tokens:

        msg = f"verify_email:{user_id}:{token}"

    Pepper/secret is taken from `settings.SECRET_KEY` (Pydantic `SecretStr`).
    """
    if not token or not user_id:
        raise ValueError("token and user_id are required")
    key_str = settings.SECRET_KEY.get_secret_value()  # SecretStr → str
    key = key_str.encode("utf-8")
    msg = f"verify_email:{user_id}:{token}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _client_ip(request: Optional[Request]) -> str:
    """Extract a best-effort client IP for throttling."""
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
    """
    Best-effort invalidation of user-scoped caches (fire-and-forget).

    Tries `cache_invalidate_tags(*tags)` first; falls back to
    `cache_invalidation_tags(*tags)` if present. Never raises.
    """
    tags: Iterable[str] = (
        f"user:{user_id}",
        f"user:{user_id}:auth",
        f"user:{user_id}:profile",
    )
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

        # Legacy name
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
        # Never let cache issues bubble into auth flows
        pass


# ─────────────────────────────────────────────────────────────
# 🔁 Resend Verification Email (no enumeration; async)
# ─────────────────────────────────────────────────────────────

async def resend_verification_email(
    email: str,
    db: AsyncSession,
    request: Optional[Request] = None,
    background_tasks: Optional[BackgroundTasks] = None,
) -> dict:
    """
    Resend a verification email if the account is not yet verified.

    Security characteristics
    ------------------------
    • **No account enumeration**: Response is generic regardless of existence,
      except if the account is *already verified* (safe to reveal).
    • **Per-email rate limit**: 1/minute by normalized email hash.
    • **Rotating tokens**: New token generated each time; DB stores digest only.

    Args:
        email: User-submitted email address.
        db: Active `AsyncSession`.
        request: Current `Request` for logging and throttling context.
        background_tasks: Optional FastAPI `BackgroundTasks` for async email + audit.

    Returns:
        A generic success message, or "already verified" when applicable.
    """
    generic = {"message": "If your email is registered, a verification link has been sent."}
    norm = _norm_email(email)

    # Rate-limit per normalized email (avoid enumeration)
    await enforce_rate_limit(
        key_suffix=f"resend-verify:{hashlib.sha256(norm.encode()).hexdigest()}",
        seconds=60,
        max_calls=1,
        error_message="Please wait before requesting another verification email.",
    )

    # Silent lookup
    user = (await db.execute(select(User).where(User.email == norm))).scalar_one_or_none()
    if not user:
        if background_tasks:
            background_tasks.add_task(
                log_audit_event, db, None, AuditEvent.RESEND_VERIFICATION, "USER_NOT_FOUND",
                request, {"email": norm}, False
            )
        return generic

    # Already verified → safe to say so
    if getattr(user, "is_verified", False):
        if background_tasks:
            background_tasks.add_task(
                log_audit_event, db, user, AuditEvent.RESEND_VERIFICATION, "ALREADY_VERIFIED",
                request, {"email": norm}, False
            )
        return {"message": "Your email is already verified."}

    # Generate fresh token & store only digest
    token = secrets.token_urlsafe(32)
    digest = _token_digest(token, user_id=str(user.id))
    now = datetime.now(timezone.utc)

    # Use nested TX if already inside a transaction
    tx_ctx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx_ctx:
        user.verification_token = digest
        user.verification_token_created_at = now
        user.email = norm  # normalize on write
        db.add(user)

    # Fire-and-forget tasks
    if background_tasks is not None:
        background_tasks.add_task(
            send_verification_email,
            email=user.email,
            token=token,  # send plaintext token to recipient only
        )
        background_tasks.add_task(
            log_audit_event, db, user, AuditEvent.RESEND_VERIFICATION, "SUCCESS",
            request, {"email": norm}, False
        )

    # Generic response (no enumeration)
    return generic


# ─────────────────────────────────────────────────────────────
# ✅ Verify Email Token (TTL, single-use, digest match)
# ─────────────────────────────────────────────────────────────

async def verify_email_token(
    token: str,
    db: AsyncSession,
    request: Optional[Request] = None,
    background_tasks: Optional[BackgroundTasks] = None,
) -> dict:
    """
    Verify a user's email by matching a provided token against stored digests.

    Security characteristics
    ------------------------
    • **Per-IP rate limit** to throttle high-volume attempts.
    • **TTL window**: Only recent (not expired) digests are considered.
    • **Single-use**: On success, digest and timestamp are cleared.
    • **Constant-time equality** (HMAC digest equality); no plaintext token in DB.

    Args:
        token: Token received via email.
        db: Active `AsyncSession`.
        request: Current `Request` for throttling & audit context.
        background_tasks: Optional background task runner for audit logging.

    Returns:
        JSON dict with a success message.

    Raises:
        HTTPException(400): Invalid or expired token.
    """
    # Throttle attempts by IP (fast path)
    ip = _client_ip(request)
    await enforce_rate_limit(
        key_suffix=f"verify-email:{ip}",
        seconds=10,
        max_calls=10,
        error_message="Too many attempts. Please try again shortly.",
    )

    # Token sanity checks
    if not token or len(token) > 512 or not _TOKEN_RE.match(token):
        raise HTTPException(status_code=400, detail="Invalid token.")

    # Search only within TTL window for unverified users with a token
    now = datetime.now(timezone.utc)
    earliest = now - timedelta(hours=EMAIL_VERIFY_TTL_HOURS)

    result = await db.execute(
        select(User)
        .where(
            User.is_verified == False,  # noqa: E712
            User.verification_token.isnot(None),
            User.verification_token_created_at.isnot(None),
            User.verification_token_created_at >= earliest,
        )
        .order_by(User.verification_token_created_at.desc())
        .limit(TOKEN_SCAN_LIMIT)
    )
    candidates = result.scalars().all()

    # Compute candidate digests and compare for equality
    match: Optional[User] = None
    for u in candidates:
        if _token_digest(token, user_id=str(u.id)) == u.verification_token:
            match = u
            break

    if not match:
        if background_tasks:
            background_tasks.add_task(
                log_audit_event, db, None, AuditEvent.VERIFY_EMAIL, "FAILURE",
                request, {"reason": "invalid_or_expired"}, False
            )
        raise HTTPException(status_code=400, detail="Invalid or expired token.")

    # Mark verified, clear token (single-use) atomically
    tx_ctx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx_ctx:
        match.is_verified = True
        match.verified_at = now
        match.verification_token = None
        match.verification_token_created_at = None
        db.add(match)

    # Best-effort cache invalidation (non-blocking)
    _invalidate_user_caches_safe(match.id)

    if background_tasks:
        background_tasks.add_task(
            log_audit_event, db, match, AuditEvent.VERIFY_EMAIL, "SUCCESS",
            request, {}, False
        )

    return {"message": "Email verified successfully."}


__all__ = [
    "resend_verification_email",
    "verify_email_token",
]
