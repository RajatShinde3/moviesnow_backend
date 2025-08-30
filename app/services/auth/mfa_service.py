# app/services/auth/mfa_service.py
from __future__ import annotations

"""
MFA Service — production-grade, test-friendly
=============================================

Responsibilities
----------------
- Enable MFA: issue a **new TOTP secret** and provisioning URI (QR).
- Verify MFA: validate a TOTP code; flip `mfa_enabled=True`; optionally
  include **recovery codes** once (if the recovery-code service is wired).
- Disable MFA: verify password in a timing-safe way and clear the secret.

Security & Reliability
----------------------
- **No secrets in logs**; all audit records are scrubbed.
- **Per-user throttling** via Redis (service-level) + route-level limits.
- **Idempotency** where safe (verify/disable tolerate current state).
- **Cache no-store** is set by the router; service never returns headers.
- **Test-friendly**: explicit `await db.refresh(...)` avoids stale state
  across shared sessions used by tests.

Integration points
------------------
- If `settings.AUTO_GENERATE_RECOVERY_CODES_ON_VERIFY` is True and a
  coroutine `generate_initial_recovery_codes(user, db)` is available,
  this service will include plaintext recovery codes **once** in the
  verify response (hashing/persistence must be done in that service).

Assumptions
-----------
- `generate_totp(secret)` returns a `pyotp.TOTP` object.
- `generate_mfa_token(user_id)` creates a short-lived confirmation token.
- `redis_utils.enforce_rate_limit(...)` raises HTTPException(429) when exceeded.
"""

from typing import Optional, List, Dict

import pyotp
from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import verify_password, generate_totp, generate_mfa_token
from app.db.models.user import User
from app.services.audit_log_service import log_audit_event, AuditEvent
import app.utils.redis_utils as redis_utils


# ─────────────────────────────────────────────────────────────
# 🔧 Helpers
# ─────────────────────────────────────────────────────────────

def _client_ip(request: Optional[Request]) -> str:
    """Best-effort client IP extraction (safe for tests & prod)."""
    try:
        if not request:
            return "-"
        fwd = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip")
        if fwd:
            return fwd.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
    except Exception:
        pass
    return "-"


def _normalize_code(code: str) -> str:
    """
    Strict TOTP format guard.

    Standard TOTP codes are 6 digits. Accept 6–8 to allow minor variants,
    but never accept non-digits.
    """
    c = (code or "").strip()
    if not c.isdigit() or not (6 <= len(c) <= 8):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA code format.",
        )
    return c


def _invalidate_user_caches_safe(user_id) -> None:
    """
    Best-effort invalidation of user-scoped caches; never raises.

    Called when enabling/disabling MFA to ensure downstream auth state
    (e.g., session overviews) reflects changes quickly.
    """
    tags = [f"user:{user_id}", f"user:{user_id}:auth", f"user:{user_id}:permissions"]
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


async def _throttle(key_suffix: str, seconds: int, max_calls: int, error_message: str) -> None:
    """
    Per-user throttle via Redis. Propagates HTTPException(429) from the
    limiter; swallows only infra errors for availability.
    """
    try:
        await redis_utils.enforce_rate_limit(
            key_suffix=key_suffix,
            seconds=seconds,
            max_calls=max_calls,
            error_message=error_message,
        )
    except HTTPException:
        raise
    except Exception:
        # Availability-first fallback (e.g., Redis outage): do not block.
        pass


# ─────────────────────────────────────────────────────────────
# 🔐 Enable MFA (provision secret & QR)
# ─────────────────────────────────────────────────────────────
async def enable_mfa(current_user: User, db: AsyncSession, request: Optional[Request]) -> Dict:
    """
    Generate and persist a **new TOTP secret** for the current user.

    Returns
    -------
    dict
        `{ "qr_code_url": str, "secret": str }` — the provisioning URI for QR
        and the base32 secret. **Do not log or persist the plaintext secret.**

    Raises
    ------
    HTTPException(400)
        If MFA is already enabled.
    HTTPException(429)
        If rate limit is exceeded (per-user).
    """
    # ── [Step 0] Ensure we see the latest DB state (fixes test flake) ────────
    try:
        await db.refresh(current_user)
    except Exception:
        pass

    # ── [Step 1] State gate ──────────────────────────────────────────────────
    if getattr(current_user, "mfa_enabled", False):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is already enabled.")

    # ── [Step 2] Throttle attempts ───────────────────────────────────────────
    await _throttle(
        key_suffix=f"mfa-enable:{current_user.id}",
        seconds=60,
        max_calls=3,
        error_message="Please wait before retrying MFA setup.",
    )

    # ── [Step 3] Generate secret and persist (pending) ───────────────────────
    secret = pyotp.random_base32()
    tx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx:
        current_user.totp_secret = secret
        # keep mfa_enabled = False until verification
        db.add(current_user)

    # ── [Step 4] Build provisioning URI (QR) ─────────────────────────────────
    totp = generate_totp(secret)
    provisioning_uri = totp.provisioning_uri(name=current_user.email, issuer_name="MoviesNow")

    # ── [Step 5] Audit success (no secret logged) ────────────────────────────
    await log_audit_event(
        db=db,
        user=current_user,
        action=AuditEvent.ENABLE_MFA,
        status="SUCCESS",
        request=request,
        meta_data={"email": current_user.email, "ip": _client_ip(request)},
    )

    # ── [Step 6] Respond ─────────────────────────────────────────────────────
    return {"qr_code_url": provisioning_uri, "secret": secret}


# ─────────────────────────────────────────────────────────────
# ✅ Verify MFA Code and finalize setup
# ─────────────────────────────────────────────────────────────
async def verify_mfa(code: str, current_user: User, db: AsyncSession, request: Optional[Request]) -> Dict:
    """
    Verify a TOTP code against the stored secret and enable MFA.

    Returns
    -------
    dict
        `{ "message": "MFA enabled successfully.", "mfa_token": str, ... }`
        Optionally includes `"recovery_codes": [..]` once if the recovery
        service is enabled.

    Raises
    ------
    HTTPException(400)
        If MFA is not set up (missing secret).
    HTTPException(401)
        If the provided TOTP code is invalid.
    HTTPException(429)
        If rate limit is exceeded (per-user).
    """
    # ── [Step 0] See latest DB state (fixes shared-session staleness in tests) ─
    try:
        await db.refresh(current_user)
    except Exception:
        pass

    # ── [Step 1] Idempotent short-circuit ────────────────────────────────────
    if getattr(current_user, "mfa_enabled", False):
        return {"message": "MFA is already enabled."}

    if not getattr(current_user, "totp_secret", None):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not set up for this account.")

    # ── [Step 2] Throttle attempts ───────────────────────────────────────────
    await _throttle(
        key_suffix=f"mfa-verify:{current_user.id}",
        seconds=60,
        max_calls=5,
        error_message="Too many attempts. Please try again shortly.",
    )

    # ── [Step 3] Normalize + verify TOTP ─────────────────────────────────────
    code = _normalize_code(code)
    totp = generate_totp(current_user.totp_secret)
    if not totp.verify(code, valid_window=1):
        await log_audit_event(
            db=db,
            user=current_user,
            action=AuditEvent.VERIFY_MFA,
            status="FAILURE",
            request=request,
            meta_data={"reason": "invalid_code"},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code.")

    # ── [Step 4] Persist enabled state ───────────────────────────────────────
    tx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx:
        current_user.mfa_enabled = True
        db.add(current_user)

    _invalidate_user_caches_safe(current_user.id)

    # ── [Step 5] Optional: recovery codes (best-effort, never logs plaintext) ─
    recovery_codes: Optional[List[str]] = None
    try:
        if bool(getattr(settings, "AUTO_GENERATE_RECOVERY_CODES_ON_VERIFY", False)):
            # Dynamic import so the project can opt-in without hard dependency.
            # Adjust the path to your router/service location.
            from app.api.v1.routers.auth.recovery_codes import generate_initial_recovery_codes  # type: ignore
            recovery_codes = await generate_initial_recovery_codes(current_user, db)
    except Exception:
        recovery_codes = None  # Skip silently if not available

    # ── [Step 6] Audit success ───────────────────────────────────────────────
    await log_audit_event(
        db=db,
        user=current_user,
        action=AuditEvent.VERIFY_MFA,
        status="SUCCESS",
        request=request,
        meta_data={
            "email": current_user.email,
            "ip": _client_ip(request),
            "recovery_codes_issued": bool(recovery_codes),
        },
    )

    # ── [Step 7] Respond (include optional recovery codes) ───────────────────
    payload: Dict = {
        "message": "MFA enabled successfully.",
        "mfa_token": generate_mfa_token(str(current_user.id)),
    }
    if recovery_codes:
        payload["recovery_codes"] = recovery_codes
    return payload


# ─────────────────────────────────────────────────────────────
# ❌ Disable MFA (password-gated)
# ─────────────────────────────────────────────────────────────
async def disable_mfa(password: str, current_user: User, db: AsyncSession, request: Optional[Request]) -> Dict:
    """
    Disable MFA after verifying the user's password.

    Returns
    -------
    dict
        `{ "message": "MFA disabled successfully" }`

    Raises
    ------
    HTTPException(403)
        If the password is invalid.
    HTTPException(429)
        If rate limit is exceeded (per-user).
    """
    # ── [Step 0] Refresh to avoid stale state in tests ───────────────────────
    try:
        await db.refresh(current_user)
    except Exception:
        pass

    # ── [Step 1] Idempotent short-circuit ────────────────────────────────────
    if not getattr(current_user, "mfa_enabled", False):
        return {"message": "MFA is already disabled."}

    # ── [Step 2] Throttle attempts ───────────────────────────────────────────
    await _throttle(
        key_suffix=f"mfa-disable:{current_user.id}",
        seconds=300,
        max_calls=5,
        error_message="Too many attempts. Please try again later.",
    )

    # ── [Step 3] Verify password (timing-safe) ───────────────────────────────
    if not verify_password(password, current_user.hashed_password):
        await log_audit_event(
            db=db,
            user=current_user,
            action=AuditEvent.DISABLE_MFA,
            status="FAILURE",
            request=request,
            meta_data={"reason": "invalid_password"},
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid password")

    # ── [Step 4] Persist disabled state ──────────────────────────────────────
    tx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx:
        current_user.totp_secret = None
        current_user.mfa_enabled = False
        db.add(current_user)

    _invalidate_user_caches_safe(current_user.id)

    # ── [Step 5] Audit success ───────────────────────────────────────────────
    await log_audit_event(
        db=db,
        user=current_user,
        action=AuditEvent.DISABLE_MFA,
        status="SUCCESS",
        request=request,
        meta_data={"email": current_user.email, "ip": _client_ip(request)},
    )

    # ── [Step 6] Respond ─────────────────────────────────────────────────────
    return {"message": "MFA disabled successfully"}
