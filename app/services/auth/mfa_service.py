from __future__ import annotations

"""
MFA service — hardened, production-grade
=======================================

Responsibilities
----------------
- Enable MFA: issue a **new TOTP secret** and provisioning URI (QR).
- Verify MFA: validate a TOTP code; **flip mfa_enabled** to True; (optionally)
  generate **recovery codes** and return them once.
- Disable MFA: verify password (timing-safe) and clear secret.

Security properties
-------------------
- **No secrets in logs**; clear audit trail for success/failure.
- **Redis-backed throttling** to rate-limit sensitive actions.
- **Idempotent** where safe (verify/disable tolerate current state).
- **No-store** is handled by the router; services only return data.
- **Best-effort** cache invalidation on auth state changes.

Integration points
------------------
- Recovery codes: If `settings.AUTO_GENERATE_RECOVERY_CODES_ON_VERIFY` is True
  and a `generate_initial_recovery_codes(user, db)` function is available, the
  service will include plaintext codes **once** in the verify response.
  (They are not logged or persisted in plaintext; your recovery service must
  hash+pepper and store digests only.)

Assumptions
-----------
- ``generate_totp(secret)`` returns a pyotp.TOTP-compatible object.
- ``generate_mfa_token(user_id)`` issues a short-lived token (optional).
- ``enforce_rate_limit`` raises HTTPException(429) on excess; we propagate it.
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
# 🔧 Small helpers
# ─────────────────────────────────────────────────────────────

def _client_ip(request: Optional[Request]) -> str:
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
    c = (code or "").strip()
    # Standard TOTP is 6 digits; accept 6–8 if you support steam/alt lengths.
    if not c.isdigit() or not (6 <= len(c) <= 8):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid MFA code format.")
    return c


def _invalidate_user_caches_safe(user_id) -> None:
    """Best-effort invalidation of user-scoped caches; never raises."""
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
    Call the Redis rate limiter. **Propagate** HTTPException (e.g., 429).
    Swallow only unexpected infra errors for availability (best effort).
    """
    try:
        await redis_utils.enforce_rate_limit(
            key_suffix=key_suffix,
            seconds=seconds,
            max_calls=max_calls,
            error_message=error_message,
        )
    except HTTPException:
        # do NOT swallow 429 or other HTTPExceptions
        raise
    except Exception:
        # availability-first fallback (e.g., Redis down). Log externally if desired.
        pass


# ─────────────────────────────────────────────────────────────
# 🔐 Enable MFA for Current User
# ─────────────────────────────────────────────────────────────
async def enable_mfa(current_user: User, db: AsyncSession, request: Optional[Request]) -> Dict:
    """
    Generate and persist a **new TOTP secret** for the current user.

    Behavior
    --------
    - Refuses if MFA already enabled.
    - Overwrites any pending secret if user re-runs enable (rate-limited).
    - Returns provisioning URI and base32 secret for client-side QR rendering.
    """
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
    tx_ctx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx_ctx:
        current_user.totp_secret = secret
        # keep mfa_enabled = False until verification
        db.add(current_user)

    # ── [Step 4] Build provisioning URI (QR) ─────────────────────────────────
    totp = generate_totp(secret)
    provisioning_uri = totp.provisioning_uri(name=current_user.email, issuer_name="CareerOS")

    # ── [Step 5] Audit success ───────────────────────────────────────────────
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
# ✅ Verify MFA Code and Finalize Setup
# ─────────────────────────────────────────────────────────────
async def verify_mfa(code: str, current_user: User, db: AsyncSession, request: Optional[Request]) -> Dict:
    """
    Verify a TOTP code and set ``mfa_enabled=True``.

    Behavior
    --------
    - Per-user throttling of attempts.
    - Accepts small clock skew via ``valid_window=1``.
    - Never logs the submitted code.
    - Idempotent: if already enabled, returns success message.
    - Optional: generate **recovery codes** immediately after enabling.
    """
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
    tx_ctx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx_ctx:
        current_user.mfa_enabled = True
        db.add(current_user)

    _invalidate_user_caches_safe(current_user.id)

    # ── [Step 5] Optional: generate initial recovery codes ───────────────────
    recovery_codes: Optional[List[str]] = None
    try:
        if bool(getattr(settings, "AUTO_GENERATE_RECOVERY_CODES_ON_VERIFY", False)):
            # Try dynamic import to avoid hard dependency if the module isn't present.
            from app.api.v1.mfa.recovery_codes import generate_initial_recovery_codes  # type: ignore
            recovery_codes = await generate_initial_recovery_codes(current_user, db)
            # `generate_initial_recovery_codes` must hash+pepper and store digests,
            # returning plaintext codes ONCE. We do not log or persist plaintext here.
    except Exception:
        # If recovery code service isn't present, skip silently.
        recovery_codes = None

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
        # Only include if you updated your response model to allow it.
        payload["recovery_codes"] = recovery_codes
    return payload


# ─────────────────────────────────────────────────────────────
# ❌ Disable MFA with Password Verification
# ─────────────────────────────────────────────────────────────
async def disable_mfa(password: str, current_user: User, db: AsyncSession, request: Optional[Request]) -> Dict:
    """
    Disable MFA after verifying the user's password.

    Behavior
    --------
    - Per-user throttling for disable action.
    - Timing-safe password verification via helper.
    - Idempotent: if already disabled, returns success message.

    Side-effects
    ------------
    - Clears user's TOTP secret and flips `mfa_enabled` to False.
    - Best-effort cache invalidation.
    """
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
    tx_ctx = db.begin_nested() if db.in_transaction() else db.begin()
    async with tx_ctx:
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
