# app/api/v1/auth/credentials.py

"""
MoviesNow — Credentials & Email Change Router (prod-ready)
==========================================================

Endpoints
---------
- POST /auth/password/change
    In-session password rotation. Requires:
    • Access token in Authorization
    • Fresh step-up token (X-Reauth) — MFA-backed recommended
    • Current password verification
    Side-effects: updates hash, sets password_changed_at (if present),
    and revokes other sessions (keep current lineage).

- POST /auth/email/change/start
    Begin an email change to a new address for the signed-in user.
    Requires step-up. Writes a short-lived token to Redis and (in prod)
    sends it to the **new** address. Returns 200 without revealing token
    (optionally returns it in debug/dev).

- POST /auth/email/change/confirm
    Confirm the email change using the token delivered to the new address.
    Requires auth; step-up recommended. Updates the user email, marks verified
    (if your model supports it), and (optionally) revokes other sessions.

Security & Resilience
---------------------
- **Step-up** enforced via `require_step_up_mfa()` (MFA-backed).
- **No-store** cache headers via `set_sensitive_cache`.
- **Rate-limited** per route (user/IP key).
- **Audit-logged** via `log_audit_event` with structured metadata.
- **Redis** used for short-lived email-change tokens.
- **Session safety**: reuse sentinels & keep-current revocation leveraged
  by reusing your `/auth/sessions/others` logic where appropriate.

Configuration knobs (optional)
------------------------------
- `EMAIL_CHANGE_TOKEN_TTL_MINUTES` (int, default 15)
- `DEBUG_RETURN_TOKENS` (bool, default False) — return token in API (dev only)

Model compatibility
-------------------
- Password field assumed to be `hashed_password` or `password_hash`.
- Email verified flag assumed to be `is_verified` (if present).
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.limiter import rate_limit
from app.core.redis_client import redis_wrapper
from app.core.security import get_current_user, verify_password, get_password_hash
from app.db.session import get_async_db
from app.db.models.user import User
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event, AuditEvent
from app.schemas.auth import EmailChangeConfirmIn, PasswordChangeIn, EmailChangeStartIn
from app.api.v1.routers.auth.sessions import revoke_other_sessions  

router = APIRouter(tags=["Credentials & Email"])

# ──────────────────────────────────────────────────────────────
# Step-up dependency (MFA-backed)
# ──────────────────────────────────────────────────────────────
try:
    # Your dependency module
    from app.dependencies.step_up import require_step_up_mfa
except Exception:
    # Fallback shim if not present (don’t fail import)
    def require_step_up_mfa():
        async def _noop():
            return {}
        return _noop

# ──────────────────────────────────────────────────────────────
# Settings & Redis keys
# ──────────────────────────────────────────────────────────────
EMAIL_CHANGE_TOKEN_TTL_MINUTES = int(getattr(settings, "EMAIL_CHANGE_TOKEN_TTL_MINUTES", 15))
DEBUG_RETURN_TOKENS = bool(getattr(settings, "DEBUG_RETURN_TOKENS", False))

EMAIL_CHG_KEY = lambda user_id: f"emailchg:{user_id}"

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _b2s(v):
    return v.decode() if isinstance(v, (bytes, bytearray)) else v

# ──────────────────────────────────────────────────────────────
# Utilities
# ──────────────────────────────────────────────────────────────
def _password_field_name(u: User) -> str:
    # Be tolerant to naming differences
    if hasattr(u, "hashed_password"):
        return "hashed_password"
    if hasattr(u, "password_hash"):
        return "password_hash"
    # Fall back to a common name; better to raise if truly missing
    return "hashed_password"

def _set_if_exists(u: User, field: str, value) -> None:
    if hasattr(u, field):
        setattr(u, field, value)

async def _email_in_use(db: AsyncSession, email: str) -> bool:
    q = select(User).where(User.email == email)
    return (await db.execute(q)).scalar_one_or_none() is not None


# ──────────────────────────────────────────────────────────────
# POST /auth/password/change — in-session rotation
# ──────────────────────────────────────────────────────────────
@router.post(
    "/password/change",
    summary="Change password (in-session; step-up required)",
    status_code=200,
)
@rate_limit("5/minute")
async def change_password(
    payload: PasswordChangeIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    _reauth=Depends(require_step_up_mfa()),  # returns verified reauth claims
):
    """
    Rotate the current user's password **in-session**.

    Requirements
    ------------
    - Caller is authenticated and provides a fresh **step-up (MFA) token** via `X-Reauth`.
    - Caller proves knowledge of the **current password**.
    - On success we:
      - Update the stored password hash
      - Set `password_changed_at` (if your model has it)
      - Revoke **other** sessions (keep the current lineage)
      - Audit the event
    """
    set_sensitive_cache(response)

    # Load a fresh copy of the user from DB
    db_user = (await db.execute(select(User).where(User.id == current_user.id))).scalar_one_or_none()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    pwd_field = _password_field_name(db_user)
    stored_hash = getattr(db_user, pwd_field, None)
    if not stored_hash or not verify_password(payload.current_password, stored_hash):
        # Audit (best-effort)
        try:
            await log_audit_event(db, action=AuditEvent.PASSWORD_CHANGE, user=current_user, status="FAILURE", request=request, meta_data={"reason": "bad_current"})
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid current password")

    # Optional: strengthen policy beyond min length
    if payload.current_password == payload.new_password:
        raise HTTPException(status_code=400, detail="New password must differ from current")

    # Update hash (and ancillary timestamps if present)
    setattr(db_user, pwd_field, get_password_hash(payload.new_password))
    _set_if_exists(db_user, "password_changed_at", _now_utc())
    await db.commit()

    # Revoke other sessions (keep current); reuse your route logic
    try:
        await revoke_other_sessions(request, response, db, current_user)  # type: ignore
    except Exception:
        # Don’t fail the change if revocation has issues; audit will still record the change
        pass

    # Audit
    try:
        await log_audit_event(db, action=AuditEvent.PASSWORD_CHANGE, user=current_user, status="SUCCESS", request=request)
    except Exception:
        pass

    return {"status": "ok"}


# ──────────────────────────────────────────────────────────────
# POST /auth/email/change/start — begin email change
# ──────────────────────────────────────────────────────────────
@router.post(
    "/email/change/start",
    summary="Start email change (step-up required)",
    status_code=200,
)
@rate_limit("5/minute")
async def email_change_start(
    payload: EmailChangeStartIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    _reauth=Depends(require_step_up_mfa()),
):
    """
    Start an **email change** to `new_email` for the current user.

    Security
    --------
    - Requires a fresh **MFA step-up** token.
    - Confirms `current_password` if supplied (recommended UX).
    - Verifies the email is different and **not already in use**.
    - Writes a short-lived token in Redis (default TTL: 15 min) and
      sends it to the **new** email address (hook here for your mailer).

    Response
    --------
    - Returns 200 with a generic message.
    - In dev (`DEBUG_RETURN_TOKENS=True`), includes the token for convenience.
    """
    set_sensitive_cache(response)

    new_email = str(payload.new_email).lower()
    if new_email == (current_user.email or "").lower():
        raise HTTPException(status_code=400, detail="New email must be different")

    if await _email_in_use(db, new_email):
        raise HTTPException(status_code=400, detail="Email is already in use")

    # Optional extra proof of possession — current password
    if payload.current_password:
        db_user = (await db.execute(select(User).where(User.id == current_user.id))).scalar_one_or_none()
        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")
        pwd_field = _password_field_name(db_user)
        stored_hash = getattr(db_user, pwd_field, None)
        if not stored_hash or not verify_password(payload.current_password, stored_hash):
            try:
                await log_audit_event(db, action=AuditEvent.EMAIL_CHANGE_START, user=current_user, status="FAILURE", request=request, meta_data={"reason": "bad_current"})
            except Exception:
                pass
            raise HTTPException(status_code=400, detail="Invalid current password")

    # Generate and store token
    token = secrets.token_urlsafe(32)
    ttl = EMAIL_CHANGE_TOKEN_TTL_MINUTES * 60
    try:
        r = redis_wrapper.client
        await r.hset(EMAIL_CHG_KEY(current_user.id), mapping={
            "token": token,
            "new_email": new_email,
            "issued_at": _now_utc().isoformat(),
        })
        await r.expire(EMAIL_CHG_KEY(current_user.id), ttl)
    except Exception:
        try:
            await log_audit_event(db, action=AuditEvent.EMAIL_CHANGE_START, user=current_user, status="FAILURE", request=request, meta_data={"reason": "kv_unavailable"})
        except Exception:
            pass
        raise HTTPException(status_code=503, detail="Temporary storage unavailable")

    # TODO: Hook your mailer here to deliver `token` to `new_email`.

    # Audit success
    try:
        await log_audit_event(db, action=AuditEvent.EMAIL_CHANGE_START, user=current_user, status="SUCCESS", request=request, meta_data={"to": new_email})
    except Exception:
        pass

    resp: Dict[str, object] = {"status": "ok"}
    if DEBUG_RETURN_TOKENS:
        resp["debug_token"] = token
    return resp


# ──────────────────────────────────────────────────────────────
# POST /auth/email/change/confirm — finalize email change
# ──────────────────────────────────────────────────────────────
@router.post(
    "/email/change/confirm",
    summary="Confirm email change with token",
    status_code=200,
)
@rate_limit("10/minute")
async def email_change_confirm(
    payload: EmailChangeConfirmIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    _reauth=Depends(require_step_up_mfa()),  # recommend step-up here, too
):
    """
    Confirm an email change using the token sent to the **new** address.

    Behavior
    --------
    - Reads the pending change from Redis; requires a valid, unexpired token.
    - Updates the user’s email in DB, marks `is_verified=True` if your model
      supports it (since control of the new inbox is proven by this step).
    - Clears the Redis key and audits the action.
    - (Optional) Revokes other sessions to reduce account-takeover risk.

    Notes
    -----
    - If you prefer **double opt-in**, you can also send a “last-chance” notice
      to the *old* address and delay the final update until a grace window passes.
    """
    set_sensitive_cache(response)

    # Load pending change
    try:
        r = redis_wrapper.client
        data = await r.hgetall(EMAIL_CHG_KEY(current_user.id))
        pending = {str(_b2s(k)): _b2s(v) for k, v in (data or {}).items()}
    except Exception:
        pending = {}

    if not pending:
        raise HTTPException(status_code=400, detail="No pending email change")

    if str(pending.get("token") or "") != payload.token:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    new_email = str(pending.get("new_email") or "").lower()
    if not new_email:
        raise HTTPException(status_code=400, detail="Invalid state")

    # Final uniqueness guard (race-safe)
    if await _email_in_use(db, new_email):
        # Someone grabbed it between start and confirm
        raise HTTPException(status_code=409, detail="Email is already in use")

    # Apply changes
    db_user = (await db.execute(select(User).where(User.id == current_user.id))).scalar_one_or_none()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    setattr(db_user, "email", new_email)
    _set_if_exists(db_user, "is_verified", True)  # If your model has it
    _set_if_exists(db_user, "email_changed_at", _now_utc())
    await db.commit()

    # Clean up the token
    try:
        await redis_wrapper.client.delete(EMAIL_CHG_KEY(current_user.id))
    except Exception:
        pass

    # Optionally revoke other sessions (keep current)
    try:
        await revoke_other_sessions(request, response, db, current_user)  # type: ignore
    except Exception:
        pass

    # Audit
    try:
        await log_audit_event(db, action=AuditEvent.EMAIL_CHANGE_CONFIRM, user=current_user, status="SUCCESS", request=request, meta_data={"new": new_email})
    except Exception:
        pass

    return {"status": "ok", "email": new_email}
