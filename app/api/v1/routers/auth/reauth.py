# app/api/v1/auth/reauth.py

"""
Enterprise-grade **Step-Up (Re-Auth)** Router
============================================

This module provides **production-ready** step-up authentication endpoints for
sensitive operations. It mints a short-lived **reauth** bearer token after an
extra challenge (password or MFA), which downstream endpoints can require via a
`require_step_up()` dependency.

Endpoints
---------
- POST /reauth/password — verify password, mint short-lived reauth token
- POST /reauth/mfa      — verify TOTP code, mint short-lived reauth token
- POST /reauth/verify   — verify current bearer is a valid reauth token

Security & design
-----------------
- **Phishing-resistant**: MFA option for step-up, password fallback
- **Tight TTL**: default 5 minutes (configurable)
- **Bound to session**: includes `session_id` lineage from the access token
- **Org-aware**: attaches most-recent active org `{org_id, role}` when present
- **Hardened**: `Cache-Control: no-store`, per-route limits, Redis brute-force
  counters keyed by **user** and **IP**, neutral error messages, thorough audit

Usage
-----
1) Include this router in `register_routes.py`:

   ```py
   from app.api.v1.auth import reauth
   router.include_router(reauth.router)
   ```

2) Protect sensitive routes with a dependency that requires a **fresh reauth**:

   ```py
   from fastapi import Depends, HTTPException, status

   async def require_step_up(claims = Depends(get_bearer_claims)):
       if (claims.get("token_type") or "").lower() != "reauth":
           raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Step-up required")
   ```

Notes
-----
- This file relies on your existing `rate_limit`, `redis_wrapper`,
  `set_sensitive_cache`, `get_current_user`, and audit logging utilities.
- Adjust `verify_totp` import if your utility differs. Here we use
  `verify_totp(secret, code)` (boolean) and `totp_secret` on the user.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from jose import jwt, JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.redis_client import redis_wrapper
from app.core.limiter import rate_limit
from app.core.dependencies import get_async_db, get_current_user
from app.security_headers import set_sensitive_cache
from app.db.models.user import User
from app.schemas.auth import ReauthMFARequest, ReauthPasswordRequest, ReauthTokenResponse
from app.utils.mfa_utils import verify_totp
from app.services.audit_log_service import log_audit_event
from app.utils.step_up import mint_reauth_token, active_org_for_user

router = APIRouter(tags=["Re-Auth / Step-Up"])  # grouped under step-up

# ─────────────────────────────────────────────────────────────
# ⚙️ Constants & helpers
# ─────────────────────────────────────────────────────────────

# Reauth TTL (seconds) — default 5 minutes.
REAUTH_TTL_SECONDS = int(getattr(settings, "REAUTH_TOKEN_EXPIRE_MINUTES", 5)) * 60

# Anti-bruteforce window & thresholds (per user & per IP)
REAUTH_WINDOW_SECONDS = 600  # 10 minutes
MAX_REAUTH_PW_FAILS = 10
MAX_REAUTH_MFA_FAILS = 10


def _reauth_pw_fail_key(user_id: UUID) -> str:
    return f"reauth:pw:fail:{user_id}"


def _reauth_mfa_fail_key(user_id: UUID) -> str:
    return f"reauth:mfa:fail:{user_id}"


def _reauth_ip_fail_key(ip: str) -> str:
    return f"reauth:ip:fail:{ip or 'unknown'}"


def _normalize_totp(code: str) -> str:
    """Require 6–8 digit numeric TOTP for basic UX/format sanity."""
    c = (code or "").strip()
    if not c.isdigit() or not (6 <= len(c) <= 8):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP format.")
    return c


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


def _extract_bearer_claims(request: Request) -> dict:
    """Decode Authorization bearer and return claims; 401 on failure.

    Enforces that we’re stepping up an **access** session (not a refresh/reauth).
    """
    authz = request.headers.get("authorization") or request.headers.get("Authorization")
    if not authz or not authz.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")
    token = authz.split(" ", 1)[1].strip()
    try:
        decoded = jwt.decode(
            token,
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["sub", "exp"]},
        )
        # Ensure we're stepping up an **access** token
        tok_typ = (decoded.get("token_type") or decoded.get("typ") or "").lower()
        if tok_typ and tok_typ != "access":
            # If your access tokens don’t carry token_type, loosen this check
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token required for step-up")
        return decoded
    except HTTPException:
        raise
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


async def _check_and_bump_fail_counters(user_id: UUID, ip: Optional[str], is_mfa: bool) -> None:
    """Enforce per-user and per-IP failure ceilings within a sliding window."""
    r = redis_wrapper.client
    user_key = _reauth_mfa_fail_key(user_id) if is_mfa else _reauth_pw_fail_key(user_id)
    ip_key = _reauth_ip_fail_key(ip or "")

    user_fails = await r.incr(user_key)
    if user_fails == 1:
        await r.expire(user_key, REAUTH_WINDOW_SECONDS)
    ip_fails = await r.incr(ip_key)
    if ip_fails == 1:
        await r.expire(ip_key, REAUTH_WINDOW_SECONDS)

    ceiling = MAX_REAUTH_MFA_FAILS if is_mfa else MAX_REAUTH_PW_FAILS
    if user_fails > ceiling or ip_fails > ceiling * 2:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many attempts")


async def _reset_fail_counters(user_id: UUID, ip: Optional[str], is_mfa: bool) -> None:
    r = redis_wrapper.client
    await r.delete(_reauth_mfa_fail_key(user_id) if is_mfa else _reauth_pw_fail_key(user_id))
    await r.delete(_reauth_ip_fail_key(ip or ""))


# ─────────────────────────────────────────────────────────────
# 🔐 POST /reauth/password — Step-up with password
# ─────────────────────────────────────────────────────────────
@router.post(
    "/reauth/password",
    response_model=ReauthTokenResponse,
    summary="Step-up with password and receive a short-lived reauth token",
)
@rate_limit("10/minute")
async def reauth_with_password(
    payload: ReauthPasswordRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> ReauthTokenResponse:
    """
    Step-up the current session by re-validating the **account password**.

    Behavior
    --------
    - Requires an authenticated **access** session (Bearer).
    - Verifies password; on success, mints a **reauth** token (short TTL, default 5 minutes).
    - Binds token to caller’s **session_id** and includes active org context.
    - Rate limited and protected by Redis **anti-bruteforce** counters.
    - Responses use **no-store** cache headers to prevent token caching.

    Errors
    ------
    401 invalid/missing credentials, 403 ownership mismatch, 429 too many attempts.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Ownership & context guard ───────────────────────────────────
    claims = _extract_bearer_claims(request)
    ip = _client_ip(request)
    user_id = UUID(str(claims.get("sub")))
    if current_user.id != user_id:
        # Defense-in-depth; get_current_user already enforces this
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    # ── [Step 2] Anti-bruteforce check ───────────────────────────────────────
    await _check_and_bump_fail_counters(user_id=user_id, ip=ip, is_mfa=False)

    # ── [Step 3] Verify password (timing-safe) ───────────────────────────────
    from app.core.security import verify_password  # local import to avoid cycles
    ok = verify_password(payload.password.get_secret_value(), current_user.hashed_password)
    if not ok:
        await log_audit_event(db, action="REAUTH_PASSWORD", user=current_user, status="FAILURE", request=request)
        # Keep counters incremented on failure
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # ── [Step 4] Bind session & org context ──────────────────────────────────
    session_id = claims.get("session_id") or claims.get("jti")
    active_org = await active_org_for_user(db, user_id)

    # ── [Step 5] Mint reauth token ───────────────────────────────────────────
    token, ttl = mint_reauth_token(
        user_id=user_id,
        session_id=str(session_id),
        active_org=active_org,
        mfa_authenticated=False,
    )

    # ── [Step 6] Reset counters & audit success ──────────────────────────────
    await _reset_fail_counters(user_id=user_id, ip=ip, is_mfa=False)
    await log_audit_event(
        db,
        action="REAUTH_PASSWORD",
        user=current_user,
        status="SUCCESS",
        request=request,
        meta_data={"session_id": session_id},
    )

    # ── [Step 7] Respond ─────────────────────────────────────────────────────
    return ReauthTokenResponse(reauth_token=token, expires_in=ttl)


# ─────────────────────────────────────────────────────────────
# 🔐 POST /reauth/mfa — Step-up with TOTP
# ─────────────────────────────────────────────────────────────
@router.post(
    "/reauth/mfa",
    response_model=ReauthTokenResponse,
    summary="Step-up with MFA (TOTP) and receive a short-lived reauth token",
)
@rate_limit("12/minute")
async def reauth_with_mfa(
    payload: ReauthMFARequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> ReauthTokenResponse:
    """
    Step-up the current session by verifying a **6-digit TOTP**.

    Behavior
    --------
    - Requires an authenticated **access** session (Bearer).
    - Validates TOTP against the user’s enrolled MFA secret; mints a short-lived **reauth** token.
    - Bound to current `session_id` and enriched with org context.
    - Rate limited and guarded by Redis **anti-bruteforce** counters.

    Errors
    ------
    400 no enrollment or bad TOTP format, 401 invalid TOTP, 403 ownership mismatch, 429 too many attempts.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Ownership & context guard ───────────────────────────────────
    claims = _extract_bearer_claims(request)
    ip = _client_ip(request)
    user_id = UUID(str(claims.get("sub")))
    if current_user.id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    # ── [Step 2] Ensure MFA enrollment ───────────────────────────────────────
    if not getattr(current_user, "mfa_enabled", False) or not getattr(current_user, "totp_secret", None):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA not enabled")

    # ── [Step 3] Anti-bruteforce check ───────────────────────────────────────
    await _check_and_bump_fail_counters(user_id=user_id, ip=ip, is_mfa=True)

    # ── [Step 4] Verify TOTP ─────────────────────────────────────────────────
    code = _normalize_totp(payload.code)
    ok = verify_totp(current_user.totp_secret, code)  # verify(secret, code) -> bool
    if not ok:
        await log_audit_event(db, action="REAUTH_MFA", user=current_user, status="FAILURE", request=request)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid code")

    # ── [Step 5] Bind session & org context ──────────────────────────────────
    session_id = claims.get("session_id") or claims.get("jti")
    active_org = await active_org_for_user(db, user_id)

    # ── [Step 6] Mint reauth token ───────────────────────────────────────────
    token, ttl = mint_reauth_token(
        user_id=user_id,
        session_id=str(session_id),
        active_org=active_org,
        mfa_authenticated=True,
    )

    # ── [Step 7] Reset counters & audit success ──────────────────────────────
    await _reset_fail_counters(user_id=user_id, ip=ip, is_mfa=True)
    await log_audit_event(
        db,
        action="REAUTH_MFA",
        user=current_user,
        status="SUCCESS",
        request=request,
        meta_data={"session_id": session_id},
    )

    # ── [Step 8] Respond ─────────────────────────────────────────────────────
    return ReauthTokenResponse(reauth_token=token, expires_in=ttl)


# ─────────────────────────────────────────────────────────────
# 🔎 POST /reauth/verify — Is current bearer a fresh reauth?
# ─────────────────────────────────────────────────────────────
@router.post(
    "/reauth/verify",
    summary="Verify that the presented bearer is a fresh reauth token",
)
@rate_limit("60/minute")
async def verify_reauth(
    request: Request,
    response: Response,
) -> dict:
    """
    Verify the **current Authorization bearer** is a valid **reauth** token and
    return the remaining TTL.

    Returns
    -------
    `{ "ok": true, "token_type": "reauth", "expires_in": <seconds> }`

    Errors
    ------
    401 if bearer is missing/invalid or not a reauth token.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Decode current bearer (no access-only restriction) ─────────
    authz = request.headers.get("authorization") or request.headers.get("Authorization")
    if not authz or not authz.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")
    token = authz.split(" ", 1)[1].strip()

    try:
        claims = jwt.decode(
            token,
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["sub", "exp"]},
        )
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    # ── [Step 2] Ensure token_type is reauth ─────────────────────────────────
    tok_typ = (claims.get("token_type") or claims.get("typ") or "").lower()
    if tok_typ != "reauth":
        # Note: this endpoint accepts only **reauth** tokens.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not a reauth token")

    # ── [Step 3] Compute remaining TTL ───────────────────────────────────────
    now = int(datetime.now(timezone.utc).timestamp())
    exp = int(claims.get("exp", 0))
    remaining = max(0, exp - now)

    # ── [Step 4] Respond ─────────────────────────────────────────────────────
    return {"ok": True, "token_type": "reauth", "expires_in": remaining}



__all__ = ["router", "reauth_with_password", "reauth_with_mfa", "verify_reauth"]
