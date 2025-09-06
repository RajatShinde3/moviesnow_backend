# app/api/v1/auth/reauth.py
"""
Enterprise‑grade **Step‑Up (Re‑Auth)** Router — MoviesNow
=========================================================

Production‑ready endpoints to **re‑authenticate** the currently logged‑in user
for sensitive operations (e.g., change password/email, delete account, manage
API keys). After a successful extra challenge (password or MFA), the server
mints a short‑lived **reauth** bearer token that downstream endpoints can
require via the `require_step_up()` dependency (see `app.dependencies.step_up`).

Why this exists
---------------
Access tokens often live minutes to hours. For high‑risk actions, you want
fresh proof‑of‑possession. These endpoints provide that proof with a very
short Time‑To‑Live (TTL) token bound to the active session.

Endpoints
---------
- **POST** `/reauth/password` — verify password, mint short‑lived reauth token
- **POST** `/reauth/mfa`      — verify TOTP code, mint short‑lived reauth token
- **POST** `/reauth/verify`   — verify current bearer is a valid reauth token

Security & Design
-----------------
- **Phishing‑resistant**: prefer MFA step‑up; password is a fallback.
- **Tight TTL**: default **5 minutes** (configurable via `REAUTH_TOKEN_EXPIRE_MINUTES`).
- **Session binding**: includes `session_id` lineage from the access token.
- **Org‑free**: MoviesNow variant has **no tenant/org claims**.
- **Hardened**: `Cache‑Control: no-store`, per‑route rate limits, Redis brute‑force
  counters keyed by **user** and **IP**, neutral error messages, thorough (best‑effort)
  audit logs.

Usage
-----
1) Include this router in your v1 aggregator (e.g., `app/api/v1/routers.py`):

   ```py
   from app.api.v1.auth import reauth
   router.include_router(reauth.router)
   ```

2) Protect sensitive routes with a **step‑up dependency**:

   ```py
   from fastapi import Depends, HTTPException, status
   from app.dependencies.step_up import require_step_up

   /account/change-email", dependencies=[Depends(require_step_up())])
   async def change_email(...):
       ...
   ```

Notes
-----
- Relies on MoviesNow utilities: `rate_limit`, `redis_wrapper`, `set_sensitive_cache`,
  `get_current_user`, and optional **audit log** model.
- MFA verification uses `pyotp` via `verify_totp(secret, code)` (see `app.core.security`).
- Step‑up token format is a regular JWT with `token_type="reauth"`.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Dict
from uuid import UUID, uuid4
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from jose import jwt, JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.redis_client import redis_wrapper
from app.core.limiter import rate_limit
from app.db.session import get_async_db
from app.core.security import verify_password, generate_totp  # MFA helper
from app.core.jwt import get_bearer_token, decode_token
from app.utils.security import set_sensitive_cache
from app.db.models.user import User
from app.schemas.auth import (
    ReauthMFARequest,
    ReauthPasswordRequest,
    ReauthTokenResponse,
)
from app.core.security import get_current_user  

router = APIRouter(tags=["Re‑Auth / Step‑Up"]) 
logger = logging.getLogger("moviesnow.auth.reauth")


# ──────────────────────────────────────────────────────────────────────────────
# ⚙️ Constants & helpers
# ──────────────────────────────────────────────────────────────────────────────

# Reauth TTL (seconds) — default 5 minutes.
_REAUTH_TTL_SECONDS: int = int(getattr(settings, "REAUTH_TOKEN_EXPIRE_MINUTES", 5)) * 60

# Anti‑bruteforce window & thresholds (per user & per IP)
_REAUTH_WINDOW_SECONDS = 600  # 10 minutes
_MAX_REAUTH_PW_FAILS = 10
_MAX_REAUTH_MFA_FAILS = 10


def _reauth_pw_fail_key(user_id: UUID) -> str:
    return f"reauth:pw:fail:{user_id}"


def _reauth_mfa_fail_key(user_id: UUID) -> str:
    return f"reauth:mfa:fail:{user_id}"


def _reauth_ip_fail_key(ip: str) -> str:
    return f"reauth:ip:fail:{ip or 'unknown'}"


def _normalize_totp(code: str) -> str:
    """Strict‑ish format check: require a **6–8 digit** numeric TOTP code.

    Raises
    ------
    HTTPException
        `400 Bad Request` when the format is invalid.
    """
    c = (code or "").strip()
    if not c.isdigit() or not (6 <= len(c) <= 8):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP format.")
    return c


def _client_ip(request: Optional[Request]) -> str:
    """Best‑effort client IP extraction (XFF, X‑Real‑IP, then `request.client`)."""
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


# ──────────────────────────────────────────────────────────────────────────────
# 🔐 Token helpers (mint + verify)
# ──────────────────────────────────────────────────────────────────────────────

def _mint_reauth_token(*, user_id: UUID, session_id: Optional[str], mfa_authenticated: bool) -> Tuple[str, int]:
    """Create a signed **reauth** token with a short TTL.

    The token includes minimal, privacy‑preserving claims and is **bound to the
    caller's session** via `session_id` (when present on the access token).

    Returns
    -------
    (token, ttl_seconds)
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(seconds=_REAUTH_TTL_SECONDS)

    payload: Dict[str, object] = {
        "sub": str(user_id),
        "exp": expire,
        "iat": now,
        "nbf": now,
        "jti": str(uuid4()),
        "token_type": "reauth",
        "mfa_authenticated": bool(mfa_authenticated),
    }
    # Optional issuer/audience pass‑throughs
    iss = getattr(settings, "JWT_ISSUER", None)
    aud = getattr(settings, "JWT_AUDIENCE", None)
    if iss:
        payload["iss"] = iss
    if aud:
        payload["aud"] = aud
    if session_id:
        payload["session_id"] = str(session_id)

    token = jwt.encode(payload, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=settings.JWT_ALGORITHM)
    return token, int(_REAUTH_TTL_SECONDS)


async def _extract_access_claims(request: Request) -> Dict:
    """Decode the **Authorization** bearer and ensure it is an **access** token.

    We reuse the centralized decoder (`app.core.jwt.decode_token`) to benefit
    from uniform issuer/audience checks and revocation verification.
    """
    access_token = get_bearer_token(request)
    claims = await decode_token(access_token, expected_types=["access"], verify_revocation=True)
    return claims


async def _check_and_bump_fail_counters(*, user_id: UUID, ip: Optional[str], is_mfa: bool) -> None:
    """Enforce per‑user and per‑IP failure ceilings within a sliding window.

    Uses Redis `INCR` with an expiry. If Redis is unavailable, the function
    degrades **open** (no counters) rather than blocking users.
    """
    r = getattr(redis_wrapper, "client", None)
    if r is None:
        return

    user_key = _reauth_mfa_fail_key(user_id) if is_mfa else _reauth_pw_fail_key(user_id)
    ip_key = _reauth_ip_fail_key(ip or "")

    try:
        user_fails = await r.incr(user_key)
        if user_fails == 1:
            await r.expire(user_key, _REAUTH_WINDOW_SECONDS)
        ip_fails = await r.incr(ip_key)
        if ip_fails == 1:
            await r.expire(ip_key, _REAUTH_WINDOW_SECONDS)

        ceiling = _MAX_REAUTH_MFA_FAILS if is_mfa else _MAX_REAUTH_PW_FAILS
        if user_fails > ceiling or ip_fails > ceiling * 2:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many attempts")
    except HTTPException:
        raise
    except Exception:
        # Best‑effort only; don't fail closed on Redis hiccups.
        logger.warning("Redis counters failed (continuing)", extra={"user_id": str(user_id)})


async def _reset_fail_counters(*, user_id: UUID, ip: Optional[str], is_mfa: bool) -> None:
    r = getattr(redis_wrapper, "client", None)
    if r is None:
        return
    try:
        await r.delete(_reauth_mfa_fail_key(user_id) if is_mfa else _reauth_pw_fail_key(user_id))
        await r.delete(_reauth_ip_fail_key(ip or ""))
    except Exception:
        pass


async def _audit(
    db: AsyncSession,
    *,
    action: str,
    status_text: str,
    user: Optional[User],
    request: Optional[Request],
    meta: Optional[Dict[str, object]] = None,
) -> None:
    """Best‑effort **audit log** insert (safe to fail).

    If the AuditLog model is available, insert a record; otherwise, write a
    structured log. This keeps the router standalone and org‑agnostic.
    """
    try:
        from app.db.models.audit_log import AuditLog  # type: ignore
        if db is not None:
            rec = AuditLog(
                user_id=getattr(user, "id", None),
                request_id=getattr(getattr(request, "state", None), "request_id", None),
                action=action,
                status=status_text,
                ip_address=_client_ip(request),
                user_agent=request.headers.get("user-agent") if request else None,
                metadata_json=meta or {},
            )
            db.add(rec)
            await db.commit()
            return
    except Exception:
        pass  # fall back to log

    # Log fallback (never raises)
    log_extra = {
        "action": action,
        "status": status_text,
        "user_id": str(getattr(user, "id", "-")),
        "ip": _client_ip(request),
        "request_id": getattr(getattr(request, "state", None), "request_id", "-"),
        "meta": meta or {},
    }
    logger.info("audit_event", extra=log_extra)


# ──────────────────────────────────────────────────────────────────────────────
# 🔐 POST /reauth/password — Step‑up with password
# ──────────────────────────────────────────────────────────────────────────────
@router.post(
    "/reauth/password",
    response_model=ReauthTokenResponse,
    summary="Step‑up with password and receive a short‑lived reauth token",
)
@rate_limit("10/minute")
async def reauth_with_password(
    payload: ReauthPasswordRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> ReauthTokenResponse:
    """Re‑authenticate the current session by verifying the **account password**.

    Behavior
    --------
    - Requires an authenticated **access** session (Bearer).
    - Verifies password; on success, mints a **reauth** token (short TTL, default 5 minutes).
    - Binds token to caller’s **session_id**.
    - Guarded by per‑user/IP Redis **anti‑bruteforce** counters and global rate limits.
    - Responses use **no‑store** cache headers to prevent token caching.

    Errors
    ------
    401 invalid/missing credentials, 403 ownership mismatch, 429 too many attempts.
    """
    # [Step 0] Cache hardening (idempotent; safe on every sensitive route)
    set_sensitive_cache(request)
    set_sensitive_cache(response)

    # [Step 1] Ownership & context guard (must be stepping up an **access** token)
    claims = await _extract_access_claims(request)
    ip = _client_ip(request)
    user_id = UUID(str(claims.get("sub")))
    if current_user.id != user_id:
        # Defense‑in‑depth; get_current_user already enforces this
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    # [Step 2] Anti‑bruteforce check
    await _check_and_bump_fail_counters(user_id=user_id, ip=ip, is_mfa=False)

    # [Step 3] Verify password (timing‑safe)
    ok = verify_password(payload.password.get_secret_value(), current_user.hashed_password)
    if not ok:
        await _audit(db, action="REAUTH_PASSWORD", status_text="FAILURE", user=current_user, request=request)
        # Keep counters incremented on failure
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # [Step 4] Bind session context
    session_id = claims.get("session_id") or claims.get("jti")

    # [Step 5] Mint reauth token
    token, ttl = _mint_reauth_token(user_id=user_id, session_id=str(session_id), mfa_authenticated=False)

    # [Step 6] Reset counters & audit success
    await _reset_fail_counters(user_id=user_id, ip=ip, is_mfa=False)
    await _audit(
        db,
        action="REAUTH_PASSWORD",
        status_text="SUCCESS",
        user=current_user,
        request=request,
        meta={"session_id": session_id},
    )

    # [Step 7] Respond
    return ReauthTokenResponse(reauth_token=token, expires_in=ttl)


# ──────────────────────────────────────────────────────────────────────────────
# 🔐 POST /reauth/mfa — Step‑up with TOTP
# ──────────────────────────────────────────────────────────────────────────────
@router.post(
    "/reauth/mfa",
    response_model=ReauthTokenResponse,
    summary="Step‑up with MFA (TOTP) and receive a short‑lived reauth token",
)
@rate_limit("12/minute")
async def reauth_with_mfa(
    payload: ReauthMFARequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> ReauthTokenResponse:
    """Re‑authenticate the current session by verifying a **6–8 digit TOTP**.

    Behavior
    --------
    - Requires an authenticated **access** session (Bearer).
    - Validates TOTP against the user’s enrolled MFA secret; mints a short‑lived **reauth** token.
    - Bound to current `session_id`.
    - Guarded by per‑user/IP Redis **anti‑bruteforce** counters and global rate limits.

    Errors
    ------
    400 no enrollment or bad TOTP format, 401 invalid TOTP, 403 ownership mismatch, 429 too many attempts.
    """
    # [Step 0] Cache hardening
    set_sensitive_cache(request)
    set_sensitive_cache(response)

    # [Step 1] Ownership & context guard
    claims = await _extract_access_claims(request)
    ip = _client_ip(request)
    user_id = UUID(str(claims.get("sub")))
    if current_user.id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    # [Step 2] Ensure MFA enrollment
    if not getattr(current_user, "mfa_enabled", False) or not getattr(current_user, "totp_secret", None):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA not enabled")

    # [Step 3] Anti‑bruteforce check
    await _check_and_bump_fail_counters(user_id=user_id, ip=ip, is_mfa=True)

    # [Step 4] Verify TOTP (use centralized TOTP settings)
    code = _normalize_totp(payload.code)
    totp = generate_totp(current_user.totp_secret)
    ok = bool(totp.verify(code, valid_window=0))  # strict 30s window by default
    if not ok:
        await _audit(db, action="REAUTH_MFA", status_text="FAILURE", user=current_user, request=request)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid code")

    # [Step 5] Bind session context
    session_id = claims.get("session_id") or claims.get("jti")

    # [Step 6] Mint reauth token (tag as MFA‑backed)
    token, ttl = _mint_reauth_token(user_id=user_id, session_id=str(session_id), mfa_authenticated=True)

    # [Step 7] Reset counters & audit success
    await _reset_fail_counters(user_id=user_id, ip=ip, is_mfa=True)
    await _audit(
        db,
        action="REAUTH_MFA",
        status_text="SUCCESS",
        user=current_user,
        request=request,
        meta={"session_id": session_id},
    )

    # [Step 8] Respond
    return ReauthTokenResponse(reauth_token=token, expires_in=ttl)


# ──────────────────────────────────────────────────────────────────────────────
# 🔎 POST /reauth/verify — Is current bearer a fresh reauth?
# ──────────────────────────────────────────────────────────────────────────────
@router.post(
    "/reauth/verify",
    summary="Verify that the presented bearer is a fresh reauth token",
)
@rate_limit("60/minute")
async def verify_reauth(request: Request, response: Response) -> dict:
    """Verify the **current Authorization bearer** is a valid **reauth** token.

    Returns
    -------
    `{ "ok": true, "token_type": "reauth", "expires_in": <seconds> }`

    Errors
    ------
    401 if bearer is missing/invalid or not a reauth token.
    """
    # [Step 0] Cache hardening
    set_sensitive_cache(request)
    set_sensitive_cache(response)

    # [Step 1] Decode current bearer (no access‑only restriction)
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

    # [Step 2] Ensure token_type is reauth
    tok_typ = (claims.get("token_type") or claims.get("typ") or "").lower()
    if tok_typ != "reauth":
        # Note: this endpoint accepts only **reauth** tokens.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not a reauth token")

    # [Step 3] Compute remaining TTL
    now = int(datetime.now(timezone.utc).timestamp())
    exp = int(claims.get("exp", 0))
    remaining = max(0, exp - now)

    # [Step 4] Respond
    return {"ok": True, "token_type": "reauth", "expires_in": remaining}


__all__ = [
    "router",
    "reauth_with_password",
    "reauth_with_mfa",
    "verify_reauth",
]
