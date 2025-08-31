
"""
Admin Authentication
====================

Admin/Superuser-only authentication endpoints with hardened security:
- POST /admin/login   : email+password login (MFA-aware) restricted to ADMIN/SUPERUSER
- POST /admin/reauth  : step-up reauthentication (password or TOTP) for admins
- POST /admin/logout  : logout via refresh token (idempotent)

Practices
---------
- Neutral errors to avoid user enumeration/leaking role memberships
- Strict rate limiting (SlowAPI decorators + Redis budgets)
- Redis idempotency for login (best-effort)
- Session lineage + metadata in Redis (session JTI, IP, UA)
- Sensitive cache headers (no-store)
- Thorough audit logging (best-effort, never blocks flows)
"""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Optional, Union
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from jose import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.limiter import rate_limit
from app.core.redis_client import redis_wrapper
from app.core.security import (
    verify_password,
    create_refresh_token,
    create_access_token,
    generate_totp,
    get_current_user,
)
from app.core.jwt import get_bearer_token, decode_token
from app.db.models.user import User
from app.db.session import get_async_db
from app.schemas.auth import (
    LoginRequest,
    TokenResponse,
    MFAChallengeResponse,
    ReauthTokenResponse,
    LogoutRequest,
)
from app.schemas.enums import OrgRole as UserRole
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event, AuditEvent
from app.services.auth.logout_service import logout_user
from pydantic import BaseModel, Field, field_validator, model_validator
import app.utils.redis_utils as redis_utils
from app.utils.redis_utils import increment_attempts, reset_attempts

# Reuse internal helpers from login_service to ensure behavior parity
from app.services.auth.login_service import (
    _now_utc,  # type: ignore
    _client_ip as _login_client_ip,  # type: ignore
    _register_session_and_meta,  # type: ignore
    _push_activity_event,  # type: ignore
)


router = APIRouter(tags=["Admin Auth"])


def _norm_email(email: str) -> str:
    return (email or "").strip().lower()


def _is_admin(user: User) -> bool:
    return getattr(user, "role", None) in {UserRole.ADMIN, UserRole.SUPERUSER}


# ─────────────────────────────────────────────────────────────────────────────
# POST /admin/login — Admin-only login (MFA-aware)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/login", response_model=Union[TokenResponse, MFAChallengeResponse], summary="Admin login (email+password, MFA-aware)")
@rate_limit("10/minute")
async def admin_login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
):
    """
    Authenticate with email and password; only ADMIN/SUPERUSER are allowed.

    Behavior
    --------
    - Neutral errors for invalid credentials or non-admin accounts.
    - Enforces account gates (verified, active).
    - If MFA is enabled, returns `MFAChallengeResponse` with a short-lived token.
    - Otherwise, returns `TokenResponse` with access + refresh bound to a session.
    """
    set_sensitive_cache(response)

    now = _now_utc()
    email_norm = _norm_email(payload.email)
    client_ip = _login_client_ip(request)

    # Per-identifier and per-IP throttling (best-effort)
    try:
        await redis_utils.enforce_rate_limit(
            key_suffix=f"adminlogin:email:{sha256(email_norm.encode()).hexdigest()}",
            seconds=60,
            max_calls=5,
            error_message="Too many attempts. Please try again shortly.",
        )
        await redis_utils.enforce_rate_limit(
            key_suffix=f"adminlogin:ip:{client_ip}",
            seconds=60,
            max_calls=20,
            error_message="Too many attempts. Please try again shortly.",
        )
    except Exception:
        pass

    # Idempotency replay (best-effort)
    idem_key = request.headers.get("Idempotency-Key")
    if idem_key:
        try:
            snap = await redis_utils.idempotency_get(f"idem:adminlogin:{idem_key}")
            if snap:
                return TokenResponse(**snap) if "access_token" in snap else MFAChallengeResponse(**snap)
        except Exception:
            pass

    # Lookup user (neutral failure)
    user = (await db.execute(select(User).where(User.email == email_norm))).scalar_one_or_none()
    if not user:
        await log_audit_event(
            db,
            user=None,
            action=AuditEvent.LOGIN,
            status="ADMIN_LOGIN_USER_NOT_FOUND",
            request=request,
            meta_data={"email_sha256": sha256(email_norm.encode()).hexdigest()},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    # Password verify (neutral failure)
    if not verify_password(payload.password, user.hashed_password):
        await log_audit_event(db, user=user, action=AuditEvent.LOGIN, status="ADMIN_INVALID_PASSWORD", request=request)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    # Account gates
    if not getattr(user, "is_verified", False):
        await log_audit_event(db, user=user, action=AuditEvent.LOGIN, status="ADMIN_EMAIL_NOT_VERIFIED", request=request)
        if getattr(settings, "ADMIN_LOGIN_NEUTRAL_ERRORS", True):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not verified")
    if not getattr(user, "is_active", True):
        await log_audit_event(db, user=user, action=AuditEvent.LOGIN, status="ADMIN_ACCOUNT_DEACTIVATED", request=request)
        if getattr(settings, "ADMIN_LOGIN_NEUTRAL_ERRORS", True):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")

    # Role guard: neutralize to avoid role enumeration
    if not _is_admin(user):
        await log_audit_event(db, user=user, action=AuditEvent.LOGIN, status="ADMIN_ROLE_REQUIRED", request=request)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    # Enforce MFA policy for admins when required
    if getattr(settings, "ADMIN_REQUIRE_MFA", True) and not getattr(user, "mfa_enabled", False):
        await log_audit_event(db, user=user, action=AuditEvent.LOGIN, status="ADMIN_MFA_REQUIRED_BUT_DISABLED", request=request)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MFA required for admin login")

    # MFA challenge path
    if getattr(user, "mfa_enabled", False):
        from uuid import uuid4 as _uuid4
        claims = {
            "sub": str(user.id),
            "token_type": "mfa",
            "typ": "mfa",
            "type": "mfa_token",
            "mfa_pending": True,
            "jti": str(_uuid4()),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        }
        iss = getattr(settings, "JWT_ISSUER", None)
        aud = getattr(settings, "JWT_AUDIENCE", None)
        if iss:
            claims["iss"] = iss
        if aud:
            claims["aud"] = aud
        mfa_token = jwt.encode(claims, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=settings.JWT_ALGORITHM)
        await log_audit_event(db, user=user, action=AuditEvent.LOGIN, status="ADMIN_MFA_REQUIRED", request=request)
        resp = MFAChallengeResponse(mfa_token=mfa_token)
        if idem_key:
            try:
                await redis_utils.idempotency_set(f"idem:adminlogin:{idem_key}", resp.model_dump(), ttl_seconds=600)
            except Exception:
                pass
        return resp

    # Refresh first (session lineage), then access
    refresh_data = await create_refresh_token(user.id)
    session_id = refresh_data.get("session_id") or refresh_data["jti"]

    await _register_session_and_meta(user.id, refresh_data, session_id, request)
    from app.services.token_service import store_refresh_token
    await store_refresh_token(
        db=db,
        user_id=user.id,
        token=refresh_data["token"],
        jti=refresh_data["jti"],
        expires_at=refresh_data["expires_at"],
        parent_jti=refresh_data.get("parent_jti"),
        ip_address=(request.client.host if request.client else None),
    )

    access_token = await create_access_token(user_id=user.id, session_id=session_id, mfa_authenticated=True)
    await _push_activity_event(user.id, action="ADMIN_LOGIN", session_id=session_id, request=request, jti=refresh_data["jti"])
    await log_audit_event(db, user=user, action=AuditEvent.LOGIN, status="ADMIN_SUCCESS", request=request)

    resp = TokenResponse(access_token=access_token, refresh_token=refresh_data["token"], token_type="bearer")
    if idem_key:
        try:
            await redis_utils.idempotency_set(f"idem:adminlogin:{idem_key}", resp.model_dump(), ttl_seconds=600)
        except Exception:
            pass
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# POST /admin/reauth — Step-up for admin (password or TOTP)
# ─────────────────────────────────────────────────────────────────────────────
class AdminReauthPasswordRequest(BaseModel):
    """Password-based step-up."""
    password: str = Field(..., min_length=1, description="Account password for step-up")


class AdminReauthMFARequest(BaseModel):
    """TOTP-based step-up."""
    code: str = Field(..., description="6–8 digit TOTP code")

    @model_validator(mode="after")
    def _validate_code(self):
        if not self.code.isdigit() or not (6 <= len(self.code) <= 8):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code format")
        return self


@router.post("/reauth", response_model=ReauthTokenResponse, summary="Admin step-up reauthentication (password or TOTP)")
@rate_limit("30/minute")
async def admin_reauth(
    request: Request,
    response: Response,
    payload: Union[AdminReauthPasswordRequest, AdminReauthMFARequest],
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    set_sensitive_cache(response)

    if not _is_admin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")

    # Extract access token claims for session lineage (best-effort)
    session_id: Optional[str] = None
    try:
        claims = await decode_token(get_bearer_token(request), expected_types=["access"], verify_revocation=False)
        session_id = claims.get("session_id")
    except Exception:
        session_id = None

    # Password path
    if hasattr(payload, "password"):
        ip = _login_client_ip(request)
        if not verify_password(getattr(payload, "password"), current_user.hashed_password):
            # Increment failure counters (per user and per IP)
            try:
                await increment_attempts(key_suffix=f"reauth:admin:pw:{current_user.id}", limit=10, ttl=600)
                await increment_attempts(key_suffix=f"reauth:admin:ip:{ip}", limit=20, ttl=600)
            except Exception:
                pass
            await log_audit_event(db, user=current_user, action=AuditEvent.MFA_LOGIN, status="ADMIN_REAUTH_BAD_PASSWORD", request=request)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        token, ttl = _mint_admin_reauth_token(current_user.id, session_id=session_id, mfa_authenticated=False)
        # Reset failure counters on success
        try:
            await reset_attempts(key_suffix=f"reauth:admin:pw:{current_user.id}")
            await reset_attempts(key_suffix=f"reauth:admin:ip:{ip}")
        except Exception:
            pass
        await log_audit_event(db, user=current_user, action=AuditEvent.MFA_LOGIN, status="ADMIN_REAUTH_PASSWORD_OK", request=request)
        return ReauthTokenResponse(reauth_token=token, expires_in=ttl)

    # TOTP path
    if hasattr(payload, "code"):
        ip = _login_client_ip(request)
        if not getattr(current_user, "mfa_enabled", False) or not getattr(current_user, "totp_secret", None):
            await log_audit_event(db, user=current_user, action=AuditEvent.MFA_LOGIN, status="ADMIN_REAUTH_MFA_NOT_ENABLED", request=request)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA not enabled")
        totp = generate_totp(current_user.totp_secret)
        try:
            if not totp.verify(getattr(payload, "code"), valid_window=1):
                try:
                    await increment_attempts(key_suffix=f"reauth:admin:mfa:{current_user.id}", limit=10, ttl=600)
                    await increment_attempts(key_suffix=f"reauth:admin:ip:{ip}", limit=20, ttl=600)
                except Exception:
                    pass
                await log_audit_event(db, user=current_user, action=AuditEvent.MFA_LOGIN, status="ADMIN_REAUTH_BAD_CODE", request=request)
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid code")
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code format")

        token, ttl = _mint_admin_reauth_token(current_user.id, session_id=session_id, mfa_authenticated=True)
        try:
            await reset_attempts(key_suffix=f"reauth:admin:mfa:{current_user.id}")
            await reset_attempts(key_suffix=f"reauth:admin:ip:{ip}")
        except Exception:
            pass
        await log_audit_event(db, user=current_user, action=AuditEvent.MFA_LOGIN, status="ADMIN_REAUTH_MFA_OK", request=request)
        return ReauthTokenResponse(reauth_token=token, expires_in=ttl)

    # Defensive: should not reach here due to validation
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Provide password or code")


def _mint_admin_reauth_token(user_id: UUID, *, session_id: Optional[str], mfa_authenticated: bool) -> tuple[str, int]:
    now = datetime.now(timezone.utc)
    ttl = int(getattr(settings, "REAUTH_TOKEN_EXPIRE_MINUTES", 5)) * 60
    exp = now + timedelta(seconds=ttl)
    claims = {
        "sub": str(user_id),
        "exp": exp,
        "iat": now,
        "nbf": now,
        "jti": sha256(f"reauth:{user_id}:{now.isoformat()}".encode()).hexdigest()[:32],
        "token_type": "reauth",
        "mfa_authenticated": bool(mfa_authenticated),
    }
    if session_id:
        claims["session_id"] = str(session_id)
    iss = getattr(settings, "JWT_ISSUER", None)
    aud = getattr(settings, "JWT_AUDIENCE", None)
    if iss:
        claims["iss"] = iss
    if aud:
        claims["aud"] = aud
    token = jwt.encode(claims, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=settings.JWT_ALGORITHM)
    return token, ttl


# ─────────────────────────────────────────────────────────────────────────────
# POST /admin/logout — Idempotent logout for admin
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/logout", response_model=dict, summary="Admin logout (revoke refresh token)")
@rate_limit("20/minute")
async def admin_logout(
    payload: LogoutRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    set_sensitive_cache(response)
    if not _is_admin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    # Delegate to logout service (idempotent, hardened)
    return await logout_user(payload.refresh_token, db, request)
