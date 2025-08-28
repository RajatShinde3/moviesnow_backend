"""
MFA API — hardened, production-grade
===================================

Endpoints
---------
POST /mfa/enable
    Start MFA setup. Generates a TOTP secret and provisioning URI (QR) and
    returns them to the client. **Does not** enable MFA yet.

POST /mfa/verify
    Verify a TOTP code to **finalize** MFA setup. On success, enables MFA
    and returns a short-lived confirmation token (optional). See notes below
    for initial recovery-code generation.

POST /mfa/disable
    Disable MFA after verifying the user's password (step-up).

Security & DX
-------------
- Route-level **rate limits** complement service-level Redis limits.
- **Sensitive cache headers** applied (`no-store`) for all endpoints.
- Delegates business logic to ``app.services.auth.mfa_service`` (audited).
- Consistent response models and clear summaries for OpenAPI.
- Ready to integrate with **Reauth** and **Recovery Codes** flows.

Notes
-----
If you want to auto-generate **recovery codes** immediately after `/mfa/verify`,
enable the `AUTO_GENERATE_RECOVERY_CODES_ON_VERIFY` flag in settings and ensure
the recovery-code service is available (see service file).
"""

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.db.models.user import User
from app.db.session import get_async_db
from app.schemas.auth import (
    DisableMFARequest,
    EnableMFAResponse,
    MFAEnableResponse,
    MessageResponse,
    VerifyMFARequest,
)
from app.security_headers import set_sensitive_cache
from app.services.auth.mfa_service import disable_mfa, enable_mfa, verify_mfa

router = APIRouter(prefix="/mfa", tags=["MFA"])  # grouped under /mfa


# ─────────────────────────────────────────────────────────────
# 🔐 Enable MFA Setup (provision secret)
# ─────────────────────────────────────────────────────────────
@router.post("/enable", response_model=EnableMFAResponse, summary="Start MFA setup and get provisioning data")
@rate_limit("5/minute")
async def enable_mfa_route(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
) -> EnableMFAResponse:
    """
    Initiate MFA setup by generating a TOTP secret + provisioning URI.

    Notes
    -----
    - Returns a **one-time** secret and QR provisioning URI; the client should
      show these once and never store them.
    - MFA is **not** enabled until ``POST /mfa/verify`` succeeds.
    - Headers are set to **no-store** to prevent caching.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Delegate to service ─────────────────────────
    return await enable_mfa(current_user, db, request)


# ─────────────────────────────────────────────────────────────
# ✅ Verify MFA Code and finalize
# ─────────────────────────────────────────────────────────────
@router.post("/verify", response_model=MFAEnableResponse, summary="Verify TOTP and enable MFA")
@rate_limit("10/minute")
async def verify_mfa_route(
    request: Request,
    payload: VerifyMFARequest,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
) -> MFAEnableResponse:
    """
    Verify a TOTP code and enable MFA for the user.

    Security
    --------
    - Per-user rate limits enforced in the service with Redis; this route-level
      limiter adds another guard.
    - Never logs raw codes. Response is marked **no-store**.
    """
    # ── [Step 0] Cache hardening ──────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Delegate to service ─────────────────────
    return await verify_mfa(payload.code, current_user, db, request)


# ─────────────────────────────────────────────────────────────
# 🚫 Disable MFA (password-gated)
# ─────────────────────────────────────────────────────────────
@router.post("/disable", response_model=MessageResponse, summary="Disable MFA after verifying password")
@rate_limit("3/minute")
async def disable_mfa_route(
    request: Request,
    payload: DisableMFARequest,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """
    Disable MFA for the current user.

    The service validates the password (timing-safe) and clears the TOTP secret.
    Response headers are **no-store** to prevent sensitive data caching.
    """
    # ── [Step 0] Cache hardening ──────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Delegate to service ──────────────────
    return await disable_mfa(payload.password, current_user, db, request)


__all__ = ["router", "enable_mfa_route", "verify_mfa_route", "disable_mfa_route"]
