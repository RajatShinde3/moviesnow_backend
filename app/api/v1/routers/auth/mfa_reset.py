"""
MFA Reset API — hardened, production-grade
=========================================

Endpoints
---------
POST /mfa/request-mfa-reset
    Begin MFA reset by issuing a one-time, short-lived reset token via email.
    Neutral messaging (no enumeration) and strict rate limiting occur in the
    service. Only a **peppered digest** is stored at rest.

POST /mfa/confirm-mfa-reset
    Validate the reset token, **disable MFA** (single-use, TTL-bound), and
    **invalidate any existing recovery codes** so old codes cannot be reused.

Security & DX
-------------
- **Route-level rate limits** (complements service-side Redis throttles).
- **Sensitive cache headers** applied to responses (``no-store``).
- Non-blocking email + audit via ``BackgroundTasks``.
- Clear OpenAPI summaries and consistent response models.
"""

from fastapi import APIRouter, BackgroundTasks, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import rate_limit
from app.db.session import get_async_db
from app.schemas.auth import MFAResetConfirm, MFAResetRequest, MessageResponse
from app.security_headers import set_sensitive_cache
from app.services.auth.mfa_reset_service import confirm_mfa_reset, request_mfa_reset

router = APIRouter(prefix="/mfa", tags=["MFA"])


# ─────────────────────────────────────────────────────────────
# 🔁 Request MFA Reset
# ─────────────────────────────────────────────────────────────
@router.post(
    "/request-mfa-reset",
    response_model=MessageResponse,
    summary="Start MFA reset (email a one-time link)",
)
@rate_limit("5/minute")
async def request_mfa_reset_handler(
    payload: MFAResetRequest,
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """
    Initiate the MFA reset flow.

    Behavior
    --------
    - Validates input and enforces **per-email & per-IP** rate limits (service).
    - Generates a CSPRNG token and stores only a **peppered HMAC digest**.
    - Sends a reset link via email asynchronously.
    - Always returns a **generic** message to avoid account enumeration.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Delegate to service ─────────────────────────────────────────
    return await request_mfa_reset(payload, db, request, background_tasks)


# ─────────────────────────────────────────────────────────────
# ✅ Confirm MFA Reset
# ─────────────────────────────────────────────────────────────
@router.post(
    "/confirm-mfa-reset",
    response_model=MessageResponse,
    summary="Confirm MFA reset (disable MFA and invalidate recovery codes)",
)
@rate_limit("10/minute")
async def confirm_mfa_reset_handler(
    payload: MFAResetConfirm,
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """
    Confirm the MFA reset using the one-time token.

    Behavior
    --------
    - Enforces **per-IP** verification throttles (service).
    - Validates token by comparing its **peppered digest** within TTL.
    - Atomically **disables MFA** and marks the token **used**.
    - **Invalidates existing recovery code batches** for the user.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Delegate to service ─────────────────────────────────────────
    return await confirm_mfa_reset(payload, db, request, background_tasks)


__all__ = [
    "router",
    "request_mfa_reset_handler",
    "confirm_mfa_reset_handler",
]
