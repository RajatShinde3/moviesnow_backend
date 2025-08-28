
"""
Password Reset API — hardened, production‑grade
==============================================

Endpoints
---------
POST /request-reset
    Start a password‑reset flow by emailing a one‑time OTP. Neutral responses
    (no enumeration), strict throttling, and **peppered HMAC** storage are
    enforced in the service.

POST /confirm-reset
    Verify the OTP and set a new password atomically. Single‑use OTP and
    optional session revocations are handled in the service.

Security & DX
-------------
- Route‑level rate limits that complement Redis throttles inside the service.
- **Sensitive cache headers** applied (``Cache-Control: no-store``).
- Delegates to ``app.services.auth.password_reset_service``.
"""

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import rate_limit
from app.db.session import get_async_db
from app.schemas.auth import (
    MessageResponse,
    PasswordResetConfirm,
    PasswordResetEmailRequest,
)
from app.security_headers import set_sensitive_cache
from app.services.auth.password_reset_service import (
    request_password_reset,
    reset_password,
)

router = APIRouter(tags=["Password Reset"])  # grouped with other auth routes


# ─────────────────────────────────────────────────────────────
# 🔑 Request Password Reset OTP
# ─────────────────────────────────────────────────────────────
@router.post(
    "/request-reset",
    response_model=MessageResponse,
    summary="Email a one‑time OTP for password reset",
)
@rate_limit("5/minute")
async def request_password_reset_route(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: PasswordResetEmailRequest,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """Initiate password reset.

    Behavior
    --------
    - Validates email format, enforces per‑email/IP throttles, and caps daily OTPs.
    - Stores only **hashed** OTPs (peppered HMAC); plaintext is emailed to the user.
    - Returns a **generic** success message to prevent account enumeration.
    - Response is marked **no‑store**.
    """
    set_sensitive_cache(response)
    return await request_password_reset(
        email=payload.email,
        db=db,
        request=request,
        background_tasks=background_tasks,
    )


# ─────────────────────────────────────────────────────────────
# 🔒 Confirm Password Reset OTP
# ─────────────────────────────────────────────────────────────
@router.post(
    "/confirm-reset",
    response_model=MessageResponse,
    summary="Verify OTP and set a new password",
)
@rate_limit("10/minute")
async def confirm_password_reset_route(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: PasswordResetConfirm,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """Finalize password reset after OTP validation.

    The service applies per‑IP and per‑user throttles, verifies the **digest** of
    the OTP within its TTL, and updates the password atomically.
    """
    set_sensitive_cache(response)
    return await reset_password(
        email=payload.email,
        otp_code=payload.otp,
        new_password=payload.new_password,
        db=db,
        request=request,
        background_tasks=background_tasks,
    )


__all__ = [
    "router",
    "request_password_reset_route",
    "confirm_password_reset_route",
]
