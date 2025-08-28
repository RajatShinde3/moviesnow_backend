from __future__ import annotations

"""
Email verification API — hardened, production‑grade
==================================================

Endpoints
---------
GET  /verify-email
    Verify a user's email via one‑time token. Neutral errors, rate‑limited
    in the service, and single‑use within TTL.

POST /resend-verification
    Resend a verification link if the account exists and is not yet verified.
    Neutral response to avoid enumeration; throttled in the service.

Security & DX
-------------
- Applies **sensitive cache headers** (``Cache-Control: no-store``) to responses.
- Delegates logic to the hardened service module
  ``app.services.auth.email_verification_service``.
- Supports ``BackgroundTasks`` for non‑blocking audit + email sending.
"""

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Body, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_async_db
from app.schemas.auth import MessageResponse
from app.security_headers import set_sensitive_cache
from app.services.auth.email_verification_service import (
    verify_email_token,
    resend_verification_email,
)

router = APIRouter(tags=["Email Verification"])


# ─────────────────────────────────────────────────────────────
# ✅ Verify Email
# ─────────────────────────────────────────────────────────────
@router.get("/verify-email", response_model=MessageResponse, summary="Verify email by token")
async def verify_email(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    token: str,
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """Verify a user's email address using a one‑time verification token.

    Notes
    -----
    - The underlying service enforces rate limits and TTL, and clears the token on success.
    - Response is marked **no‑store** to avoid caching sensitive state.
    """
    set_sensitive_cache(response)
    return await verify_email_token(token=token, db=db, request=request, background_tasks=background_tasks)


# ─────────────────────────────────────────────────────────────
# 🔁 Resend Verification Email
# ─────────────────────────────────────────────────────────────
@router.post(
    "/resend-verification",
    response_model=MessageResponse,
    summary="Resend verification link to an email",
)
async def resend_verification(
    response: Response,
    request: Request,
    background_tasks: BackgroundTasks,
    email: str = Body(..., embed=True, description="User email to resend the verification link to."),
    db: AsyncSession = Depends(get_async_db),
) -> MessageResponse:
    """Resend a verification email.

    Security
    --------
    - Neutral message is always returned to avoid account enumeration.
    - Service applies **per‑email/IP rate limits** and stores only a **peppered HMAC**
      digest of the token at rest.
    - Response is marked **no‑store**.
    """
    set_sensitive_cache(response)
    return await resend_verification_email(email=email, db=db, request=request, background_tasks=background_tasks)


__all__ = ["router", "verify_email", "resend_verification"]
