# app/api/v1/auth/authentication.py
from __future__ import annotations

"""
Authentication API — MoviesNow (org‑free, production‑grade)
==========================================================

Endpoints
---------
POST /auth/login
    Email+password sign‑in. If the user has MFA enabled, returns an MFA
    challenge. Otherwise returns access+refresh tokens.

POST /auth/mfa-login
    Completes the MFA flow: validates the short‑lived MFA token + TOTP and
    issues access+refresh tokens.

Security & DX
-------------
- **No org context** — pure account authentication.
- **Route rate limits** complement Redis throttles inside services.
- **Sensitive cache headers** applied on token‑issuing routes (no‑store).
- **Auth logic delegated** to hardened services in `app.services.auth.login_service`.
- Neutral errors; thorough audit is handled inside the service layer.

Notes
-----
- We return Pydantic models directly so headers set on `response` (e.g.,
  `Cache-Control: no-store`) are preserved by FastAPI.
"""

from fastapi import APIRouter, Body, Depends, Request, Response

from app.core.limiter import rate_limit
from app.db.session import get_async_db
from app.schemas.auth import (
    LoginRequest,
    MFAChallengeResponse,
    MFALoginRequest,
    TokenResponse,
)
from app.security_headers import set_sensitive_cache
from app.services.auth.login_service import login_user, login_with_mfa
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/auth", tags=["Authentication"])  # org‑free auth


# ──────────────────────────────────────────────────────────────
# 🔐 POST /auth/login — Email + Password (MFA‑aware)
# ──────────────────────────────────────────────────────────────
@router.post("/login", response_model=TokenResponse | MFAChallengeResponse, summary="Email + password login")
@rate_limit("5/minute")
async def login(
    request: Request,
    response: Response,
    payload: LoginRequest = Body(...),
    db: AsyncSession = Depends(get_async_db),
) -> TokenResponse | MFAChallengeResponse:
    """Authenticate with email/password.

    Behavior
    --------
    - If the account has **MFA enabled**, returns an `MFAChallengeResponse` containing
      a short‑lived token for the next step (`/auth/mfa-login`).
    - Otherwise returns **access** + **refresh** tokens.

    Security
    --------
    - Marks the response **no-store** (so tokens are not cached).
    - Per‑email and per‑IP throttles executed inside `login_user`.
    """
    # [Step 0] Cache hardening
    set_sensitive_cache(response)

    # [Step 1] Delegate to login service (handles audit, throttles, IP, UA)
    result = await login_user(payload=payload, db=db, request=request)

    # [Step 2] Return the model so our headers are preserved
    return result


# ──────────────────────────────────────────────────────────────
# 🔐 POST /auth/mfa-login — Finalize MFA with challenge + TOTP
# ──────────────────────────────────────────────────────────────
@router.post("/mfa-login", response_model=TokenResponse, summary="Finalize MFA and issue tokens")
@rate_limit("5/minute")
async def mfa_login(
    request: Request,
    response: Response,
    payload: MFALoginRequest = Body(...),
    db: AsyncSession = Depends(get_async_db),
) -> TokenResponse:
    """Validate MFA challenge + TOTP and issue tokens.

    Security
    --------
    - Marks the response **no-store** (so tokens are not cached).
    - Rate limiting and audit handled in service.
    """
    # [Step 0] Cache hardening
    set_sensitive_cache(response)

    # [Step 1] Delegate to service (handles verification, audit, token minting)
    result = await login_with_mfa(payload, db, request)

    # [Step 2] Return the model so our headers are preserved
    return result


__all__ = ["router", "login", "mfa_login"]
