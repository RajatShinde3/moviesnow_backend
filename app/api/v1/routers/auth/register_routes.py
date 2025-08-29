# app/api/v1/auth/register_routes.py
from __future__ import annotations

# ── [Step 0] Imports kept local to avoid circulars & speed cold starts ────────
from fastapi import APIRouter, Depends, Response

# Child routers (your existing modules; unchanged)
from . import (
    signup,
    login,
    mfa,
    email_verification,
    password_reset,
    account_deactivation,
    account_deletion,
    mfa_reset,
    reactivation,
    refresh_logout,
    audit_log,
    recovery_codes,
    reauth,
    trusted_devices
)

# Optional: add no-store headers to every auth response via dependency
try:
    from app.security_headers import set_sensitive_cache
    def _no_store_dep(response: Response) -> None:
        # ── [Step 1] Apply cache-hardening headers for auth endpoints ─────────
        set_sensitive_cache(response)
except Exception:
    # If security headers helper isn’t present, fall back to a no-op dependency
    def _no_store_dep(response: Response) -> None:  # pragma: no cover
        return None


# ──────────────────────────────────────────────────────────────────────────────
# ⚙️  Factory: build an auth router with consistent defaults
#     - base_prefix: mount everything under a shared prefix if desired
#     - add_no_store: apply Cache-Control: no-store on all included routes
#     - default_responses: standardized OpenAPI docs for common auth errors
# ──────────────────────────────────────────────────────────────────────────────
def build_auth_router(
    *,
    base_prefix: str = "",              # e.g., "" (if mounted at /api/v1/auth in main)
    add_no_store: bool = True,          # apply cache hardening by default
) -> APIRouter:
    # ── [Step 2] Router skeleton with optional global dependency ──────────────
    dependencies = [Depends(_no_store_dep)] if add_no_store else None
    router = APIRouter(prefix=base_prefix, dependencies=dependencies, tags=["Auth"])

    # ── [Step 3] Canonical responses for auth endpoints (OpenAPI quality) ─────
    common_responses = {
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        429: {"description": "Too Many Requests"},
        500: {"description": "Internal Server Error"},
    }

    # ── [Step 4] Register core auth first (logical grouping) ──────────────────
    router.include_router(signup.router,        responses=common_responses)          # /signup
    router.include_router(login.router,         responses=common_responses)          # /login, /mfa-login, /switch-org, /my-orgs
    router.include_router(refresh_logout.router, responses=common_responses)         # /refresh-token, /logout, /revoke-token

    # ── [Step 5] MFA & verification flows ─────────────────────────────────────
    router.include_router(mfa.router,                 responses=common_responses)    # /mfa/enable, /mfa/verify, /mfa/disable
    router.include_router(mfa_reset.router,           responses=common_responses)    # /mfa/request-mfa-reset, /mfa/confirm-mfa-reset
    router.include_router(email_verification.router,  responses=common_responses)    # /verify-email, /resend-verification

    # ── [Step 6] Password & account lifecycle ─────────────────────────────────
    router.include_router(password_reset.router,      responses=common_responses)    # /request-reset, /confirm-reset
    router.include_router(account_deactivation.router, responses=common_responses)   # /request-deactivation-otp, /deactivate-user
    router.include_router(account_deletion.router,    responses=common_responses)    # /request-deletion-otp, /delete-user
    router.include_router(reactivation.router,        responses=common_responses)    # /request-reactivation, /reactivate

    # ── [Step 7] User info & admin-ish views ──────────────────────────────────
    router.include_router(audit_log.router,           responses=common_responses)    # /audit-logs/audit

    router.include_router(recovery_codes.router,      responses=common_responses)    
    router.include_router(reauth.router,              responses=common_responses)    
    router.include_router(trusted_devices.router,     responses=common_responses)    

    return router


# ──────────────────────────────────────────────────────────────────────────────
# 📦 Backwards-compatible export: keep `router` name so existing imports work
#     Your main app can still do: app.include_router(router, prefix="/api/v1/auth")
#     Or adopt the factory for different mount points/environments.
# ──────────────────────────────────────────────────────────────────────────────
router = build_auth_router()
