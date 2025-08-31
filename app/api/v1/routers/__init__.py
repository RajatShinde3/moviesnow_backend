# app/api/v1/__init__.py

from __future__ import annotations

from fastapi import APIRouter, Depends, Response

# ───────────────────────────────────────────────
# 📦 Feature-Specific Routers (unchanged)
# ───────────────────────────────────────────────
from .auth import register_routes as auth_routes

# Optional: add no-store headers globally (auth-sensitive endpoints already apply this internally)
try:
    from app.security_headers import set_sensitive_cache
    def _no_store_dep(response: Response) -> None:
        # ── [Step 0] Apply cache-hardening headers to API v1 (safe default) ────
        set_sensitive_cache(response)
except Exception:  # pragma: no cover
    def _no_store_dep(response: Response) -> None:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# 🚀 API V1 Master Router (factory)
#     - You can toggle cache headers globally without touching child routers.
#     - Standardized OpenAPI responses for consistency across docs/clients.
# ──────────────────────────────────────────────────────────────────────────────
def build_api_v1_router(*, add_no_store: bool = False) -> APIRouter:
    # ── [Step 1] Create the master router with optional global dependency ─────
    dependencies = [Depends(_no_store_dep)] if add_no_store else None
    router = APIRouter(dependencies=dependencies)

    # ── [Step 2] Canonical responses for better OpenAPI quality ───────────────
    common_responses = {
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        409: {"description": "Conflict"},
        429: {"description": "Too Many Requests"},
        500: {"description": "Internal Server Error"},
    }

    # ── [Step 3] Main Feature Routes (keep prefixes & tags identical) ─────────
    router.include_router(auth_routes.router,           prefix="/auth",           tags=["Auth"],           responses=common_responses)

    return router


# ──────────────────────────────────────────────────────────────────────────────
# 📦 Backwards-compatible export (keeps your existing imports working)
#     Your main app can still do:
#       from app.api.v1 import router as api_v1_router
#       app.include_router(api_v1_router, prefix="/api/v1")
# ──────────────────────────────────────────────────────────────────────────────
router = build_api_v1_router(add_no_store=False)
