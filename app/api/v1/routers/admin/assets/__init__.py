# app/api/v1/routers/admin/assets/__init__.py
from __future__ import annotations

"""
🧊🎛️ MoviesNow • Admin Assets Router (Aggregator)
=================================================

This module assembles all **Admin Assets** sub-routers (artwork, streams,
subtitles, trailers, uploads, etc.) under a single parent router with
consistent cache hardening and standardized OpenAPI error responses.

Why this file?
--------------
- 🧱 **Single mount point** for all Admin Assets endpoints.
- 🧰 **Global cache hardening** via a lightweight dependency that sets
  `Cache-Control: no-store` for sensitive admin operations.
- 🧭 **Unified OpenAPI responses** so error docs are consistent across modules.
- 🧩 **Composable**: expose a factory to mount at any base prefix.

Quick use
---------
    from app.api.v1.routers.admin.assets import router as admin_assets_router
    app.include_router(admin_assets_router, prefix="/api/v1/admin/assets")

Or create a custom-configured instance:

    from app.api.v1.routers.admin.assets import build_auth_router
    admin_router = build_auth_router(base_prefix="/api/v1/admin/assets", add_no_store=True)
    app.include_router(admin_router)

Security notes
--------------
- 🛡️ This layer is *not* an auth gate itself; each child router enforces
  ADMIN/SUPERUSER + MFA independently.
- 🚫 Responses are marked **no-store** by default to avoid caching signed URLs
  or other sensitive material.

"""

# ── [Step 0] Imports kept local to avoid circulars & speed cold starts ────────
from fastapi import APIRouter, Depends, Response

# Child routers (kept unchanged; each module owns its endpoints & tags)
from . import (
    artwork,        
    bulk,           
    cdn_delivery,  
    meta,          
    streams,        
    subtitles,     
    trailers,     
    uploads,        
    validation,    
    video,        
)

# ── [Step 1] Optional global "no-store" dependency for cache hardening ───────
try:
    from app.security_headers import set_sensitive_cache

    def _no_store_dep(response: Response) -> None:
        """
        🧊 Cache Hardening Hook
        Sets `Cache-Control: no-store` (+ related) on every response routed
        through this aggregator to reduce the risk of caching sensitive URLs.
        """
        set_sensitive_cache(response)

except Exception:
    # If security headers helper isn’t present, fall back to a no-op dependency
    def _no_store_dep(response: Response) -> None:  # pragma: no cover
        return None


# ──────────────────────────────────────────────────────────────────────────────
# ⚙️  Router Factory
#     Build a parent router with consistent defaults and rich OpenAPI docs.
#     - base_prefix  : mount everything under a shared prefix (e.g., "/admin/assets")
#     - add_no_store : apply Cache-Control: no-store on all included routes
# ──────────────────────────────────────────────────────────────────────────────
def build_auth_router(
    *,
    base_prefix: str = "",       # e.g., "/api/v1/admin/assets"
    add_no_store: bool = True,   # apply cache hardening by default
) -> APIRouter:
    """
    🧱 Build Admin Assets Router

    Parameters
    ----------
    base_prefix : str
        A path prefix to apply to *all* included child routers. Useful when the
        aggregator isn’t mounted directly at the final API root.
    add_no_store : bool
        If True, adds a lightweight dependency that sets `Cache-Control: no-store`
        on every response (defense-in-depth for signed URLs & admin actions).

    Returns
    -------
    fastapi.APIRouter
        A composed router that includes all Admin Assets sub-routers with
        standardized error responses.

    Design
    ------
    - 🎛️ **Consistent tags**: Defaults the parent router tag to "Admin Assets".
    - 🧩 **Loose coupling**: Each child router keeps its own internal validation,
      rate limits, and permissions; this aggregator doesn’t override them.
    - 🧭 **Uniform error surface**: Common error codes documented once, reused for
      all includes to keep the OpenAPI spec concise and readable.
    """
    # ── [Step 2] Router skeleton with optional global dependency ──────────────
    dependencies = [Depends(_no_store_dep)] if add_no_store else None
    router = APIRouter(prefix=base_prefix, dependencies=dependencies, tags=["Admin Assets"])

    # ── [Step 3] Canonical responses for assets endpoints (OpenAPI quality) ───
    common_responses = {
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        409: {"description": "Conflict"},
        429: {"description": "Too Many Requests"},
        500: {"description": "Internal Server Error"},
        503: {"description": "Service Unavailable"},
    }

    # ── [Step 4] Register child routers (logical grouping with 3D-icon notes) ─
    router.include_router(artwork.router,      responses=common_responses)
    router.include_router(bulk.router,         responses=common_responses)
    router.include_router(cdn_delivery.router, responses=common_responses)
    router.include_router(meta.router,         responses=common_responses)
    router.include_router(streams.router,      responses=common_responses)
    router.include_router(subtitles.router,    responses=common_responses)
    router.include_router(trailers.router,     responses=common_responses)
    router.include_router(uploads.router,      responses=common_responses)
    router.include_router(validation.router,   responses=common_responses)
    router.include_router(video.router,        responses=common_responses)

    return router


# ──────────────────────────────────────────────────────────────────────────────
# 📦 Backwards-compatible export
#     Your main app can still do: app.include_router(router, prefix="/api/v1/admin/assets")
#     Or adopt the factory for different mount points/environments.
# ──────────────────────────────────────────────────────────────────────────────
router = build_auth_router()

__all__ = ["build_auth_router", "router"]
