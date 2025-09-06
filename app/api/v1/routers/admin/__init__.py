from __future__ import annotations

"""
Admin router package (v1)
=========================

Provides a consistent structure for admin endpoints by domain:
- assets, titles, series, sessions, staff, taxonomy, auth
- api_keys, bundles, downloads, jwks, cdn_cookies

Design
------
• Each submodule defines its own `APIRouter` (with security, rate limits, tags).
• This package aggregates them into a single `router` export.
• Mount with a base path in your app:
    app.include_router(admin_v1.router, prefix="/api/v1/admin")

Notes
-----
• We add common 401/403/429 response docs at include-time for a uniform OpenAPI.
• No extra prefix/dependencies are forced here; domain routers stay in control.
"""

# ─────────────────────────────────────────────────────────────────────────────
# 🧭 Imports
# ─────────────────────────────────────────────────────────────────────────────

from fastapi import APIRouter, status
from typing import Dict, Any, Iterable, Optional

from .assets import router as assets_router
from .titles import router as titles_router
from .series import router as series_router
from .sessions import router as sessions_router
from .staff import router as staff_router
from .taxonomy import router as taxonomy_router
from .auth import router as auth_router
from .api_keys import router as api_keys_router
from .bundles import router as bundles_router
from .downloads import router as downloads_router
from .jwks import router as jwks_router
from .cdn_cookies import router as cdn_router


# ─────────────────────────────────────────────────────────────────────────────
# 📋 Common OpenAPI responses (docs-only; behavior unchanged)
# ─────────────────────────────────────────────────────────────────────────────

COMMON_ADMIN_RESPONSES: Dict[int, Dict[str, Any]] = {
    status.HTTP_401_UNAUTHORIZED: {"description": "Unauthorized (admin/MFA)"},
    status.HTTP_403_FORBIDDEN: {"description": "Forbidden"},
    status.HTTP_429_TOO_MANY_REQUESTS: {"description": "Rate limit exceeded"},
}


# ─────────────────────────────────────────────────────────────────────────────
# 🧱 Default aggregated router
# ─────────────────────────────────────────────────────────────────────────────

router = APIRouter()  # callers mount with prefix="/api/v1/admin"

# Include domain routers without extra prefix; each subrouter owns its paths/tags.
router.include_router(assets_router, responses=COMMON_ADMIN_RESPONSES)
router.include_router(titles_router, responses=COMMON_ADMIN_RESPONSES)
router.include_router(series_router, responses=COMMON_ADMIN_RESPONSES)
router.include_router(sessions_router, responses=COMMON_ADMIN_RESPONSES)
router.include_router(staff_router, responses=COMMON_ADMIN_RESPONSES)
router.include_router(taxonomy_router, responses=COMMON_ADMIN_RESPONSES)
router.include_router(auth_router, responses=COMMON_ADMIN_RESPONSES)
router.include_router(api_keys_router, responses=COMMON_ADMIN_RESPONSES)
router.include_router(bundles_router, responses=COMMON_ADMIN_RESPONSES)
router.include_router(downloads_router, responses=COMMON_ADMIN_RESPONSES)
router.include_router(jwks_router, responses=COMMON_ADMIN_RESPONSES)
router.include_router(cdn_router, responses=COMMON_ADMIN_RESPONSES)


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Optional factory (for future customization/prefixing at build time)
# ─────────────────────────────────────────────────────────────────────────────

def build_admin_router(
    *,
    extra_responses: Optional[Dict[int, Dict[str, Any]]] = None,
    include: Optional[Iterable[APIRouter]] = None,
) -> APIRouter:
    """Create a fresh admin router aggregate.

    Parameters
    ----------
    extra_responses:
        Additional OpenAPI response docs to merge onto the common set.
    include:
        Subset/sequence of domain routers to include (defaults to all).

    Returns
    -------
    APIRouter
        A new router ready to be mounted by the application.
    """
    r = APIRouter()
    responses = {**COMMON_ADMIN_RESPONSES, **(extra_responses or {})}
    subrouters = list(include) if include is not None else [
        assets_router,
        titles_router,
        series_router,
        sessions_router,
        staff_router,
        taxonomy_router,
        auth_router,
        api_keys_router,
        bundles_router,
        downloads_router,
        jwks_router,
        cdn_router,
    ]
    for sr in subrouters:
        r.include_router(sr, responses=responses)
    return r


__all__ = [
    "router",
    "build_admin_router",
    "assets_router",
    "titles_router",
    "series_router",
    "sessions_router",
    "staff_router",
    "taxonomy_router",
    "auth_router",
    "api_keys_router",
    "bundles_router",
    "downloads_router",
    "jwks_router",
    "cdn_router",
]
