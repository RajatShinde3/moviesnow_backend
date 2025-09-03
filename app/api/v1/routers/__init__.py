"""
🧭✨ MoviesNow • API v1 Router Aggregator
========================================

Exports both the **combined `router`** (ready to include) and each **individual
sub-router** so callers can mount them as needed.

Why this file?
--------------
- 🧱 **One place** to compose public, user, player, ops, delivery, and admin routes.
- 🧭 **Predictable layout**: stable prefixes for user and admin surfaces.
- 🧰 **Composable**: expose a `build_v1_router()` factory for custom mount points.

Quick usage
-----------
    from app.api.v1 import router as v1_router
    app.include_router(v1_router, prefix="/api/v1")

Or with the factory:

    from app.api.v1 import build_v1_router
    v1 = build_v1_router()
    app.include_router(v1, prefix="/api/v1")

Security notes
--------------
- 🔐 This layer is a pure aggregator; **auth & rate limits live in child routers**.
- 🧊 If a child router sets sensitive cache headers, those are preserved here.
"""

from fastapi import APIRouter

from .public import discovery_router, bundles_router, downloads_router
from .user import me_router
from .player import sessions_router
from .ops import observability_router
from .delivery import router as delivery_router
from .admin import router as admin_router


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Factory: build a combined v1 router with stable path layout
#     - Keeps import-time side effects minimal.
#     - Makes local testing vs prod mounting trivial.
# ─────────────────────────────────────────────────────────────────────────────
def build_v1_router() -> APIRouter:
    """
    Compose the API v1 surface into a single `APIRouter`.

    Returns
    -------
    fastapi.APIRouter
        A router that includes:
          • Public discovery (no extra prefix)
          • User endpoints under `/user`
          • Player sessions (as defined in module)
          • Observability/ops (as defined in module)
          • Admin endpoints under `/admin`
          • Delivery endpoints (no extra prefix)
    """
    r = APIRouter()

    # 🛰️ Public discovery endpoints → mounted as-is (e.g., /titles, /search)
    r.include_router(discovery_router)
    r.include_router(downloads_router)
    r.include_router(bundles_router)
    r.include_router(me_router, prefix="/user")
    r.include_router(sessions_router)
    r.include_router(observability_router)
    r.include_router(admin_router, prefix="/admin")
    r.include_router(delivery_router)

    return r


# ─────────────────────────────────────────────────────────────────────────────
# 📦 Backwards-compatible default export
#     Most apps will do: app.include_router(router, prefix="/api/v1")
# ─────────────────────────────────────────────────────────────────────────────
router = build_v1_router()


__all__ = [
    # Combined
    "router",
    "build_v1_router",
    # Individuals (for bespoke mounts/testing)
    "discovery_router",
    "bundles_router",
    "downloads_router",
    "me_router",
    "sessions_router",
    "observability_router",
    "delivery_router",
    "admin_router",
]
