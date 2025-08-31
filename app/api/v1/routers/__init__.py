"""Aggregate v1 routers for easy inclusion.

Exports both individual routers and a combined `router` that includes them
under a consistent path layout.
"""

from fastapi import APIRouter

from .public import discovery_router
from .user import me_router
from .player import sessions_router
from .ops import observability_router
from .admin import router as admin_router


# Combined v1 router
router = APIRouter()

# Public discovery endpoints -> mounted as-is (e.g., /titles, /search)
router.include_router(discovery_router)

# User endpoints -> grouped under /user (e.g., /user/me)
router.include_router(me_router, prefix="/user")

# Player telemetry -> already namespaced (/player/sessions)
router.include_router(sessions_router)

# Operational endpoints (/healthz, /readyz, /metrics, etc.)
router.include_router(observability_router)

# Admin endpoints under /admin
router.include_router(admin_router, prefix="/admin")


__all__ = [
    "router",
    "discovery_router",
    "me_router",
    "sessions_router",
    "observability_router",
]
