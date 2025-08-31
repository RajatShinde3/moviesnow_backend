"""Admin router package (v1).

Provides a consistent structure for admin endpoints by domain:
- assets, titles, series, sessions, staff, taxonomy, auth

Initially, each module re-exports the legacy top-level router to preserve
imports and routes; over time, implementations can migrate into these files.
"""

from fastapi import APIRouter

from .assets import router as assets_router
from .titles import router as titles_router
from .series import router as series_router
from .sessions import router as sessions_router
from .staff import router as staff_router
from .taxonomy import router as taxonomy_router
from .auth import router as auth_router
from .api_keys import router as api_keys_router
from .genres import router as genres_router


router = APIRouter()

# Include domain routers without extra prefix; callers can mount with 
# `prefix="/api/v1/admin"` to get the standard admin base path.
router.include_router(assets_router)
router.include_router(titles_router)
router.include_router(series_router)
router.include_router(sessions_router)
router.include_router(staff_router)
router.include_router(taxonomy_router)
router.include_router(auth_router)
router.include_router(api_keys_router)
router.include_router(genres_router)

__all__ = [
    "router",
    "assets_router",
    "titles_router",
    "series_router",
    "sessions_router",
    "staff_router",
    "taxonomy_router",
    "auth_router",
    "api_keys_router",
    "genres_router",
]

