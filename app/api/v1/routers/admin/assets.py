"""Admin assets endpoints wrapper (v1).

Re-exports the legacy `app.api.v1.routers.admin_assets.router` so imports can
standardize on `app.api.v1.routers.admin.assets` while tests and existing
code keep working.
"""

from app.api.v1.routers.admin_assets import router  # noqa: F401

__all__ = ["router"]

