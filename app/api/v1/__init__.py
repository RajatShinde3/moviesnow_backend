"""Versioned API (v1) aggregator.

Expose an aggregated FastAPI router via the symbol `routers` so that
`from app.api.v1 import routers as api_v1_router` returns an APIRouter
ready to be included under the configured API prefix.
"""

from .routers import router as routers

__all__ = ["routers"]

