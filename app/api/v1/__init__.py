"""Versioned API (v1) aggregator.

Expose an aggregated FastAPI router via `app.api.v1.routers.router`.
Prefer importing directly from the routers subpackage to avoid name
shadowing with the package name:

    from app.api.v1.routers import router as api_v1_router
"""

# Note: avoid `routers = ...` here to prevent shadowing the `routers` package
# which breaks dotted-path resolution used by tests (monkeypatch, etc.).

__all__ = []

