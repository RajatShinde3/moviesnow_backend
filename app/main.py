# app/main.py
from __future__ import annotations

"""
# MoviesNow API — Application Entrypoint (FastAPI)

Production-grade ASGI application factory and lifecycle for the MoviesNow
(streaming + secure downloads) backend.

## Design Goals
- Deterministic, testable **app factory** (`create_app`) with explicit lifespan.
- Safe, explicit **middleware order**:
  1) request id → 2) (optional) org context → 3) security headers/HTTPS →
  4) CORS → 5) gzip → 6) rate limits → 7) strip `Server` header.
- Centralized exception handling (kept compatible with custom handlers if present).
- Hardened defaults: no `Server` leakage, strict CORS, CSP nonce, HSTS.
- Graceful local/dev behavior (best-effort infra connections, never crash on import).

## Probes
- `/healthz` — liveness (process up).
- `/readyz` — readiness (quick DB/Redis checks with short timeouts).
"""

from contextlib import asynccontextmanager
from typing import AsyncIterator, Callable
import logging
import os

from fastapi import FastAPI, Request
from starlette.middleware.gzip import GZipMiddleware
from starlette.responses import JSONResponse, Response

# -- Logging bootstrap (Loguru + stdlib intercept) ----------------------------
# Importing sets up handlers/format; ignore the symbol with _ alias.
try:
    from app.core import logger as _logsetup  # noqa: F401
except Exception:
    pass

# -- Middlewares & security ---------------------------------------------------
from app.middleware.request_id import RequestIDMiddleware
from app.security_headers import install_security, configure_cors
from app.middleware.admin_ip_allowlist import AdminIPAllowlistMiddleware

# -- Rate limiting ------------------------------------------------------------
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
try:
    # Preferred: use your installer (handles storage/compat)
    from app.core.limiter import install_rate_limiter, rate_limit_exempt
except Exception:  # pragma: no cover
    install_rate_limiter = None  # type: ignore
    def rate_limit_exempt():  # type: ignore
        def _noop(fn):
            return fn
        return _noop

# -- Settings & optional custom exception handlers ----------------------------
from app.core.config import settings

logger = logging.getLogger("moviesnow")
logger.setLevel(logging.INFO)


# ─────────────────────────────────────────────────────────────────────────────
# 🔄 Lifespan: startup & shutdown
# ─────────────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Application lifecycle manager.

    Startup:
        - Log a startup banner.
        - Best-effort connect to Redis (non-fatal on failure).

    Shutdown:
        - Best-effort dispose DB async engine (if present).
        - Best-effort close Redis connection (if present).
    """
    logger.info("✅ MoviesNow API starting up")

    # Connect Redis (best-effort)
    try:
        from app.core.redis_client import redis_wrapper  # type: ignore
        try:
            await redis_wrapper.connect()
            logger.info("🔌 Redis connected")
        except Exception:
            logger.exception("Redis connect failed (continuing in degraded mode)")
    except Exception:
        pass

    try:
        yield
    finally:
        # Dispose DB engine (best-effort)
        try:
            from app.db.session import async_engine  # type: ignore
        except Exception:
            async_engine = None  # type: ignore
        if async_engine is not None:
            try:
                await async_engine.dispose()
                logger.info("🛑 Database engine disposed")
            except Exception:
                logger.exception("Error disposing DB engine")

        # Close Redis (best-effort)
        try:
            from app.core.redis_client import redis_wrapper  # type: ignore
            try:
                await redis_wrapper.close()
                logger.info("🛑 Redis connection closed")
            except Exception:
                logger.exception("Error closing Redis client")
        except Exception:
            pass

        logger.info("🛑 MoviesNow API shutting down")


# ─────────────────────────────────────────────────────────────────────────────
# 🏗️ App factory
# ─────────────────────────────────────────────────────────────────────────────
def create_app() -> FastAPI:
    """
    Build and configure the FastAPI app instance.

    Returns:
        FastAPI: fully wired application with middleware, exception handlers,
        routers, and health/readiness endpoints.
    """
    # Docs toggles
    enable_docs = getattr(settings, "ENABLE_DOCS", True)
    docs_url = "/docs" if enable_docs else None
    redoc_url = "/redoc" if enable_docs else None
    openapi_url = "/openapi.json" if enable_docs else None

    app = FastAPI(
        title=getattr(settings, "PROJECT_NAME", "MoviesNow API"),
        version=getattr(settings, "VERSION", "1.0.0"),
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )

    # ── Middlewares (order matters) ─────────────────────────────────────────
    app.add_middleware(RequestIDMiddleware)  # 1) Correlation ID

    # 2) Security headers + HTTPS redirect (config via env)
    install_security(app)

    # 3) CORS (allow-list/regex via env; exposes X-Request-ID, ETag, etc.)
    configure_cors(app)

    # 3.5) Optional Admin IP allowlist (path-scoped)
    try:
        allow_csv = os.getenv("ADMIN_IP_ALLOWLIST", "").strip()
        if allow_csv:
            allow = [p.strip() for p in allow_csv.split(",") if p.strip()]
            api_prefix = getattr(settings, "API_V1_STR", "/api/v1")
            admin_prefix = f"{api_prefix.rstrip('/')}/admin"
            app.add_middleware(AdminIPAllowlistMiddleware, admin_prefix=admin_prefix, allowlist=allow)
            logger.info("Admin IP allowlist enabled for %s", admin_prefix)
    except Exception:
        logger.exception("Failed to enable Admin IP allowlist middleware")

    # 4) GZip (safe defaults)
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    # 5) Rate limiter (SlowAPI middleware + 429 handler)
    try:
        if install_rate_limiter:
            install_rate_limiter(app)
            app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        else:
            logger.warning("⚠️ RateLimiter not installed (module missing)")
    except Exception:
        logger.exception("Failed to install rate limiter")

    # Optional maintenance schedulers (best-effort)
    try:
        # Token cleanup scheduler (expired/revoked)
        from app.utils.token_cleanup import start_token_cleanup_scheduler  # type: ignore
        if os.getenv("TOKEN_CLEANUP_SCHEDULER", "true").lower() == "true":
            start_token_cleanup_scheduler()
    except Exception:
        logger.info("Token cleanup scheduler not started")

    try:
        # JWKS rotation/prune scheduler
        from app.utils.jwks_rotation import start_jwks_scheduler  # type: ignore
        if os.getenv("JWKS_SCHEDULER", "true").lower() == "true":
            start_jwks_scheduler()
    except Exception:
        logger.info("JWKS scheduler not started")

    # 6) Strip/override Server header at the end of the chain
    @app.middleware("http")
    async def _strip_server_header(request: Request, call_next: Callable) -> Response:
        """Remove the `Server` header to avoid leaking implementation details."""
        response: Response = await call_next(request)
        try:
            if "server" in response.headers:
                del response.headers["server"]
            # Optionally set a neutral identifier:
            # response.headers["Server"] = "MoviesNow"
        except Exception:
            pass
        return response

    # ── Optional custom exception handlers (if your project provides them) ──
    try:
        from app.core.exception_handlers import (  # type: ignore
            http_exception_handler,
            validation_exception_handler,
            global_exception_handler,
        )
        from fastapi import HTTPException
        from fastapi.exceptions import RequestValidationError
        from starlette.exceptions import HTTPException as StarletteHTTPException

        app.add_exception_handler(StarletteHTTPException, http_exception_handler)  # type: ignore[arg-type]
        app.add_exception_handler(HTTPException, http_exception_handler)           # type: ignore[arg-type]
        app.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore[arg-type]
        app.add_exception_handler(Exception, global_exception_handler)             # type: ignore[arg-type]
    except Exception:
        # Fall back to FastAPI defaults if your custom handlers aren't available.
        pass

    # ── Routers (versioned API) ─────────────────────────────────────────────
    try:
        # Include the aggregated v1 router from the routers subpackage.
        from app.api.v1.routers import router as api_v1_router  # type: ignore
        app.include_router(
            api_v1_router,
            prefix=getattr(settings, "API_V1_STR", "/api/v1"),
            tags=["v1"],
        )
    except Exception:
        logger.warning("No v1 router found at app.api.v1.routers; continuing without API routes")

    # Non-versioned security & discovery endpoints (well-known, oauth2, idempotency)
    try:
        from app.api.well_known import router as well_known_router  # type: ignore
        app.include_router(well_known_router)
    except Exception:
        logger.warning("well-known router not available; skipping OIDC/JWKS endpoints")

    # ── Meta endpoints ──────────────────────────────────────────────────────
    @app.get("/healthz", tags=["meta"])  # health endpoints should not be rate limited
    @rate_limit_exempt()
    async def healthz() -> dict[str, bool]:
        """
        Liveness probe.

        Returns:
            {"ok": True} when the process is responsive. No external checks.
        """
        return {"ok": True}

    @app.get("/readyz", tags=["meta"])  # readiness should not be rate limited
    @rate_limit_exempt()
    async def readyz() -> dict[str, object]:
        """
        Readiness probe (quick DB + Redis checks, best-effort).

        Returns:
            dict with per-dependency booleans and aggregated `ready` flag.
        """
        db_ok = False
        redis_ok = False

        # Redis: if not connected, attempt a quick ping.
        try:
            from app.core.redis_client import redis_wrapper  # type: ignore
            redis_ok = await redis_wrapper.is_connected()
            if not redis_ok:
                try:
                    await redis_wrapper.connect()
                    redis_ok = await redis_wrapper.is_connected()
                except Exception:
                    redis_ok = False
        except Exception:
            redis_ok = False

        # DB: quick "SELECT 1" with short timeout
        try:
            from app.db.session import async_engine  # type: ignore
            from sqlalchemy import text
            async with async_engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False

        return {
            "ready": bool(db_ok and redis_ok),
            "checks": {"db": db_ok, "redis": redis_ok},
        }

    @app.get("/", include_in_schema=False)
    async def root() -> JSONResponse:
        """Minimal root that points to docs (when enabled)."""
        body = {
            "name": getattr(settings, "PROJECT_NAME", "MoviesNow API"),
            "docs": app.docs_url or "",
            "version": getattr(settings, "VERSION", "1.0.0"),
        }
        return JSONResponse(body)

    return app


# ─────────────────────────────────────────────────────────────────────────────
# 🚀 Module-level ASGI app for Uvicorn/Gunicorn
# ─────────────────────────────────────────────────────────────────────────────
app = create_app()
__all__ = ["create_app", "app"]


# Local dev runner (prefer: `uvicorn app.main:app --reload`)
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "1") == "1",
        workers=int(os.getenv("WORKERS", "1")),
        log_level=os.getenv("LOG_LEVEL", "info"),
    )
