# app/core/exception_handlers.py
from __future__ import annotations

"""
MoviesNow — Exception Handlers (production-grade)
-------------------------------------------------
Structured, secure, and consistent exception handling for FastAPI/Starlette.

Goals
-----
- One JSON shape for all errors (problem-like), with `request_id` correlation
- No secret leakage; optionally include debug traces based on env
- Preserve HTTP semantics (status code, headers like WWW-Authenticate)
- Helpful, bounded validation details (422)
- Minimal dependencies; pure FastAPI/Starlette

Environment knobs
-----------------
- `APP_DEBUG` → when set to truthy ("1", "true"), include exception class name
  and minimal traceback info in logs; response stays generic for 500s.
"""

from typing import Any, Dict, List, Optional
import logging
import os
import traceback

from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY

logger = logging.getLogger("moviesnow")
_DEBUG = os.getenv("APP_DEBUG", "").lower() in {"1", "true", "yes"}


# ─────────────────────────────────────────────────────────────
# 🆔 Request Helper
# ─────────────────────────────────────────────────────────────
def get_request_id(request: Request) -> str:
    """Return the current request id or "N/A".

    The `RequestIDMiddleware` attaches `request.state.request_id`.
    """
    return getattr(request.state, "request_id", "N/A")


# ─────────────────────────────────────────────────────────────
# 🧱 Response shaping helper
# ─────────────────────────────────────────────────────────────
def _problem_json(
    *,
    request: Request,
    status_code: int,
    message: str,
    code: Optional[int] = None,
    details: Optional[Any] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the canonical error body used across handlers.

    Keys:
    - error: bool (always True)
    - message: human readable summary
    - code: HTTP status code
    - request_id: correlation id
    - details: optional machine-readable info (e.g., validation)
    - ...(any vetted extra fields)
    """
    body: Dict[str, Any] = {
        "error": True,
        "message": str(message or "Error"),
        "code": int(code or status_code),
        "request_id": get_request_id(request),
    }
    if details is not None:
        body["details"] = details
    if extra:
        # Drop any obviously sensitive keys before merging
        for k in ("token", "authorization", "password", "secret"):
            extra.pop(k, None)
        body.update(extra)
    return body


# ─────────────────────────────────────────────────────────────
# ⚠️ HTTP Exception Handler
# ─────────────────────────────────────────────────────────────
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle `HTTPException` with structured JSON."""
    log_extra = {"request_id": get_request_id(request), "path": request.url.path, "status": exc.status_code}
    logger.warning(f"HTTPException: {exc.detail}", extra=log_extra)

    body = _problem_json(
        request=request,
        status_code=exc.status_code,
        message=str(exc.detail or "HTTP error"),
        code=exc.status_code,
    )

    # Preserve headers like `WWW-Authenticate`
    headers = getattr(exc, "headers", None)
    return JSONResponse(status_code=exc.status_code, content=body, headers=headers)


# ─────────────────────────────────────────────────────────────
# ❌ Validation Error Handler (422)
# ─────────────────────────────────────────────────────────────
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Return 422 with compact, bounded validation details."""
    # Normalize and bound details
    errors: List[Dict[str, Any]] = []
    for e in exc.errors()[:100]:  # hard cap to avoid huge payloads
        errors.append(
            {
                "loc": e.get("loc"),
                "msg": e.get("msg"),
                "type": e.get("type"),
            }
        )

    # Log (sanitized)
    logger.warning(
        "Validation error",
        extra={"request_id": get_request_id(request), "count": len(errors), "path": request.url.path},
    )

    # Shape response
    body = _problem_json(
        request=request,
        status_code=HTTP_422_UNPROCESSABLE_ENTITY,
        message="Validation failed",
        code=HTTP_422_UNPROCESSABLE_ENTITY,
        details=errors,
    )
    return JSONResponse(status_code=HTTP_422_UNPROCESSABLE_ENTITY, content=body)


# ─────────────────────────────────────────────────────────────
# 🔥 Global Exception Handler (Fallback 500)
# ─────────────────────────────────────────────────────────────
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all handler: log details, return generic 500 body.

    In debug mode we log the traceback, but we never include it in the response.
    """
    req_id = get_request_id(request)
    tb = traceback.format_exc() if _DEBUG else None
    log_extra = {"request_id": req_id, "path": request.url.path, "exc": exc.__class__.__name__}

    if _DEBUG:
        logger.exception("Unhandled exception", extra={**log_extra, "trace": tb})
    else:
        logger.exception("Unhandled exception", extra=log_extra)

    body = _problem_json(
        request=request,
        status_code=500,
        message="Internal Server Error",
        code=500,
    )
    return JSONResponse(status_code=500, content=body)
