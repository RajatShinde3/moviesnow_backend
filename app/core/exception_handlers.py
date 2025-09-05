from __future__ import annotations

"""
Problem+JSON exception handlers (RFC 7807).

FastAPI integrates these via app/main.py when this module is present.
All HTTP errors are rendered as application/problem+json with a stable schema.
"""

from typing import Dict
from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException


def _problem(title: str, detail: str, status_code: int, request: Request) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "type": "about:blank",
            "title": title,
            "detail": detail,
            "status": status_code,
            "instance": str(request.url),
        },
        media_type="application/problem+json",
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:  # type: ignore
    title = exc.__class__.__name__.replace("Exception", "").strip() or "Error"
    detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return _problem(title, detail, exc.status_code, request)


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:  # type: ignore
    detail = "Validation error"
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "type": "about:blank",
            "title": detail,
            "detail": detail,
            "status": status.HTTP_422_UNPROCESSABLE_ENTITY,
            "instance": str(request.url),
            "errors": exc.errors(),
        },
        media_type="application/problem+json",
    )


async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:  # type: ignore
    # Hide internals; logs elsewhere should capture stack traces.
    return _problem("Internal Server Error", "An unexpected error occurred.", status.HTTP_500_INTERNAL_SERVER_ERROR, request)


__all__ = [
    "http_exception_handler",
    "validation_exception_handler",
    "global_exception_handler",
]

