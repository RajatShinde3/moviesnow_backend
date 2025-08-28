# app/core/exception.py
from __future__ import annotations

"""
MoviesNow — Application Exceptions (production-grade, org-free)
===============================================================
A small, consistent layer on top of FastAPI/Starlette's `HTTPException` that
lets us attach structured metadata and integrate cleanly with our JSON error
shape from `app.core.exception_handlers`.

Key ideas
---------
- One base `AppException` that carries `code`, `request_id`, `user_id`, `details`, `extra`.
- Domain exceptions inherit from it and set sane defaults.
- Helpers to render a canonical body (`to_problem`) compatible with our handlers.
- Zero breaking changes for callers already catching `HTTPException`.

Usage
-----
    raise PermissionDeniedException(permission="content:delete", role="VIEWER")

    # Or create a typed app error directly
    raise AppException(status_code=409, message="Email already registered", code=40901, details={"field":"email"})
"""

from typing import Any, Dict, Optional

from fastapi import HTTPException, status

__all__ = [
    "AppException",
    "PermissionDeniedException",
    "InvalidTokenException",
]


# ──────────────────────────────────────────────────────────────
# 📦 Core: AppException
# ──────────────────────────────────────────────────────────────
class AppException(HTTPException):
    """Base application-level exception with optional metadata.

    Attributes
    -----------
    status_code : int
        HTTP status code (e.g., 400/401/403/404/409/422/500).
    message : str
        Human-readable error message (serialized as `detail` as well).
    code : int
        Optional internal/typed error code. Defaults to `status_code`.
    request_id : str | None
        Optional request correlation id (middleware adds it to the response body).
    user_id : str | None
        User id for auditing/context.
    details : dict | list | str | None
        Machine-readable details (e.g., validation errors, constraints, ids).
    extra : dict | None
        Additional non-sensitive metadata to surface to clients.
    headers : dict | None
        Optional headers (e.g., `{"WWW-Authenticate": "Bearer"}`).
    """

    def __init__(
        self,
        *,
        status_code: int,
        message: str,
        code: Optional[int] = None,
        request_id: Optional[str] = None,
        user_id: Optional[str] = None,
        details: Optional[Any] = None,
        extra: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=message, headers=headers)
        self.code: int = int(code or status_code)
        self.message: str = message
        self.request_id: Optional[str] = request_id
        self.user_id: Optional[str] = user_id
        self.details: Optional[Any] = details
        self.extra: Dict[str, Any] = extra or {}

    # ── [Helper] Canonical body used by handlers ───────────────────────────
    def to_problem(self, *, fallback_request_id: Optional[str] = None) -> Dict[str, Any]:
        """Return a dict matching our problem-like JSON shape."""
        body: Dict[str, Any] = {
            "error": True,
            "message": self.message,
            "code": self.code,
            "request_id": self.request_id or fallback_request_id or "N/A",
        }
        if self.details is not None:
            body["details"] = self.details
        # Avoid leaking obvious secrets if someone passed them in `extra`.
        extra_sanitized = dict(self.extra) if self.extra else {}
        for k in ("token", "authorization", "password", "secret"):
            extra_sanitized.pop(k, None)
        body.update(extra_sanitized)
        return body


# ──────────────────────────────────────────────────────────────
# 🔐 Authorization/Role domain exceptions (generic)
# ──────────────────────────────────────────────────────────────
class PermissionDeniedException(AppException):
    """Raised when a user lacks a required permission."""

    def __init__(
        self,
        *,
        permission: str,
        role: str,
        request_id: Optional[str] = None,
        user_id: Optional[str] = None,
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            message=f"Permission '{permission}' denied for role '{role}'",
            code=status.HTTP_403_FORBIDDEN,
            request_id=request_id,
            user_id=user_id,
            details=details or {"permission": permission, "role": role},
        )


# ──────────────────────────────────────────────────────────────
# 🔑 Auth/Token exceptions
# ──────────────────────────────────────────────────────────────
class InvalidTokenException(AppException):
    """Raised for invalid or expired tokens (401 by default)."""

    def __init__(
        self,
        *,
        detail: str = "Invalid or expired token",
        status_code: int = status.HTTP_401_UNAUTHORIZED,
        headers: Optional[Dict[str, str]] = None,
        request_id: Optional[str] = None,
        user_id: Optional[str] = None,
        details: Optional[Any] = None,
    ) -> None:
        # Encourage `WWW-Authenticate` header when dealing with access tokens
        headers = headers or {"WWW-Authenticate": "Bearer"}
        super().__init__(
            status_code=status_code,
            message=detail,
            code=status_code,
            request_id=request_id,
            user_id=user_id,
            details=details,
            headers=headers,
        )
