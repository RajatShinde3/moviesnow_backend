from __future__ import annotations

from typing import Iterable, Optional, Callable

from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.api.http_utils import get_client_ip


class AdminIPAllowlistMiddleware(BaseHTTPMiddleware):
    """Optional IP allowlist for admin routes.

    Enabled when mounted with a non-empty `allowlist`.
    Applies only to paths starting with `admin_prefix`.
    """

    def __init__(self, app: ASGIApp, *, admin_prefix: str, allowlist: Iterable[str]) -> None:
        super().__init__(app)
        self.admin_prefix = admin_prefix.rstrip("/") or "/api/v1/admin"
        self.allow = {ip.strip() for ip in allowlist if str(ip).strip()}

    async def dispatch(self, request, call_next: Callable):
        path = request.url.path
        if self.allow and path.startswith(self.admin_prefix):
            ip = get_client_ip(request)
            if ip not in self.allow:
                return JSONResponse(
                    {"detail": "Admin access restricted by IP allowlist"}, status_code=403
                )
        return await call_next(request)

