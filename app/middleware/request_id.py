# app/middleware/request_id.py
from __future__ import annotations

"""
# MoviesNow — Request ID Middleware (ASGI, production-grade)

- Reuses client-supplied `X-Request-ID` / `X-Correlation-ID` (when valid).
- Optionally accepts W3C `traceparent` header (extracts 32-hex trace id) if enabled.
- Generates UUIDv4 when absent/invalid.
- Injects into `request.state.request_id` and response header.
- Adds `request_id` to **loguru** context for the entire request lifetime.
- Pure ASGI middleware (no BaseHTTPMiddleware pitfalls).

## Env / Config
- `REQUEST_ID_HEADER_NAME` (default: `X-Request-ID`)
- `REQUEST_ID_TRUST_CLIENT_IDS` ("true"/"false"; default: "true")
- `REQUEST_ID_MAX_LENGTH` (default: 128)
- `REQUEST_ID_ACCEPT_TRACEPARENT` ("false" by default) — if true, may use W3C trace id

## Usage
    from app.middleware.request_id import RequestIDMiddleware, get_request_id
    app.add_middleware(RequestIDMiddleware)

    @app.get("/ping")
    async def ping(request: Request):
        rid = get_request_id(request)
        return {"ok": True, "request_id": rid}
"""

import os
import re
import uuid
from typing import Optional

from loguru import logger
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send


# ─────────────────────────────────────────────────────────────
# ⚙️ Config (env-driven, with sane defaults)
# ─────────────────────────────────────────────────────────────

HEADER_NAME = os.getenv("REQUEST_ID_HEADER_NAME", "X-Request-ID")
TRUST_CLIENT_IDS = os.getenv("REQUEST_ID_TRUST_CLIENT_IDS", "true").lower() == "true"
MAX_ID_LENGTH = int(os.getenv("REQUEST_ID_MAX_LENGTH", "128"))
ACCEPT_TRACEPARENT = os.getenv("REQUEST_ID_ACCEPT_TRACEPARENT", "false").lower() == "true"

_UUID_V4_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
_TRACE_ID_32HEX_RE = re.compile(r"^[0-9a-fA-F]{32}$")  # w3c trace-id (128-bit), not all zeros per spec


class RequestIDMiddleware:
    """Lightweight ASGI middleware to manage a per-request correlation ID.

    Notes:
        - Uses UUIDv4 for generated IDs.
        - Accepts client IDs only if `TRUST_CLIENT_IDS` is true and they match UUIDv4.
        - If `ACCEPT_TRACEPARENT` is true, uses `traceparent`'s 32-hex trace-id when present and valid.
        - Validation is defensive against log injection: strict format & length.
    """

    def __init__(self, app: ASGIApp, header_name: str = HEADER_NAME) -> None:
        self.app = app
        self.header_name = header_name

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        headers = Headers(scope=scope)
        req_id = self._choose_request_id(headers)

        # Expose to downstream handlers
        state = scope.setdefault("state", {})
        state["request_id"] = req_id

        # Ensure all logs for this request include request_id
        async def _send_wrapper(message):
            # On response start, attach header idempotently
            if message.get("type") == "http.response.start":
                raw = message.setdefault("headers", [])  # list[tuple[bytes, bytes]]
                name_bytes = self.header_name.encode("latin-1")
                # remove any existing variant (case-insensitive) to avoid duplicates
                message["headers"] = [(k, v) for (k, v) in raw if k.lower() != name_bytes.lower()]
                message["headers"].append((name_bytes, req_id.encode("latin-1")))
            return await send(message)

        with logger.contextualize(request_id=req_id):
            try:
                await self.app(scope, receive, _send_wrapper)
            except Exception:
                logger.exception("[RequestID] Unhandled exception during request processing")
                raise

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _choose_request_id(self, headers: Headers) -> str:
        """Return a safe request id from headers or generate a UUIDv4."""
        if TRUST_CLIENT_IDS:
            # 1) Preferred custom header, then alias
            incoming = headers.get(self.header_name) or headers.get("X-Correlation-ID")
            if incoming:
                candidate = incoming.strip()
                if 0 < len(candidate) <= MAX_ID_LENGTH and _UUID_V4_RE.fullmatch(candidate):
                    # Validate true UUIDv4
                    try:
                        val = uuid.UUID(candidate)
                        if val.version == 4:
                            return str(val)
                    except Exception:
                        pass

            # 2) Optional: W3C traceparent ("00-<trace-id>-<span-id>-<flags>")
            if ACCEPT_TRACEPARENT:
                tp = headers.get("traceparent")
                # Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
                if tp and len(tp) <= 128:
                    parts = tp.split("-")
                    if len(parts) >= 3:
                        trace_id = parts[1]
                        # w3c forbids all-zero trace-id; keep strict 32-hex
                        if _TRACE_ID_32HEX_RE.fullmatch(trace_id) and trace_id != ("0" * 32):
                            # Return in a UUID-like group for readability (no actual UUID guarantee)
                            # e.g., 32hex -> 8-4-4-4-12
                            as_uuidish = f"{trace_id[0:8]}-{trace_id[8:12]}-{trace_id[12:16]}-{trace_id[16:20]}-{trace_id[20:32]}"
                            return as_uuidish.lower()

        # 3) Fallback to a new UUIDv4
        return str(uuid.uuid4())


# ─────────────────────────────────────────────────────────────
# 🔎 Convenience accessor
# ─────────────────────────────────────────────────────────────

def get_request_id(request) -> str:
    """
    Fetch the current request id from `request.state` (returns empty string if absent).

    Args:
        request: FastAPI/Starlette Request.

    Returns:
        str: request id if present, else "".
    """
    return getattr(getattr(request, "state", object()), "request_id", "") or ""


__all__ = ["RequestIDMiddleware", "get_request_id"]
