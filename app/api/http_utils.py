from __future__ import annotations

"""
HTTP utilities shared by routers:
- ID sanitization, client IP resolution
- Lightweight token bucket rate limiter (per-process)
- API key enforcement and admin checks
- Webhook signature verification helpers

Note: production deployments should prefer centralized, Redis-backed rate
limiting (see app.core.limiter) and infrastructure-level request filtering.
"""

import hashlib
import hmac
import os
import re
import time
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request, Response, status
from fastapi.responses import JSONResponse


_SANITIZE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def sanitize_title_id(title_id: str) -> str:
    if _SANITIZE_ID_RE.match(title_id) or re.match(r"^[0-9a-fA-F-]{8,36}$", title_id):
        return title_id
    raise HTTPException(status_code=400, detail="Invalid title_id format")


def get_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


class _TokenBucket:
    def __init__(self, rate: int, per_seconds: int):
        self.rate = rate
        self.per = per_seconds
        self.tokens = rate
        self.updated = time.monotonic()

    def allow(self, amount: int = 1) -> bool:
        now = time.monotonic()
        elapsed = now - self.updated
        self.tokens = min(self.rate, self.tokens + (elapsed * self.rate / self.per))
        self.updated = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


_rate_buckets: Dict[str, _TokenBucket] = {}


def rate_limit(
    request: Request,
    response: Response,
    limit: int = 120,
    window_seconds: int = 60,
):
    """Simple per-IP+path token bucket.

    Replace with a Redis-backed limiter in production to work across
    processes/instances or use app.core.limiter for SlowAPI integration.
    """
    ip = get_client_ip(request)
    key = f"{ip}:{request.url.path}"
    bucket = _rate_buckets.get(key)
    if not bucket:
        bucket = _TokenBucket(limit, window_seconds)
        _rate_buckets[key] = bucket
    allowed = bucket.allow(1)
    response.headers["X-RateLimit-Limit"] = str(limit)
    response.headers["X-RateLimit-Remaining"] = str(max(0, int(bucket.tokens)))
    response.headers["X-RateLimit-Window"] = str(window_seconds)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
        )


def enforce_public_api_key(request: Request):
    """Optional header-based API key enforcement for public endpoints."""
    required = os.environ.get("PUBLIC_API_KEY")
    if not required:
        return
    provided = (
        request.headers.get("x-api-key")
        or request.headers.get("X-API-Key")
        or request.query_params.get("api_key")
    )
    if not provided or not hmac.compare_digest(str(provided), str(required)):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def json_no_store(payload: Any, status_code: int = 200) -> JSONResponse:
    resp = JSONResponse(content=payload, status_code=status_code)
    resp.headers["Cache-Control"] = "no-store"
    return resp


def require_admin(request: Request):
    """Require admin privileges.

    Strategy:
      1) If `ADMIN_API_KEY` is set, require it via `X-Admin-Key` header.
      2) Else, try `get_current_user` and accept if the user has attributes/keys
         indicating admin: is_superuser/is_admin/role == 'admin'.
      3) As a last resort, require `X-Admin: true` header when `ALLOW_DEV_AUTH` is enabled.
    """
    admin_key = os.environ.get("ADMIN_API_KEY")
    if admin_key:
        provided = request.headers.get("x-admin-key") or request.headers.get("X-Admin-Key")
        if not provided or not hmac.compare_digest(str(provided), str(admin_key)):
            raise HTTPException(status_code=401, detail="Invalid or missing admin key")
        return

    user = None
    try:
        user = get_current_user(request)  # type: ignore
    except Exception:
        user = None
    if user is not None:
        if isinstance(user, dict):
            if user.get("is_superuser") or user.get("is_admin") or user.get("role") == "admin":
                return
        else:
            if getattr(user, "is_superuser", False) or getattr(user, "is_admin", False) or getattr(user, "role", None) == "admin":
                return
    # Dev fallback
    if os.environ.get("ALLOW_DEV_AUTH") in {"1", "true", "True"} and (
        request.headers.get("x-admin") == "true" or request.headers.get("X-Admin") == "true"
    ):
        return
    raise HTTPException(status_code=403, detail="Admin privileges required")


from app.core.cache import TTLCache  # re-export for compatibility


async def verify_webhook_signature(
    request: Request,
    *,
    secret_env: str,
    header_name: str = "X-Signature",
    scheme: str = "sha256=",
) -> bool:
    """Verify HMAC signature of webhook request body.

    - Reads secret from `secret_env` (env var name). If not set, verification is skipped.
    - Expects signature header like `sha256=hexhash` (configurable via `scheme`).
    - Returns True when valid or when secret is missing; False when present and mismatch.
    """
    secret = os.environ.get(secret_env)
    if not secret:
        return True
    sig = request.headers.get(header_name) or request.headers.get(header_name.lower())
    if not sig or not sig.startswith(scheme):
        return False
    body = await request.body()
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig[len(scheme) :], mac)


# -------------------------
# Current user resolution
# -------------------------


def resolve_get_current_user():
    """Attempt to resolve the project's get_current_user dependency.

    Tries a few common locations. If missing, provides a dev-only fallback
    that reads `X-User-Id`/`X-User-Email` when `ALLOW_DEV_AUTH` is true.
    """
    candidates = [
        ("app.api.deps", "get_current_user"),
        ("app.api.deps", "get_current_active_user"),
        ("app.core.auth", "get_current_user"),
        ("app.core.security", "get_current_user"),
    ]
    for mod, attr in candidates:
        try:
            module = __import__(mod, fromlist=[attr])
            func = getattr(module, attr)
            return func
        except Exception:
            continue

    # Dev fallback: only enabled when ALLOW_DEV_AUTH is set
    def dev_user(request: Request):
        if os.environ.get("ALLOW_DEV_AUTH") not in {"1", "true", "True"}:
            raise HTTPException(status_code=401, detail="Authentication required")
        user_id = request.headers.get("x-user-id") or "dev-user"
        email = request.headers.get("x-user-email") or "dev@example.com"
        return {"id": user_id, "email": email}

    return dev_user


# Export a resolved dependency for convenience in routers
get_current_user = resolve_get_current_user()
