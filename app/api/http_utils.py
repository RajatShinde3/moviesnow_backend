from __future__ import annotations

"""
MoviesNow · HTTP Utilities
==========================

Shared helpers for API routers:

- ID sanitization (slugs & UUIDs)
- Client IP resolution (proxy-aware, opt-in)
- Lightweight per-process token-bucket rate limiting (dependency)
- Public API key enforcement (header/query, rotation & hashed support)
- Admin check (key-based or user-role based with dev fallback)
- Webhook HMAC verification (rotating secrets)

Notes
-----
• For multi-process or multi-instance deployments, prefer a centralized,
  Redis-backed limiter (see `app.core.limiter`) and infra-level request filtering.
• All helpers aim to be side-effect free and fast; dependency functions return
  `None` on success or raise `HTTPException` on failure.
"""

import hashlib
import hmac
import ipaddress
import os
import re
import threading
import time
from typing import Any, Dict, Mapping, Optional

from fastapi import HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

# Public re-export used elsewhere in your codebase
from app.core.cache import TTLCache  # re-export for compatibility


# ─────────────────────────────────────────────────────────────────────────────
# ID Sanitization
# ─────────────────────────────────────────────────────────────────────────────

_SANITIZE_SLUG_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_SANITIZE_UUID_RE = re.compile(r"^[0-9a-fA-F-]{8,36}$")


def sanitize_title_id(title_id: str) -> str:
    """Validate a title identifier.

    Accepts:
      - Slugs matching `[A-Za-z0-9_-]{1,128}`
      - UUID-like strings (8–36 chars, hex with hyphens)

    Returns the original `title_id` when valid; otherwise raises HTTP 400.

    Steps
    -----
    1) Test against slug regex.
    2) Test against relaxed UUID regex.
    3) Raise if both fail.
    """
    if _SANITIZE_SLUG_RE.match(title_id) or _SANITIZE_UUID_RE.match(title_id):
        return title_id
    raise HTTPException(status_code=400, detail="Invalid title_id format")


# ─────────────────────────────────────────────────────────────────────────────
# Client IP Resolution
# ─────────────────────────────────────────────────────────────────────────────

def _parse_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        # Strip port if present (e.g. "1.2.3.4:12345")
        host = value.split("%")[0].split(":")[0] if value.count(":") == 1 else value
        ipaddress.ip_address(host.strip())
        return host.strip()
    except Exception:
        return None


def get_client_ip(request: Request) -> str:
    """Determine the best-guess client IP.

    Trust behavior (opt-in)
    -----------------------
    • By default, uses the socket peer address.
    • If `TRUST_FORWARD_HEADERS=1` is set, will consult (in order):
        1) `CF-Connecting-IP`
        2) `True-Client-IP`
        3) `X-Real-Ip`
        4) `X-Forwarded-For` (first IP)
    • You can constrain trust further with `TRUSTED_PROXY_ONLY=1` which will only
      use forwarded headers if the socket peer is a private (RFC1918/4193) address.

    Returns "unknown" when no address can be determined.
    """
    peer = request.client.host if request.client and request.client.host else None
    peer_ip = _parse_ip(peer)

    trust = os.environ.get("TRUST_FORWARD_HEADERS") in {"1", "true", "True"}
    proxy_only = os.environ.get("TRUSTED_PROXY_ONLY") in {"1", "true", "True"}

    if not trust:
        return peer_ip or "unknown"

    # If restricted, require that peer is from a private range to trust headers.
    if proxy_only:
        try:
            if not peer_ip or ipaddress.ip_address(peer_ip).is_private is False:
                return peer_ip or "unknown"
        except Exception:
            return peer_ip or "unknown"

    # Check common headers set by CDNs/proxies
    for hdr in ("cf-connecting-ip", "true-client-ip", "x-real-ip"):
        ip = _parse_ip(request.headers.get(hdr) or request.headers.get(hdr.title()))
        if ip:
            return ip

    xff = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
    if xff:
        # Use first hop (left-most) which should be the original client if your
        # edge properly appends.
        first = xff.split(",")[0].strip()
        ip = _parse_ip(first)
        if ip:
            return ip

    return peer_ip or "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Lightweight Token-Bucket Limiter (per-process)
# ─────────────────────────────────────────────────────────────────────────────

class _TokenBucket:
    """Simple token bucket with monotonic clock and thread-safety."""

    __slots__ = ("rate", "per", "tokens", "updated", "_lock")

    def __init__(self, rate: int, per_seconds: int):
        self.rate = max(1, int(rate))
        self.per = max(1, int(per_seconds))
        self.tokens: float = float(self.rate)
        self.updated = time.monotonic()
        self._lock = threading.Lock()

    def allow(self, amount: int = 1) -> bool:
        now = time.monotonic()
        with self._lock:
            elapsed = now - self.updated
            # Refill
            self.tokens = min(self.rate, self.tokens + (elapsed * self.rate / self.per))
            self.updated = now
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False

    def seconds_until_next_token(self) -> int:
        """Rough seconds until one token is available (integer)."""
        with self._lock:
            if self.tokens >= 1.0:
                return 0
            # tokens_deficit / (rate/per) = seconds
            deficit = 1.0 - self.tokens
            sec = deficit / (self.rate / self.per)
            return max(0, int(sec + 0.999))  # ceil


_rate_buckets: Dict[str, _TokenBucket] = {}


def rate_limit(
    request: Request,
    response: Response,
    limit: int = 120,
    window_seconds: int = 60,
):
    """Per-IP+method+path token-bucket limiter (process-local).

    Headers set on response:
      - `X-RateLimit-Limit`: configured limit
      - `X-RateLimit-Remaining`: integer tokens left (floored)
      - `X-RateLimit-Window`: window in seconds
      - `Retry-After`: seconds until next token (when 429)

    Steps
    -----
    1) Build a key from IP + HTTP method + normalized path.
    2) Create or reuse a token bucket.
    3) Attempt to consume one token; on failure, raise 429.
    """
    ip = get_client_ip(request)
    key = f"{ip}:{request.method}:{request.url.path}"
    bucket = _rate_buckets.get(key)
    if not bucket:
        bucket = _TokenBucket(limit, window_seconds)
        _rate_buckets[key] = bucket

    allowed = bucket.allow(1)

    # Observability-friendly headers
    remaining = max(0, int(bucket.tokens))
    response.headers["X-RateLimit-Limit"] = str(limit)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Window"] = str(window_seconds)

    if not allowed:
        retry_after = bucket.seconds_until_next_token()
        response.headers["Retry-After"] = str(retry_after)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Public API Key Enforcement
# ─────────────────────────────────────────────────────────────────────────────

def _compare_ct(a: str, b: str) -> bool:
    """Constant-time string comparison."""
    return hmac.compare_digest(str(a), str(b))


def enforce_public_api_key(request: Request):
    """Optionally require a public API key for read-only endpoints.

    Allowed sources (checked in order):
      1) `X-API-Key` header (case-insensitive)
      2) `api_key` query parameter

    Rotation & hashing:
      - `PUBLIC_API_KEY` may contain a single key or a comma-separated list.
      - Alternatively, set `PUBLIC_API_KEY_SHA256` with one or more hex digests.
        The provided key is SHA-256 hashed and compared against the list.

    Behavior:
      - If no env var is set, the check is a no-op (endpoint remains public).
      - On mismatch/missing key, raises HTTP 401.
    """
    raw_keys = os.environ.get("PUBLIC_API_KEY", "")
    raw_hashes = os.environ.get("PUBLIC_API_KEY_SHA256", "")
    keys = [k.strip() for k in raw_keys.split(",") if k.strip()]
    hashes = [h.strip().lower() for h in raw_hashes.split(",") if h.strip()]

    if not keys and not hashes:
        return  # Not enforced

    provided = (
        request.headers.get("x-api-key")
        or request.headers.get("X-API-Key")
        or request.query_params.get("api_key")
    )
    if not provided:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    # Direct key match
    for k in keys:
        if _compare_ct(provided, k):
            return

    # Hashed match (SHA-256 hex)
    if hashes:
        candidate = hashlib.sha256(provided.encode("utf-8")).hexdigest()
        for h in hashes:
            if _compare_ct(candidate, h):
                return

    raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ─────────────────────────────────────────────────────────────────────────────
# No-store JSON helper
# ─────────────────────────────────────────────────────────────────────────────

def json_no_store(
    payload: Any,
    status_code: int = 200,
    *,
    request: Optional[Request] = None,
    response: Optional[Response] = None,
) -> JSONResponse:
    """
    Return a JSON response with strict `no-store` caching.

    Accepts optional `request`/`response` kwargs for compatibility with callers
    that want to pass through the current Response object; these are ignored
    here but kept to avoid unexpected-kwarg errors.
    """
    resp = JSONResponse(content=payload, status_code=status_code)
    # Tests expect exactly these headers for sensitive responses
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    # Propagate selected headers set on an existing Response object (if provided)
    if response is not None:
        for key in ("Location", "X-Total-Count", "Link"):
            if key in response.headers:
                resp.headers[key] = response.headers[key]
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# Admin Requirement
# ─────────────────────────────────────────────────────────────────────────────

def require_admin(request: Request):
    """Require administrative privileges.

    Strategy (ordered):
      1) If `ADMIN_API_KEY` is set → require `X-Admin-Key` (constant-time).
      2) Else, attempt to resolve `get_current_user` and allow if:
         • dict user with `is_superuser`/`is_admin`/`role == 'admin'`, or
         • object user with those attributes.
      3) Dev fallback: if `ALLOW_DEV_AUTH=1` and `X-Admin: true`, allow.

    Raises HTTP 401/403 on failure.
    """
    admin_key = os.environ.get("ADMIN_API_KEY")
    if admin_key:
        provided = request.headers.get("x-admin-key") or request.headers.get("X-Admin-Key")
        if not provided or not _compare_ct(provided, admin_key):
            raise HTTPException(status_code=401, detail="Invalid or missing admin key")
        return

    # Try to use the resolved project-level dependency if available.
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


# ─────────────────────────────────────────────────────────────────────────────
# Webhook HMAC Verification
# ─────────────────────────────────────────────────────────────────────────────

async def verify_webhook_signature(
    request: Request,
    *,
    secret_env: str,
    header_name: str = "X-Signature",
    scheme: str = "sha256=",
) -> bool:
    """Verify HMAC signature of the raw request body.

    Configuration
    -------------
    • `secret_env`: env var name holding one or more shared secrets. Supports
      comma-separated rotation (any match accepts).
    • `header_name`: HTTP header carrying the signature (default `X-Signature`).
    • `scheme`: expected prefix (default `sha256=`), e.g., "sha256=".

    Behavior
    --------
    • If `secret_env` is unset/empty → returns True (verification disabled).
    • If header missing or malformed → returns False.
    • Computes `HMAC_SHA256(secret, body)` and constant-time compares to header.

    Returns True/False (no exceptions); callers should raise on False.
    """
    raw = os.environ.get(secret_env, "")
    if not raw:
        return True  # not enforced
    secrets = [s.strip() for s in raw.split(",") if s.strip()]

    sig = request.headers.get(header_name) or request.headers.get(header_name.lower())
    if not sig or not sig.startswith(scheme):
        return False

    body = await request.body()
    provided = sig[len(scheme):]

    for secret in secrets:
        calc = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        if _compare_ct(calc, provided):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Current user resolution (best-effort)
# ─────────────────────────────────────────────────────────────────────────────

def resolve_get_current_user():
    """Resolve the project's `get_current_user` dependency.

    Tries a few common locations. If none is available, provides a dev-only
    fallback that extracts identity from headers when `ALLOW_DEV_AUTH=1`.

    Dev fallback headers:
      • `X-User-Id`, `X-User-Email`
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
# Filename sanitization (safe for Content-Disposition)
def sanitize_filename(name: Optional[str], fallback: str = "download.bin") -> str:
    """Return a safe filename limited to [A-Za-z0-9._-] and underscores for spaces.

    - Strips leading/trailing whitespace
    - Replaces whitespace with single underscore
    - Removes any characters outside A-Za-z0-9._-
    - Falls back to provided name if empty
    """
    s = (name or "").strip()
    if not s:
        return fallback
    import re as _re
    s = _re.sub(r"\s+", "_", s)
    s = _re.sub(r"[^A-Za-z0-9._-]", "", s)
    return s or fallback
