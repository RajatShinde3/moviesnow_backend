# app/core/limiter.py
from __future__ import annotations

"""
MoviesNow — Rate Limiting (SlowAPI, production-grade, org-free)
---------------------------------------------------------------
- **User/IP-aware** key function (no org/tenant coupling)
- Exemptions for health/docs/static and trusted IPs
- Redis or in-memory storage (via `RATELIMIT_STORAGE_URI`)
- Version-safe middleware installer
"""

import os
from typing import Callable, Optional, List, Set

from dotenv import load_dotenv
from loguru import logger
from starlette.requests import Request
from slowapi import Limiter
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

# ──────────────────────────────────────────────────────────────
# ⚙️ Env & defaults
# ──────────────────────────────────────────────────────────────
load_dotenv()

RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
DEFAULT_LIMIT = os.getenv("DEFAULT_RATE_LIMIT", "100/minute").strip()            # e.g. "100/minute,1000/hour"
STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "").strip()                     # e.g. "redis://localhost:6379/1" or "memory://"
STRATEGY = os.getenv("RATELIMIT_STRATEGY", "moving-window").strip()              # "fixed-window" or "moving-window"

SKIP_PATHS: List[str] = [
    p.strip()
    for p in os.getenv(
        "RATE_LIMIT_SKIP_PATHS",
        "/ping,/health,/metrics,/docs,/openapi.json,/static/,/favicon.ico",
    ).split(",")
    if p.strip()
]

TRUSTED_IPS: Set[str] = {ip.strip() for ip in os.getenv("RATE_LIMIT_TRUSTED_IPS", "").split(",") if ip.strip()}


# ──────────────────────────────────────────────────────────────
# 🔑 Keying & exemptions (user/ip only — org removed)
# ──────────────────────────────────────────────────────────────
def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        ip = xff.split(",")[0].strip()
        if ip:
            return ip
    xri = request.headers.get("x-real-ip")
    if xri:
        return xri.strip()
    return get_remote_address(request) or "unknown"


def get_user_rate_limit_key(request: Request) -> str:
    """
    Key priority (org-free):
      1) user:<user_id>   (if `request.state.user_id` is set by auth)
      2) ip:<addr>        (fallback)
    """
    try:
        user_id = getattr(request.state, "user_id", None)
        if user_id:
            return f"user:{user_id}"
    except Exception as e:
        logger.warning(f"[RateLimit] key_func error; falling back to IP | err={e}")
    return f"ip:{_client_ip(request)}"


def should_exempt_request(request: Request) -> bool:
    """
    Exempt when:
    - global switch is off
    - path starts with any SKIP_PATHS
    - client IP is in TRUSTED_IPS
    """
    if not RATE_LIMIT_ENABLED:
        return True
    try:
        path = request.url.path
        if any(path.startswith(prefix) for prefix in SKIP_PATHS):
            return True
        if _client_ip(request) in TRUSTED_IPS:
            return True
    except Exception as e:
        logger.warning(f"[RateLimit] exemption check failed; enforce limits | err={e}")
    return False


# ──────────────────────────────────────────────────────────────
# 🚦 Limiter instance (Redis/memory)
# ──────────────────────────────────────────────────────────────
def _build_default_limits() -> List[str]:
    return [chunk.strip() for chunk in DEFAULT_LIMIT.split(",") if chunk.strip()]


def _make_limiter() -> Optional[Limiter]:
    storage_uri = STORAGE_URI or "memory://"
    try:
        try:
            limiter = Limiter(
                key_func=get_user_rate_limit_key,
                default_limits=_build_default_limits(),
                headers_enabled=True,
                storage_uri=storage_uri,
                strategy=STRATEGY,  # not available in some slowapi versions
            )
        except TypeError:
            # Fallback for older slowapi that lacks `strategy`
            limiter = Limiter(
                key_func=get_user_rate_limit_key,
                default_limits=_build_default_limits(),
                headers_enabled=True,
                storage_uri=storage_uri,
            )
        logger.info(
            "✅ RateLimiter ready | enabled=%s | default=%s | storage=%s | skip=%s | trusted_ips=%d",
            RATE_LIMIT_ENABLED, _build_default_limits(), storage_uri, SKIP_PATHS, len(TRUSTED_IPS)
        )
        return limiter
    except Exception as e:
        logger.error(f"❌ Failed to init Limiter; limits disabled | err={e}")
        return None


limiter: Optional[Limiter] = _make_limiter()


# ──────────────────────────────────────────────────────────────
# 🎯 Route decorators
# ──────────────────────────────────────────────────────────────
def _exempt_noarg() -> bool:
    """
    Adapter for SlowAPI versions that call `exempt_when()` with no arguments.
    Pull the current Request from Limiter's internal request context.
    """
    try:
        req = limiter._request_context.get() if limiter is not None else None  # type: ignore[attr-defined]
    except Exception:
        req = None
    return should_exempt_request(req) if req is not None else False


def _chain_decorators(decorators: List[Callable]) -> Callable:
    def _apply(fn: Callable) -> Callable:
        for deco in reversed(decorators):
            fn = deco(fn)
        return fn

    return _apply


def rate_limit(*limits: str) -> Callable:
    """
    Apply per-route limits with our standard exemptions.

    Examples:
        @rate_limit("10/minute")
        @rate_limit("5/second", "100/minute")
    """
    if limiter is None:
        def _noop(fn: Callable) -> Callable:
            return fn
        return _noop

    selected = list(limits) if limits else _build_default_limits()
    decorators = [
        limiter.limit(limit_value, exempt_when=_exempt_noarg)
        for limit_value in selected
    ]
    return _chain_decorators(decorators)


def rate_limit_exempt() -> Callable:
    """Explicitly exempt a route from limiting."""
    if limiter is None:
        def _noop(fn: Callable) -> Callable: return fn
        return _noop
    return limiter.exempt


# ──────────────────────────────────────────────────────────────
# 🔧 Installer
# ──────────────────────────────────────────────────────────────
def install_rate_limiter(app) -> None:
    """Attach SlowAPI middleware in a version-compatible way."""
    if not limiter:
        logger.warning("RateLimiter not initialized; middleware not installed")
        return
    if not RATE_LIMIT_ENABLED:
        logger.info("RateLimiter disabled by env; middleware not installed")
        return

    app.state.limiter = limiter
    # Add WITHOUT kwargs for maximum compatibility
    app.add_middleware(SlowAPIMiddleware)
    logger.info("✅ SlowAPI middleware installed (compat mode)")
