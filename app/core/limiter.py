from __future__ import annotations

"""
MoviesNow — HTTP Rate Limiting (SlowAPI)
========================================

Highlights
----------
- **User/IP aware** keying: per-user when auth sets `request.state.user_id`,
  else per-client-IP (using XFF/X-Real-IP/client.host).
- **Production exemptions**: health/docs/static, configurable trusted IPs.
- **Test/CI friendly**:
    - `RATE_LIMIT_NAMESPACE`: prefixes keys so parallel runs don't collide.
    - `RATE_LIMIT_TEST_BYPASS`: disables limits when truthy.
    - `X-RateLimit-Bypass: 1` header can exempt a single request (opt-in).
- **Backends**: Redis via `RATELIMIT_STORAGE_URI` or in-memory fallback.
- **Version compatibility**: handles SlowAPI/limits API differences.

Environment
-----------
RATE_LIMIT_ENABLED           default: "true"
DEFAULT_RATE_LIMIT           default: "100/minute"
RATELIMIT_STORAGE_URI        default: "" (falls back to "memory://")
RATELIMIT_STRATEGY           default: "moving-window"  (ignored if unsupported)
RATE_LIMIT_SKIP_PATHS        default: "/ping,/health,/metrics,/docs,/openapi.json,/static/,/favicon.ico"
RATE_LIMIT_TRUSTED_IPS       default: "" (comma separated)
RATE_LIMIT_NAMESPACE         default: "" (e.g., "pytest-<runid>")
RATE_LIMIT_TEST_BYPASS       default: "" (truthy to bypass in tests/CI)
RATE_LIMIT_BYPASS_HEADER     default: "X-RateLimit-Bypass"

Usage
-----
    from app.core.limiter import install_rate_limiter, rate_limit, rate_limit_exempt

    app = FastAPI()
    install_rate_limiter(app)

    @router.get("/expensive")
    @rate_limit("5/second", "300/minute")
    async def expensive(): ...

    @router.get("/health")
    @rate_limit_exempt()
    async def health(): ...
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
# ⚙️ Environment & defaults
# ──────────────────────────────────────────────────────────────
load_dotenv()

RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
DEFAULT_LIMIT = os.getenv("DEFAULT_RATE_LIMIT", "100/minute").strip()
STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "").strip()               # e.g. "redis://localhost:6379/1" or "memory://"
STRATEGY = os.getenv("RATELIMIT_STRATEGY", "moving-window").strip()        # "fixed-window" or "moving-window"

SKIP_PATHS: List[str] = [
    p.strip()
    for p in os.getenv(
        "RATE_LIMIT_SKIP_PATHS",
        "/ping,/health,/metrics,/docs,/openapi.json,/static/,/favicon.ico",
    ).split(",")
    if p.strip()
]

TRUSTED_IPS: Set[str] = {ip.strip() for ip in os.getenv("RATE_LIMIT_TRUSTED_IPS", "").split(",") if ip.strip()}

# Test/CI knobs
NAMESPACE = os.getenv("RATE_LIMIT_NAMESPACE", "").strip()
TEST_BYPASS = os.getenv("RATE_LIMIT_TEST_BYPASS", "").strip().lower() in {"1", "true", "yes", "on"}
BYPASS_HEADER = os.getenv("RATE_LIMIT_BYPASS_HEADER", "X-RateLimit-Bypass")

# ──────────────────────────────────────────────────────────────
# 🧠 Keying & exemptions (org-free)
# ──────────────────────────────────────────────────────────────
def _client_ip(request: Request) -> str:
    """
    Best-effort client IP:
    1) X-Forwarded-For (first hop)
    2) X-Real-IP
    3) ASGI client.host
    """
    try:
        xff = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
        if xff:
            ip = xff.split(",")[0].strip()
            if ip:
                return ip
        xri = request.headers.get("x-real-ip") or request.headers.get("X-Real-IP")
        if xri:
            return xri.strip()
        ip = get_remote_address(request)
        return ip or "unknown"
    except Exception:
        return "unknown"


def _with_namespace(key: str) -> str:
    """Prefix the limiter key with a namespace (useful for CI/pytest isolation)."""
    return f"{NAMESPACE}:{key}" if NAMESPACE else key


def get_user_rate_limit_key(request: Request) -> str:
    """
    Build a limiter key. Priority:
      1) user:<user_id>  (when auth sets `request.state.user_id`)
      2) ip:<addr>       (fallback)
    Always prefixed with RATE_LIMIT_NAMESPACE when set.
    """
    try:
        user_id = getattr(request.state, "user_id", None)
        if user_id:
            return _with_namespace(f"user:{user_id}")
    except Exception as e:
        logger.warning(f"[RateLimit] key_func error; falling back to IP | err={e}")
    return _with_namespace(f"ip:{_client_ip(request)}")


def _path_is_skipped(path: str) -> bool:
    """Return True when the path should be exempt from rate limiting."""
    # Exact or prefix matches for common static/docs paths
    for prefix in SKIP_PATHS:
        if not prefix:
            continue
        if prefix.endswith("/"):
            if path.startswith(prefix):
                return True
        else:
            if path == prefix or path.startswith(prefix):
                return True
    return False


def should_exempt_request(request: Optional[Request]) -> bool:
    """
    Exempt a request when:
      - global switch is off, or
      - path is in SKIP_PATHS, or
      - client IP is TRUSTED, or
      - test bypass is enabled (env) or header indicates bypass.
    """
    # Re-evaluate env flags at request time so tests/CI can toggle without
    # re-importing this module.
    _enabled_env = os.getenv("RATE_LIMIT_ENABLED", "true").strip().lower() == "true"
    _test_bypass_env = os.getenv("RATE_LIMIT_TEST_BYPASS", "").strip().lower() in {"1", "true", "yes", "on"}

    if not _enabled_env:
        return True
    if request is None:  # defensive
        return False

    try:
        # Explicit one-off bypass header (opt-in; useful for e2e/setup)
        if request.headers.get(BYPASS_HEADER, "").strip() in {"1", "true", "yes", "on"}:
            return True

        path = request.url.path
        if _path_is_skipped(path):
            return True

        ip = _client_ip(request)
        if ip in TRUSTED_IPS:
            return True

        if _test_bypass_env:
            # Safe default for big test suites; set RATE_LIMIT_TEST_BYPASS=""
            # in tests that specifically assert rate limiting behavior.
            return True
    except Exception as e:
        logger.warning(f"[RateLimit] exemption check failed; enforcing limits | err={e}")
    return False


# ──────────────────────────────────────────────────────────────
# 🧰 Limiter instance (Redis / memory)
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
                strategy=STRATEGY,  # ignored by older slowapi
            )
        except TypeError:
            # SlowAPI w/o `strategy` kw
            limiter = Limiter(
                key_func=get_user_rate_limit_key,
                default_limits=_build_default_limits(),
                headers_enabled=True,
                storage_uri=storage_uri,
            )

        logger.info(
            "✅ RateLimiter ready | enabled=%s | default=%s | storage=%s | skip=%s | trusted_ips=%d | ns=%s | test_bypass=%s",
            RATE_LIMIT_ENABLED, _build_default_limits(), storage_uri, SKIP_PATHS, len(TRUSTED_IPS), NAMESPACE, TEST_BYPASS
        )
        return limiter
    except Exception as e:
        logger.error(f"❌ Failed to init Limiter; limits disabled | err={e}")
        return None


limiter: Optional[Limiter] = _make_limiter()

# ──────────────────────────────────────────────────────────────
# 🎛 Decorators
# ──────────────────────────────────────────────────────────────
def _exempt_when(request: Optional[Request] = None) -> bool:
    """
    Works with both SlowAPI styles:
    - Newer: exempt_when receives the Request
    - Older: exempt_when receives no args; get Request from limiter context
    """
    try:
        req = request
        if req is None and limiter is not None:
            # Fallback to contextvar when middleware provided it
            try:
                req = limiter._request_context.get()  # type: ignore[attr-defined]
            except Exception:
                req = None
        return should_exempt_request(req)
    except Exception:
        return False


def _chain(decorators: List[Callable]) -> Callable:
    def _apply(fn: Callable) -> Callable:
        for deco in reversed(decorators):
            fn = deco(fn)
        return fn
    return _apply


def rate_limit(*limits: str) -> Callable:
    """
    Apply per-route limits with MoviesNow exemptions.

    Examples
    --------
    @rate_limit("10/minute")
    @rate_limit("5/second", "100/minute")
    """
    if limiter is None:
        def _noop(fn: Callable) -> Callable:
            return fn
        return _noop

    selected = list(limits) if limits else _build_default_limits()
    decorators = [
        limiter.limit(limit_value, exempt_when=_exempt_when)
        for limit_value in selected
    ]
    return _chain(decorators)


def rate_limit_exempt() -> Callable:
    """Explicitly exempt a route from limiting."""
    if limiter is None:
        def _noop(fn: Callable) -> Callable:
            return fn
        return _noop
    return limiter.exempt


# ──────────────────────────────────────────────────────────────
# 🔧 Installer
# ──────────────────────────────────────────────────────────────
def install_rate_limiter(app) -> None:
    """
    Attach SlowAPI middleware.

    Notes
    -----
    - Uses compat mode (no kwargs) to support older SlowAPI.
    - Honors RATE_LIMIT_ENABLED: middleware is not installed when disabled.
    """
    if not limiter:
        logger.warning("RateLimiter not initialized; middleware not installed")
        return
    if not RATE_LIMIT_ENABLED:
        logger.info("RateLimiter disabled by env; middleware not installed")
        return

    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)  # compatible signature
    logger.info("✅ SlowAPI middleware installed (compat mode)")
