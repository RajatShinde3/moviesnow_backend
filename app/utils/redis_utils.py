# app/utils/redis_utils.py
from __future__ import annotations

"""
MoviesNow — Redis utilities (minimal, org-free)
===============================================

What’s included (only what we need):
• Per-request rate limiting (IP/route or custom key)
• Simple attempt counters (e.g., OTP/login tries)
• Small distributed lock (SET NX + token; safe release)
• Optional idempotency helpers (thin pass-through)

No org/tenant logic. No heavy Lua/compat layers.
"""

from typing import Callable, Optional
import logging
import secrets

from fastapi import HTTPException, Request, status

from app.core.redis_client import redis_wrapper

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# 🔤 Namespaces
# ──────────────────────────────────────────────
RATE_LIMIT_PREFIX = "rate-limit"
ATTEMPT_PREFIX = "attempts"
LOCK_PREFIX = "lock"

# Lua for safe compare-and-delete on release (used if EVAL is available)
# KEYS[1] = key, ARGV[1] = token
_UNLOCK_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
else
  return 0
end
"""

# ──────────────────────────────────────────────
# 🧰 Client helper
# ──────────────────────────────────────────────
def _client():
    try:
        return getattr(redis_wrapper, "client", None)
    except Exception:
        return None

def _norm_path(p: str) -> str:
    return (p or "/").rstrip("/") or "/"

# ──────────────────────────────────────────────
# ⏱️ Rate Limiting
# ──────────────────────────────────────────────
async def enforce_rate_limit(
    *,
    key_suffix: str,
    seconds: int,
    max_calls: int = 1,
    error_message: str = "Too many requests. Please try again later.",
) -> None:
    """
    Increment a counter and set TTL on first hit.
    If Redis is unavailable, we **fail-open** (do nothing).
    """
    rc = _client()
    if rc is None:
        return  # no redis → do not block

    key = f"{RATE_LIMIT_PREFIX}:{key_suffix}"
    try:
        count = await rc.incr(key)  # type: ignore[func-returns-value]
        if int(count) == 1:
            # best-effort TTL on first increment
            try:
                await rc.expire(key, int(seconds))
            except Exception:
                pass
        if int(count) > int(max_calls):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=error_message)
    except HTTPException:
        raise
    except Exception:
        # Redis hiccup → fail-open
        logger.debug("enforce_rate_limit: redis error (fail-open).", exc_info=True)

def ip_path_key(request: Request) -> str:
    """Default key: `ip:{addr}:{path}`."""
    ip = request.client.host if request and request.client else "unknown"
    return f"ip:{ip}:{_norm_path(request.url.path)}"

def rate_limiter(
    key_builder: Callable[[Request], str] = ip_path_key,
    *,
    seconds: int,
    max_calls: int = 1,
    message: str = "Too many requests. Please try again later.",
):
    """FastAPI dependency factory."""
    async def _dep(request: Request) -> None:
        try:
            suffix = key_builder(request)
        except Exception:
            suffix = ip_path_key(request)
        await enforce_rate_limit(
            key_suffix=suffix,
            seconds=seconds,
            max_calls=max_calls,
            error_message=message,
        )
    return _dep

# ──────────────────────────────────────────────
# 🚫 Attempt tracking (e.g., OTP/login failures)
# ──────────────────────────────────────────────
async def increment_attempts(
    *,
    key_suffix: str,
    limit: int,
    ttl: int = 3600,
    error_message: str = "Too many failed attempts.",
) -> None:
    """
    INCR with TTL on first hit; raise 429 if limit exceeded.
    Fail-open when Redis is unavailable.
    """
    rc = _client()
    if rc is None:
        return
    key = f"{ATTEMPT_PREFIX}:{key_suffix}"
    try:
        count = await rc.incr(key)  # type: ignore[func-returns-value]
        if int(count) == 1:
            try:
                await rc.expire(key, int(ttl))
            except Exception:
                pass
        if int(count) > int(limit):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=error_message)
    except HTTPException:
        raise
    except Exception:
        logger.debug("increment_attempts: redis error (fail-open).", exc_info=True)

async def reset_attempts(*, key_suffix: str) -> None:
    rc = _client()
    if rc is None:
        return
    try:
        await rc.delete(f"{ATTEMPT_PREFIX}:{key_suffix}")
    except Exception:
        logger.debug("reset_attempts: best-effort delete failed.", exc_info=True)

# ──────────────────────────────────────────────
# 🔐 Distributed lock (tokened)
# ──────────────────────────────────────────────
async def acquire_lock(*, key_suffix: str, ttl: int = 30) -> Optional[str]:
    """SET NX with TTL; returns token if acquired, else None. Fail-open: return token when no Redis."""
    rc = _client()
    token = secrets.token_urlsafe(16)
    if rc is None:
        return token  # pretend lock acquired (single-instance dev)
    key = f"{LOCK_PREFIX}:{key_suffix}"
    try:
        ok = await rc.set(key, token, ex=int(ttl), nx=True)
        return token if ok in (True, 1, b"OK", "OK") else None
    except Exception:
        logger.debug("acquire_lock: redis error.", exc_info=True)
        return None

async def release_lock(*, key_suffix: str, token: str) -> bool:
    """
    Compare-and-delete using small Lua when available; fallback to GET+DEL.
    """
    rc = _client()
    if rc is None:
        return True
    key = f"{LOCK_PREFIX}:{key_suffix}"
    try:
        if hasattr(rc, "eval"):
            try:
                res = await rc.eval(_UNLOCK_LUA, 1, key, token)  # redis-py style
            except TypeError:
                # aioredis style
                res = await rc.eval(_UNLOCK_LUA, keys=[key], args=[token])
            return bool(int(res or 0))
    except Exception:
        pass  # fall through to GET+DEL

    try:
        val = await rc.get(key)
        if isinstance(val, (bytes, bytearray)):
            val = val.decode("utf-8", errors="ignore")
        if val == token:
            await rc.delete(key)
            return True
    except Exception:
        logger.debug("release_lock: fallback compare-delete failed.", exc_info=True)
    return False

# ──────────────────────────────────────────────
# ♻️ Idempotency snapshots (thin pass-through)
# ──────────────────────────────────────────────
async def idempotency_get(key: str):
    try:
        return await redis_wrapper.idempotency_get(key)
    except Exception:
        return None

async def idempotency_set(key: str, value, ttl_seconds: int = 600):
    try:
        await redis_wrapper.idempotency_set(key, value, ttl_seconds=ttl_seconds)
    except Exception:
        pass
