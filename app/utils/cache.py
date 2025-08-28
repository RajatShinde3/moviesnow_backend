# app/utils/cache.py
from __future__ import annotations

"""
MoviesNow — Redis-backed caching (async, lean)
==============================================

What you get
------------
• Reuses shared client from `app.core.redis_client.redis_wrapper` when available
• Namespaced keys with SHA-256 hashing for long keys
• JSON serialization (UUID/datetime safe via `default=str`)
• Optional zlib compression (threshold-based)
• Tagging + bulk invalidation (UNLINK with DEL fallback)
• Single-flight memoizer to prevent cache stampedes
• Fail-open behavior: logs errors but doesn’t break request paths
"""

import asyncio
import hashlib
import json
import logging
import os
import time
import zlib
from contextlib import suppress
from typing import Any, Awaitable, Callable, Iterable, Optional

import redis.asyncio as redis
from redis.exceptions import ConnectionError, RedisError, TimeoutError

logger = logging.getLogger("moviesnow.cache")

# ─────────────────────────────────────────────────────────────
# ⚙️ Configuration
# ─────────────────────────────────────────────────────────────
CACHE_REDIS_URL: str = (
    os.getenv("CACHE_REDIS_URL")
    or os.getenv("REDIS_URL")
    or "redis://localhost:6379/0"
)
CACHE_NAMESPACE: str = os.getenv("CACHE_NAMESPACE", "moviesnow:cache").strip()
CACHE_DEFAULT_TTL: int = int(os.getenv("CACHE_DEFAULT_TTL", "300"))
CACHE_COMPRESS: bool = os.getenv("CACHE_COMPRESS", "true").lower() == "true"
CACHE_COMPRESS_THRESHOLD: int = int(os.getenv("CACHE_COMPRESS_THRESHOLD", "256"))
CACHE_MAX_KEY_LEN: int = int(os.getenv("CACHE_MAX_KEY_LEN", "512"))
CACHE_LOCK_TIMEOUT: int = int(os.getenv("CACHE_LOCK_TIMEOUT", "30"))
CACHE_LOCK_SLEEP: float = float(os.getenv("CACHE_LOCK_SLEEP", "0.05"))

__all__ = [
    "cache_set",
    "cache_get",
    "cache_delete",
    "cache_exists",
    "cache_touch",
    "cache_invalidate_tags",
    "cache_memoize",
    "cache_ping",
    "cache_close",
]

# ─────────────────────────────────────────────────────────────
# 🧠 Redis client (prefer shared wrapper)
# ─────────────────────────────────────────────────────────────
_local_client: Optional[redis.Redis] = None

async def _ensure_local_client() -> redis.Redis:
    """Create a small pooled client if shared wrapper isn’t available."""
    global _local_client
    if _local_client is None:
        _local_client = redis.from_url(
            CACHE_REDIS_URL,
            encoding="utf-8",
            decode_responses=False,  # store bytes; we manage JSON explicitly
            max_connections=20,
        )
    return _local_client

async def get_redis() -> redis.Redis:
    """Return a connected Redis client (shared wrapper → local fallback)."""
    try:
        from app.core.redis_client import redis_wrapper  # type: ignore
        client = getattr(redis_wrapper, "client", None)
        if client is not None:
            return client
    except Exception:
        pass
    return await _ensure_local_client()

# ─────────────────────────────────────────────────────────────
# 🔑 Key helpers (namespace + hashing)
# ─────────────────────────────────────────────────────────────
def _normalize_key(key: str) -> str:
    """
    Build the final storage key:
      1) Trim whitespace/newlines
      2) Prefix with namespace
      3) If too long, replace tail with SHA-256 digest
    """
    key = (key or "").strip().replace("\n", " ")
    full = f"{CACHE_NAMESPACE}:{key}"
    if len(full) <= CACHE_MAX_KEY_LEN:
        return full
    h = hashlib.sha256(full.encode("utf-8")).hexdigest()
    return f"{CACHE_NAMESPACE}:h:{h}"

# ─────────────────────────────────────────────────────────────
# 🧰 Serialization (JSON + optional compression)
# ─────────────────────────────────────────────────────────────
# First byte encodes codec: 0x00 = plain JSON, 0x01 = zlib JSON
_PLAIN = b"\x00"
_COMP = b"\x01"

def _json_dumps(value: Any) -> bytes:
    return json.dumps(value, default=str, separators=(",", ":")).encode("utf-8")

def _json_loads(data: bytes) -> Any:
    return json.loads(data.decode("utf-8"))

def _encode_payload(value: Any) -> bytes:
    raw = _json_dumps(value)
    if CACHE_COMPRESS and len(raw) > CACHE_COMPRESS_THRESHOLD:
        return _COMP + zlib.compress(raw)
    return _PLAIN + raw

def _decode_payload(blob: Optional[bytes]) -> Optional[Any]:
    if not blob:
        return None
    kind, data = blob[:1], blob[1:]
    try:
        if kind == _COMP:
            return _json_loads(zlib.decompress(data))
        return _json_loads(data)
    except Exception as e:  # best-effort
        logger.error(f"[cache] decode error: {e}")
        return None

# ─────────────────────────────────────────────────────────────
# 📦 Basic operations
# ─────────────────────────────────────────────────────────────
async def cache_set(
    key: str,
    value: Any,
    ttl: Optional[int] = None,
    *,
    tags: Optional[Iterable[str]] = None,
    nx: bool = False,
) -> bool:
    """
    Store a Python object under `key` with TTL.
    - `nx=True` only sets if the key doesn’t already exist.
    - `tags=[...]` associates the key to tag sets for invalidation.
    """
    k = _normalize_key(key)
    try:
        client = await get_redis()
        payload = _encode_payload(value)

        # SET with NX when requested (compat path for skinny clients)
        try:
            ok = await client.set(k, payload, ex=ttl or CACHE_DEFAULT_TTL, nx=nx or None)
        except TypeError:
            if nx:
                ok = await client.setnx(k, payload)  # type: ignore[attr-defined]
                if ok:
                    with suppress(Exception):
                        await client.expire(k, ttl or CACHE_DEFAULT_TTL)  # type: ignore[attr-defined]
            else:
                ok = await client.set(k, payload, ex=ttl or CACHE_DEFAULT_TTL)

        # Tag membership (best-effort)
        if tags:
            try:
                p = client.pipeline()
                for t in tags:
                    tag_key = _normalize_key(f"tag:{t}")
                    p.sadd(tag_key, k)
                    p.expire(tag_key, ttl or CACHE_DEFAULT_TTL)
                await p.execute()
            except Exception:
                for t in tags:
                    tag_key = _normalize_key(f"tag:{t}")
                    with suppress(Exception):
                        await client.sadd(tag_key, k)
                        await client.expire(tag_key, ttl or CACHE_DEFAULT_TTL)

        return bool(ok)
    except (RedisError, ConnectionError, TimeoutError) as e:
        logger.error(f"[cache_set] redis error key={k}: {e}")
        return False
    except Exception as e:
        logger.exception(f"[cache_set] unexpected error key={k}: {e}")
        return False

async def cache_get(key: str, default: Optional[Any] = None) -> Optional[Any]:
    """Get object by key; returns `default` on miss or error."""
    k = _normalize_key(key)
    try:
        client = await get_redis()
        blob = await client.get(k)
        val = _decode_payload(blob)
        return default if val is None else val
    except (RedisError, ConnectionError, TimeoutError) as e:
        logger.error(f"[cache_get] redis error key={k}: {e}")
        return default
    except Exception as e:
        logger.exception(f"[cache_get] unexpected error key={k}: {e}")
        return default

async def cache_delete(key: str) -> bool:
    """Delete a cache entry; returns `True` if a key was removed."""
    k = _normalize_key(key)
    try:
        client = await get_redis()
        removed = 0
        try:
            if hasattr(client, "unlink"):
                removed = int(await client.unlink(k))  # type: ignore[attr-defined]
            else:
                removed = int(await client.delete(k))
        except Exception:
            removed = int(await client.delete(k))
        return bool(removed)
    except Exception as e:
        logger.error(f"[cache_delete] error key={k}: {e}")
        return False

async def cache_exists(key: str) -> bool:
    """Return `True` if the given key exists."""
    k = _normalize_key(key)
    try:
        client = await get_redis()
        return bool(await client.exists(k))
    except Exception as e:
        logger.error(f"[cache_exists] error key={k}: {e}")
        return False

async def cache_touch(key: str, ttl: Optional[int] = None) -> bool:
    """Update TTL without changing value."""
    k = _normalize_key(key)
    try:
        client = await get_redis()
        return bool(await client.expire(k, ttl or CACHE_DEFAULT_TTL))
    except Exception as e:
        logger.error(f"[cache_touch] error key={k}: {e}")
        return False

# ─────────────────────────────────────────────────────────────
# 🧹 Tag invalidation (UNLINK/DEL)
# ─────────────────────────────────────────────────────────────
async def _unlink_or_delete_many(client: redis.Redis, keys: list[str]) -> int:
    """Try UNLINK (non-blocking) then DEL in chunks."""
    if not keys:
        return 0
    deleted = 0
    try:
        if hasattr(client, "unlink"):
            for i in range(0, len(keys), 512):
                deleted += int(await client.unlink(*keys[i:i+512]))  # type: ignore[attr-defined]
            return deleted
    except Exception:
        pass
    for i in range(0, len(keys), 512):
        deleted += int(await client.delete(*keys[i:i+512]))
    return deleted

async def cache_invalidate_tags(*tags: str) -> int:
    """
    Invalidate all keys associated with provided tags.
    Returns number of keys scheduled for deletion (best-effort).
    """
    total = 0
    try:
        client = await get_redis()
        keys_to_del: list[str] = []
        for t in tags:
            tag_key = _normalize_key(f"tag:{t}")
            try:
                members = await client.smembers(tag_key)
                if members:
                    for m in members:
                        if isinstance(m, (bytes, bytearray)):
                            keys_to_del.append(m.decode())
                        else:
                            keys_to_del.append(str(m))
            finally:
                with suppress(Exception):
                    await client.delete(tag_key)

        if keys_to_del:
            total = await _unlink_or_delete_many(client, keys_to_del)
    except Exception as e:
        logger.error(f"[cache_invalidate_tags] error tags={tags}: {e}")
    return total

# ─────────────────────────────────────────────────────────────
# 🐕‍🦺 Single-flight memoizer
# ─────────────────────────────────────────────────────────────
async def cache_memoize(
    key: str,
    loader: Callable[[], Awaitable[Any]],
    ttl: Optional[int] = None,
    *,
    tags: Optional[Iterable[str]] = None,
    lock_timeout: Optional[int] = None,
    wait_timeout: Optional[float] = None,
    default: Optional[Any] = None,
) -> Any:
    """
    Return cached value for `key` or compute via `loader` with a Redis lock.
    - One producer computes; followers wait briefly
    - If Redis is down, compute once without caching (fail-open)
    """
    cached = await cache_get(key, default=None)
    if cached is not None:
        return cached

    k = _normalize_key(key)
    lock_key = f"{k}:lock"
    lock_ttl = lock_timeout or CACHE_LOCK_TIMEOUT
    try:
        client = await get_redis()
        got_lock = False
        try:
            got_lock = bool(await client.set(lock_key, b"1", nx=True, ex=lock_ttl))
        except TypeError:
            got_lock = bool(await client.setnx(lock_key, b"1"))  # type: ignore[attr-defined]
            if got_lock:
                with suppress(Exception):
                    await client.expire(lock_key, lock_ttl)  # type: ignore[attr-defined]

        if got_lock:
            try:
                value = await loader()
                await cache_set(key, value, ttl=ttl, tags=tags)
                return value
            finally:
                with suppress(Exception):
                    await client.delete(lock_key)
        else:
            deadline = time.monotonic() + (min(2.0, float(lock_ttl)) if wait_timeout is None else float(wait_timeout))
            while time.monotonic() < deadline:
                await asyncio.sleep(CACHE_LOCK_SLEEP)
                cached = await cache_get(key, default=None)
                if cached is not None:
                    return cached
            return default
    except Exception as e:
        logger.error(f"[cache_memoize] error key={k}: {e}")
        try:
            return await loader()
        except Exception:
            logger.exception(f"[cache_memoize] loader failed key={k}")
            return default

# ─────────────────────────────────────────────────────────────
# 🩺 Health + shutdown
# ─────────────────────────────────────────────────────────────
async def cache_ping() -> bool:
    try:
        client = await get_redis()
        pong = await client.ping()
        return bool(pong)
    except Exception as e:
        logger.error(f"[cache_ping] {e}")
        return False

async def cache_close() -> None:
    """Close the fallback local client if it was created."""
    global _local_client
    try:
        if _local_client is not None:
            await _local_client.close()
            _local_client = None
    except Exception as e:
        logger.warning(f"[cache_close] {e}")
