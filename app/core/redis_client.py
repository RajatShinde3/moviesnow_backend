# app/core/redis_client.py
from __future__ import annotations

"""
MoviesNow — Redis Client (Async, Production-grade)
==================================================
Central, **single source of truth** for Redis access in the app.

What this provides
------------------
• Resilient connection manager (standalone + cluster) with retries & backoff  
• Pooled async client with health checks  
• Sliding-window **rate limiting** (atomic Lua, with safe Python fallback)  
• **Idempotency** snapshots (JSON set/get)  
• Generic JSON set/get helpers  
• Async **distributed lock** (native lock preferred; `SETNX` fallback)  

Public API (imported as `redis_wrapper`)
----------------------------------------
- await redis_wrapper.connect() / await redis_wrapper.close() / await redis_wrapper.is_connected()
- redis_wrapper.client
- await redis_wrapper.rate_limit_sliding_window(key, max_ops, window_seconds)
- await redis_wrapper.idempotency_set(key, value, ttl_seconds=86400)
- await redis_wrapper.idempotency_get(key)
- await redis_wrapper.json_set(key, value, ttl_seconds=None)
- await redis_wrapper.json_get(key, default=None)
- async with redis_wrapper.lock(name, timeout=10, blocking_timeout=3): ...

Design notes
------------
• **No duplication**: import helpers from here; don’t re-implement elsewhere.  
• **Fail-open** for rate limiting if Redis hiccups (never 500 your auth flows).  
• **Strict** on locks: raise `TimeoutError` if not acquired within `blocking_timeout`.  
• Compatible with test mocks that lack some Redis methods (eval, blocking_timeout in lock, etc.).
"""

import asyncio
import inspect
import json
import logging
import os
import random
import time
from contextlib import asynccontextmanager
from typing import Any, Optional, Tuple, Protocol
from urllib.parse import urlparse

import redis.asyncio as redis
from redis.asyncio.lock import Lock
from redis.exceptions import ConnectionError, RedisError, TimeoutError as RedisTimeoutError

# Optional cluster import (kept optional for environments without cluster)
try:  # pragma: no cover
    from redis.asyncio.cluster import RedisCluster  # type: ignore
except Exception:  # pragma: no cover
    RedisCluster = None  # type: ignore

from app.core.config import settings

logger = logging.getLogger("redis")

# ─────────────────────────────────────────────────────────────────────────────
# Tunables (env-aware sensible defaults)
# ─────────────────────────────────────────────────────────────────────────────
MAX_RETRIES = int(os.getenv("REDIS_CONNECT_MAX_RETRIES", "5"))
BASE_DELAY = float(os.getenv("REDIS_CONNECT_BASE_DELAY", "0.3"))  # seconds
HEALTH_CHECK_INTERVAL = int(os.getenv("REDIS_HEALTH_CHECK_INTERVAL", "30"))  # seconds
SOCKET_TIMEOUT = float(os.getenv("REDIS_SOCKET_TIMEOUT", "3"))
SOCKET_CONNECT_TIMEOUT = float(os.getenv("REDIS_SOCKET_CONNECT_TIMEOUT", "3"))
POOL_MAX_CONNECTIONS = int(os.getenv("REDIS_POOL_MAX_CONNECTIONS", "64"))
CLIENT_NAME = os.getenv("REDIS_CLIENT_NAME", "moviesnow-api")
DECODE_RESPONSES = os.getenv("REDIS_DECODE_RESPONSES", "true").lower() == "true"

# ─────────────────────────────────────────────────────────────────────────────
# Minimal protocol both redis.Redis and cluster clients satisfy (typing only)
# ─────────────────────────────────────────────────────────────────────────────
class _RedisProto(Protocol):
    async def ping(self) -> Any: ...
    async def script_load(self, script: str) -> Any: ...
    async def evalsha(self, sha: str, numkeys: int, *keys_and_args: Any) -> Any: ...
    async def eval(self, script: str, numkeys: int, *keys_and_args: Any) -> Any: ...
    async def set(self, name: str, value: Any, *, ex: Optional[int] = None, px: Optional[int] = None, nx: Optional[bool] = None) -> Any: ...
    async def setnx(self, name: str, value: Any) -> Any: ...
    async def expire(self, name: str, time: int) -> Any: ...
    async def get(self, name: str) -> Any: ...
    async def exists(self, *names: Any) -> Any: ...
    async def delete(self, *names: Any) -> Any: ...
    async def unlink(self, *names: Any) -> Any: ...
    def lock(self, name: str, timeout: int = ..., blocking_timeout: int = ..., sleep: float = ...) -> Lock: ...
    async def close(self) -> Any: ...

# ─────────────────────────────────────────────────────────────────────────────
# Lua script for atomic sliding-window rate limiting (ZSET)
# ─────────────────────────────────────────────────────────────────────────────
RATE_LIMIT_LUA = """
-- KEYS[1]  = zset key
-- KEYS[2]  = seq key
-- ARGV[1]  = now_ms
-- ARGV[2]  = window_ms
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[1] - ARGV[2])
local seq = redis.call('INCR', KEYS[2])
local member = ARGV[1] .. '-' .. seq
redis.call('ZADD', KEYS[1], ARGV[1], member)
redis.call('PEXPIRE', KEYS[1], ARGV[2])
redis.call('PEXPIRE', KEYS[2], ARGV[2])
return redis.call('ZCARD', KEYS[1])
"""

# ─────────────────────────────────────────────────────────────────────────────
# Client
# ─────────────────────────────────────────────────────────────────────────────
class RedisClient:
    """
    Singleton Redis/RedisCluster connection manager (asyncio).

    Features
    --------
    • Resilient connect with exponential backoff + jitter  
    • Optional Cluster support via `redis+cluster://` or `rediss+cluster://`  
    • Pooled connections, health checks  
    • Atomic sliding-window rate limit helper (Lua) with safe fallback  
    • Idempotency JSON helpers  
    • Async distributed lock helper  
    """

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._client: Optional[_RedisProto] = None
        self._is_cluster: bool = self._detect_cluster(redis_url)
        self._rate_limit_sha: Optional[str] = None

    # ── lifecycle ────────────────────────────────────────────────────────────
    async def connect(self) -> None:
        """
        Establish a connection with retries; pre-load the RL Lua script.

        Steps
        -----
        - **[Step 1]** Reuse a healthy client when possible.
        - **[Step 2]** Attempt connection with backoff and jitter.
        - **[Step 3]** Load Lua script (best-effort).
        """
        # ── [Step 1] Reuse an existing healthy client ───────────────────────
        if self._client:
            try:
                await self._client.ping()
                logger.debug("Redis already connected.")
                return
            except Exception:
                self._client = None  # stale client → reconnect

        attempt = 0
        last_err: Optional[Exception] = None

        # ── [Step 2] Retry with backoff ─────────────────────────────────────
        while attempt < MAX_RETRIES:
            attempt += 1
            try:
                self._client = await self._build_client()
                await self._client.ping()

                # ── [Step 3] Best-effort script preload ────────────────────
                try:
                    self._rate_limit_sha = await self._client.script_load(RATE_LIMIT_LUA)
                except Exception:
                    self._rate_limit_sha = None

                logger.info("✅ Connected to Redis%s", " (cluster)" if self._is_cluster else "")
                return
            except Exception as e:  # noqa: BLE001
                last_err = e
                delay = self._backoff(attempt)
                logger.warning(
                    "Redis connect attempt %s/%s failed: %s (retrying in %.2fs)",
                    attempt, MAX_RETRIES, repr(e), delay,
                )
                await asyncio.sleep(delay)

        logger.error("❌ Redis connection failed after %s retries.", MAX_RETRIES)
        raise RuntimeError("Redis connection failed") from last_err

    async def close(self) -> None:
        """
        Gracefully close connection & pool (alias: `disconnect`).

        Steps
        -----
        - **[Step 1]** Close logical client.
        - **[Step 2]** Disconnect pool (best-effort).
        - **[Step 3]** Reset local state.
        """
        if not self._client:
            return
        try:
            await self._client.close()
            pool = getattr(self._client, "connection_pool", None)
            if pool:
                try:
                    await pool.disconnect(inuse_connections=True)  # type: ignore[attr-defined]
                except Exception:
                    pass
            logger.info("🛑 Redis connection closed.")
        except RedisError as e:
            logger.warning("Error closing Redis connection: %s", e)
        finally:
            self._client = None
            self._rate_limit_sha = None

    # Back-compat alias
    disconnect = close

    async def is_connected(self) -> bool:
        """Return True if `PING` succeeds (healthy connection)."""
        if not self._client:
            return False
        try:
            return bool(await self._client.ping())
        except RedisError:
            return False

    @property
    def client(self) -> _RedisProto:
        """Low-level client; ensure `connect()` was called at startup."""
        if not self._client:
            raise RuntimeError("Redis client not initialized. Call connect() first.")
        return self._client

    # ── helpers: rate limiting / idempotency / JSON / lock ──────────────────
    async def rate_limit_sliding_window(
        self,
        key: str,
        *,
        max_ops: int,
        window_seconds: int,
        now_ms: Optional[int] = None,
    ) -> Tuple[int, bool]:
        """
        Sliding-window rate limit using a ZSET and an atomic Lua script.

        Step-by-step
        -----------
        1) Remove entries older than the current window.  
        2) Add a new, unique member for this hit.  
        3) Expire both keys with PEXPIRE.  
        4) Return current cardinality (count) and limited flag.

        Fallback
        --------
        If the client lacks EVAL/EVALSHA (e.g., minimal test mocks), keep a
        compact JSON list of timestamps and enforce TTL ≈ window. This path is
        **dev/test only** — production should use the Lua path.

        Returns
        -------
        tuple[int, bool] : (current_count, is_limited)
        """
        if not self._client:
            raise RuntimeError("Redis not connected")

        now_ms = now_ms or int(time.time() * 1000)
        window_ms = window_seconds * 1000

        try:
            # Preferred: evalsha → eval
            if self._rate_limit_sha and hasattr(self._client, "evalsha"):
                count = await self._client.evalsha(self._rate_limit_sha, 2, key, f"{key}:seq", now_ms, window_ms)
            elif hasattr(self._client, "eval"):
                count = await self._client.eval(RATE_LIMIT_LUA, 2, key, f"{key}:seq", now_ms, window_ms)
            else:
                raise AttributeError("Redis client lacks eval/evalsha")
            count = int(count)
            return count, count > max_ops

        except (AttributeError, NotImplementedError):
            # Dev/test fallback (no eval): JSON timestamp ring with px TTL
            try:
                jkey = f"{key}:pyrl"
                raw = await self._client.get(jkey)
                try:
                    arr = json.loads(raw) if raw else []
                except Exception:
                    arr = []
                cutoff = now_ms - window_ms
                arr = [t for t in arr if isinstance(t, int) and t >= cutoff]
                arr.append(now_ms)
                count = len(arr)
                await self._client.set(jkey, json.dumps(arr, separators=(",", ":")), px=window_ms)  # type: ignore[arg-type]
                return count, count > max_ops
            except Exception:
                logger.exception("rate_limit_sliding_window: fallback failed; fail-open")
                return 0, False

        except (ConnectionError, RedisTimeoutError):
            # Network/transient issue: fail-open
            logger.exception("rate_limit_sliding_window: Redis unavailable (fail-open).")
            return 0, False

    async def idempotency_set(self, key: str, value: Any, *, ttl_seconds: int = 86400) -> None:
        """Store a JSON snapshot for idempotent responses (atomic SET with EX)."""
        if not self._client:
            raise RuntimeError("Redis not connected")
        payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        await self._client.set(key, payload, ex=ttl_seconds)

    async def idempotency_get(self, key: str) -> Optional[Any]:
        """Load a JSON snapshot; tolerant of bytes/str payloads (defensive)."""
        if not self._client:
            raise RuntimeError("Redis not connected")
        raw = await self._client.get(key)
        if raw is None:
            return None
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", errors="replace")
        try:
            return json.loads(raw)
        except Exception:
            return None

    async def json_set(self, key: str, value: Any, *, ttl_seconds: Optional[int] = None) -> None:
        """Generic JSON setter with optional TTL."""
        if not self._client:
            raise RuntimeError("Redis not connected")
        data = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        if ttl_seconds:
            await self._client.set(key, data, ex=ttl_seconds)
        else:
            await self._client.set(key, data)

    async def json_get(self, key: str, default: Any = None) -> Any:
        """Generic JSON getter with sensible default on parse errors/None."""
        if not self._client:
            raise RuntimeError("Redis not connected")
        raw = await self._client.get(key)
        if raw is None:
            return default
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", errors="replace")
        try:
            return json.loads(raw)
        except Exception:
            return default

    @asynccontextmanager
    async def lock(
        self,
        name: str,
        *,
        timeout: int = 10,
        blocking_timeout: int = 3,
        sleep: float = 0.2,
    ):
        """
        Async distributed lock — production-grade with compatibility shims
        =================================================================

        Provides a process-safe mutex backed by Redis. Prefers the client’s native
        lock API and gracefully falls back to a portable `SETNX` spin-lock.

        Priority & Behavior
        -------------------
        1) **Native Redis lock** (`client.lock(...)`):
           - Try `lock(name, timeout=..., blocking_timeout=..., sleep=...)`.
           - Fallback to `lock(name, timeout=..., sleep=...)` if the client/mock
             doesn’t accept `blocking_timeout` (common in tests).
           - Attempt `acquire(blocking=True, blocking_timeout=...)`, then
             `acquire(blocking=True, timeout=...)`, then plain `acquire()` depending on signature.
           - Release in `finally`, best-effort.

        2) **SETNX spin-lock** (portable):
           - Repeatedly `SETNX` and `EXPIRE` until acquired or `blocking_timeout` elapses.
           - Only the **owner token** releases the key.
           - Works with skinny clients implementing only `setnx/get/expire/delete`.

        Failure semantics
        -----------------
        - If Redis is **not connected**, raise `RuntimeError`.
        - If not acquired within `blocking_timeout`, raise **built-in** `TimeoutError`.
        - Releases are best-effort; never crash the request.

        Steps
        -----
        - **[Step 1]** Validate connectivity.
        - **[Step 2]** Try native lock with signature fallbacks.
        - **[Step 3]** If unavailable, use `SETNX` spin-lock fallback.
        - **[Step 4]** Owner-only release on exit.
        """
        # ── [Step 1] Validate connectivity ─────────────────────────────────
        if not getattr(self, "_client", None):
            raise RuntimeError("Redis not connected")
        rc = self._client

        async def _maybe_await(res):
            """Await if awaitable; otherwise return the value."""
            return await res if inspect.isawaitable(res) else res

        # ── [Step 2] Native lock path (with signature fallbacks) ───────────
        if hasattr(rc, "lock"):
            lock_obj = None
            try:
                lock_obj = rc.lock(name, timeout=timeout, blocking_timeout=blocking_timeout, sleep=sleep)
            except TypeError:
                # skinny mock: no blocking_timeout kwarg
                try:
                    lock_obj = rc.lock(name, timeout=timeout, sleep=sleep)
                except TypeError:
                    try:
                        lock_obj = rc.lock(name, timeout=timeout)
                    except TypeError:
                        lock_obj = None

            if lock_obj is not None:
                acquired = False
                try:
                    try:
                        res = lock_obj.acquire(blocking=True, blocking_timeout=blocking_timeout)
                    except TypeError:
                        try:
                            res = lock_obj.acquire(blocking=True, timeout=blocking_timeout)
                        except TypeError:
                            res = lock_obj.acquire()
                    acquired = bool(await _maybe_await(res))
                    if not acquired:
                        raise TimeoutError(f"Failed to acquire lock: {name}")

                    yield  # critical section

                finally:
                    try:
                        if acquired:
                            rel = lock_obj.release()
                            if inspect.isawaitable(rel):
                                await rel
                    except Exception:
                        logger.debug("Redis native lock release failed (best-effort).", exc_info=True)
                return  # native lock path completed

        # ── [Step 3] SETNX token spin-lock fallback ────────────────────────
        token = f"{time.time_ns()}-{os.getpid()}-{random.randint(0, 1_000_000)}"
        deadline = time.monotonic() + max(0.0, float(blocking_timeout))
        acquired = False
        try:
            while time.monotonic() < deadline:
                ok = False
                try:
                    # Best path: kwargs (redis-py)
                    ok = await rc.set(name, token, ex=int(timeout), nx=True)
                except TypeError:
                    # Skinny client: emulate NX via SETNX + EXPIRE
                    if hasattr(rc, "setnx"):
                        ok = bool(await rc.setnx(name, token))
                        if ok:
                            try:
                                await rc.expire(name, int(timeout))
                            except Exception:
                                # couldn't set TTL → release and retry
                                try:
                                    await rc.delete(name)
                                except Exception:
                                    pass
                                ok = False
                    else:
                        # Last-resort dev/test path: if not exists -> SET+EX (racy, acceptable for tests)
                        try:
                            not_exists = not bool(await rc.exists(name)) if hasattr(rc, "exists") else True
                            if not_exists:
                                await rc.set(name, token, ex=int(timeout))
                                ok = True
                        except Exception:
                            ok = False

                if bool(ok):
                    acquired = True
                    break
                await asyncio.sleep(sleep)

            if not acquired:
                raise TimeoutError(f"Failed to acquire lock: {name}")

            yield  # critical section

        finally:
            # ── [Step 4] Best-effort owner-only release ────────────────────
            try:
                val = await rc.get(name) if hasattr(rc, "get") else token
                if isinstance(val, (bytes, bytearray)):
                    val = val.decode("utf-8", errors="ignore")
                if acquired and val == token:
                    try:
                        await rc.delete(name)
                    except Exception:
                        pass
            except Exception:
                pass

    # ── internals ───────────────────────────────────────────────────────────
    async def _build_client(self) -> _RedisProto:
        """Instantiate Redis or RedisCluster client with sane pool options from URL."""
        url = self.redis_url.strip()
        parsed = urlparse(url)
        client_kwargs = dict(
            decode_responses=DECODE_RESPONSES,
            health_check_interval=HEALTH_CHECK_INTERVAL,
            socket_keepalive=True,
            socket_timeout=SOCKET_TIMEOUT,
            socket_connect_timeout=SOCKET_CONNECT_TIMEOUT,
            retry_on_timeout=True,
            max_connections=POOL_MAX_CONNECTIONS,
            client_name=CLIENT_NAME,
        )

        # TLS handling for rediss://*
        if parsed.scheme.startswith("rediss"):
            cert_reqs = os.getenv("REDIS_SSL_CERT_REQS", "required").lower()
            if cert_reqs == "none":  # dev only; not recommended for prod
                client_kwargs["ssl_cert_reqs"] = None  # type: ignore

        if self._is_cluster and RedisCluster is not None:  # runtime path
            return RedisCluster.from_url(url, **client_kwargs)  # type: ignore
        return redis.Redis.from_url(url, **client_kwargs)

    @staticmethod
    def _detect_cluster(url: str) -> bool:
        scheme = urlparse(url).scheme
        return scheme in ("redis+cluster", "rediss+cluster")

    @staticmethod
    def _backoff(attempt: int) -> float:
        # Exponential backoff with jitter (cap at 3s)
        return min(3.0, BASE_DELAY * (2 ** (attempt - 1))) + random.uniform(0, 0.25)


# ─────────────────────────────────────────────────────────────────────────────
# Singleton instance + FastAPI dependency
# ─────────────────────────────────────────────────────────────────────────────
redis_wrapper = RedisClient(getattr(settings, "REDIS_URL", "redis://localhost:6379/0"))

async def get_redis() -> _RedisProto:
    """
    FastAPI dependency that returns the active client.

    Behavior
    --------
    • In production, `main.py` should call `await redis_wrapper.connect()` on startup.  
    • In dev/test, if startup didn’t run yet, this tries a best-effort connect so routes
      don’t crash; failures are logged. Callers still get a clear error if they access
      `.client` without a connection.
    """
    if not await redis_wrapper.is_connected():
        try:
            await redis_wrapper.connect()
        except Exception:
            # Fail-open to avoid breaking requests that can degrade gracefully
            logger.exception("get_redis: unable to ensure connection; using lazy client")
    return redis_wrapper.client
