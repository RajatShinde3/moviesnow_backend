from __future__ import annotations

"""
MockRedisClient (async) — test-grade, wrapper-compatible
========================================================
Covers the subset of Redis used across the codebase:

KV        : get/set/setex/psetex/setnx/mget/exists/ttl/pttl/expire/pexpire/incr/decr
Delete    : delete/unlink/flushdb/execute_command("UNLINK", ...)
Sets      : sadd/srem/smembers/sismember
Hashes    : hset/hget/hdel/hgetall
Scan      : keys/scan/scan_iter (glob match)
Health    : ping/close/info/dbsize
Pipeline  : chainable pipeline with async execute() and async context manager
Lua       : eval()/evalsha() supporting:
            • INCR + (first-hit) EXPIRE (rate-limit/attempts)
            • GET + compare token + DEL (unlock script)
            Keyword form eval(script, keys=[...], args=[...]) supported.
Lock      : lock(name, timeout=..., blocking_timeout=..., sleep=...) → MockLock
            acquire()/release() and async context manager

Design notes
------------
- Values are stored exactly as written (bytes or str). TTLs are second/ms precision.
- Deterministic, minimal behavior for tests; not a byte-for-byte Redis emulation.
- Friendly with `app.core.redis_client.redis_wrapper` and utilities relying on
  `scan_iter`, `UNLINK`, pipelines, `_eval_compat` helpers, etc.
"""

from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any, AsyncIterator, Dict, Iterable, List, Mapping, Optional, Tuple, Union
import asyncio
import hashlib
import time
import secrets

# ─────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────

_DEF_EXPIRE_NONE = None


def _now() -> float:
    return time.time()


def _ensure_text(v) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        return v.decode("utf-8", errors="replace")
    return str(v)


# ─────────────────────────────────────────────────────────────
# Core mock client
# ─────────────────────────────────────────────────────────────

class MockRedisClient:
    
    def __init__(self) -> None:
        # Simple key spaces by type
        self.store: Dict[str, Any] = {}               # strings / bytes
        self.expirations: Dict[str, Optional[float]] = {}  # epoch seconds or None
        self.sets: Dict[str, set] = {}
        self.hashes: Dict[str, Dict[str, Any]] = {}
        self.lists: Dict[str, List[Any]] = {}
        # Lua registry for script_load/evalsha
        self._sha_to_script: Dict[str, str] = {}
        # Tiny in-memory locks
        self._locks: Dict[str, str] = {}  # key -> token
        self._closed = False

    async def rpush(self, key: str, value: str) -> int:
        """Simulate RPUSH for adding elements to a Redis list."""
        if key not in self.lists:
            self.lists[key] = []  # Create list if it doesn't exist
        self.lists[key].append(value)  # Append to the list
        return len(self.lists[key])  # Return the new length of the list

    async def llen(self, key: str) -> int:
        """Simulate LLEN to return the length of a Redis list."""
        return len(self.lists.get(key, []))  # Return length of the list

    async def lrange(self, key: str, start: int, end: int) -> List[Any]:
        """Simulate LRANGE with Redis semantics (inclusive end, supports negatives)."""
        lst = self.lists.get(key, [])
        n = len(lst)
        # Normalize negative indices
        if start < 0:
            start = n + start
        if end < 0:
            end = n + end
        # Clamp bounds
        if start < 0:
            start = 0
        if end < 0 or start >= n:
            return []
        if end >= n:
            end = n - 1
        if start > end:
            return []
        # Inclusive end
        return list(lst[start:end + 1])

    async def ltrim(self, key: str, start: int, end: int) -> bool:
        """Simulate LTRIM keeping only the specified inclusive range."""
        lst = self.lists.get(key, [])
        n = len(lst)
        if n == 0:
            self.lists[key] = []
            return True
        # Normalize negative indices
        if start < 0:
            start = n + start
        if end < 0:
            end = n + end
        # Clamp bounds similar to Redis behavior
        if start < 0:
            start = 0
        if end < 0:
            # Entire list trimmed away
            self.lists[key] = []
            return True
        if start >= n:
            self.lists[key] = []
            return True
        if end >= n:
            end = n - 1
        if start > end:
            self.lists[key] = []
            return True
        self.lists[key] = list(lst[start:end + 1])
        return True

    # ── housekeeping ──────────────────────────────────────────
    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        self._closed = True

    async def flushdb(self) -> None:
        self.store.clear()
        self.expirations.clear()
        self.sets.clear()
        self.hashes.clear()
        self.lists.clear()
        self._locks.clear()
        self._sha_to_script.clear()

    # Some test suites call flushall; treat it as flushdb in this mock
    async def flushall(self) -> None:
        await self.flushdb()

    async def info(self) -> Dict[str, Any]:
        return {"redis_version": "mock", "connected_clients": 1}

    async def dbsize(self) -> int:
        # count live keys across spaces (approx)
        self._purge_expired()
        live = set(self.store.keys()) | set(self.sets.keys()) | set(self.hashes.keys())
        return len(live)

    # ── expiration helpers ────────────────────────────────────
    def _expired(self, key: str) -> bool:
        exp = self.expirations.get(key, _DEF_EXPIRE_NONE)
        return exp is not None and exp <= _now()

    def _purge_expired(self) -> None:
        for k in list(self.store.keys()):
            if self._expired(k):
                self.store.pop(k, None)
                self.expirations.pop(k, None)
        for k in list(self.sets.keys()):
            if self._expired(k):
                self.sets.pop(k, None)
                self.expirations.pop(k, None)
        for k in list(self.hashes.keys()):
            if self._expired(k):
                self.hashes.pop(k, None)
                self.expirations.pop(k, None)

    def _set_expiration(self, key: str, *, ex: Optional[int] = None, px: Optional[int] = None, keepttl: bool = False) -> None:
        if keepttl:
            return
        if ex is not None:
            self.expirations[key] = _now() + int(ex)
        elif px is not None:
            self.expirations[key] = _now() + (int(px) / 1000.0)
        else:
            self.expirations[key] = _DEF_EXPIRE_NONE

    # ─────────────────────────────────────────────────────────
    # String / KV commands
    # ─────────────────────────────────────────────────────────

    async def get(self, key: str) -> Optional[Any]:
        self._purge_expired()
        return self.store.get(key)

    async def mget(self, *keys: str) -> List[Optional[Any]]:
        self._purge_expired()
        out: List[Optional[Any]] = []
        for k in keys:
            out.append(self.store.get(k) if not self._expired(k) else None)
        return out

    async def set(
        self,
        key: str,
        value: Any,
        ex: Optional[int] = None,
        px: Optional[int] = None,
        nx: bool = False,
        xx: bool = False,
        keepttl: bool = False,
    ) -> bool:
        self._purge_expired()
        exists = key in self.store and not self._expired(key)
        if nx and exists:
            return False
        if xx and not exists:
            return False
        self.store[key] = value
        self._set_expiration(key, ex=ex, px=px, keepttl=keepttl)
        return True

    async def setex(self, key: str, time_seconds: int, value: Any) -> bool:
        return await self.set(key, value, ex=int(time_seconds))

    async def psetex(self, key: str, time_ms: int, value: Any) -> bool:
        return await self.set(key, value, px=int(time_ms))

    async def setnx(self, key: str, value: Any) -> bool:
        return await self.set(key, value, nx=True)

    async def incr(self, key: str, amount: int = 1) -> int:
        self._purge_expired()
        cur = int(self.store.get(key, 0))
        cur += int(amount)
        self.store[key] = cur
        return cur

    async def decr(self, key: str, amount: int = 1) -> int:
        return await self.incr(key, -int(amount))

    async def expire(self, key: str, time_seconds: int) -> bool:
        if key in self.store or key in self.sets or key in self.hashes:
            self.expirations[key] = _now() + int(time_seconds)
            return True
        return False

    async def pexpire(self, key: str, time_ms: int) -> bool:
        if key in self.store or key in self.sets or key in self.hashes:
            self.expirations[key] = _now() + (int(time_ms) / 1000.0)
            return True
        return False

    async def ttl(self, key: str) -> int:
        self._purge_expired()
        if key not in self.store and key not in self.sets and key not in self.hashes:
            return -2
        exp = self.expirations.get(key, _DEF_EXPIRE_NONE)
        if exp is None:
            return -1
        ttl = int(round(exp - _now()))
        return max(ttl, -2)

    async def pttl(self, key: str) -> int:
        self._purge_expired()
        if key not in self.store and key not in self.sets and key not in self.hashes:
            return -2
        exp = self.expirations.get(key, _DEF_EXPIRE_NONE)
        if exp is None:
            return -1
        ttl_ms = int(round((exp - _now()) * 1000))
        return max(ttl_ms, -2)

    async def exists(self, *keys: str) -> int:
        self._purge_expired()
        count = 0
        for k in keys:
            if (k in self.store or k in self.sets or k in self.hashes) and not self._expired(k):
                count += 1
        return count

    async def delete(self, *keys: str) -> int:
        removed = 0
        for k in keys:
            removed += int(self.store.pop(k, None) is not None)
            removed += int(self.sets.pop(k, None) is not None)
            removed += int(self.hashes.pop(k, None) is not None)
            self.expirations.pop(k, None)
        return removed

    async def unlink(self, *keys: str) -> int:
        # behave like DEL in the mock
        return await self.delete(*keys)

    async def execute_command(self, cmd: str, *args: Any, **kwargs: Any) -> Any:
        # minimal support for UNLINK fallback paths
        if cmd.upper() == "UNLINK":
            return await self.unlink(*args)
        if cmd.upper() == "DEL":
            return await self.delete(*args)
        raise NotImplementedError(f"execute_command({cmd}) not supported in mock")

    # ─────────────────────────────────────────────────────────
    # Set commands
    # ─────────────────────────────────────────────────────────

    async def sadd(self, key: str, *members: Any) -> int:
        self._purge_expired()
        s = self.sets.setdefault(key, set())
        before = len(s)
        s.update(members)
        return len(s) - before

    async def srem(self, key: str, *members: Any) -> int:
        s = self.sets.setdefault(key, set())
        before = len(s)
        for m in members:
            s.discard(m)
        return before - len(s)

    async def smembers(self, key: str) -> set:
        self._purge_expired()
        return set(self.sets.get(key, set()))

    async def sismember(self, key: str, member: Any) -> bool:
        self._purge_expired()
        return member in self.sets.get(key, set())

    # ─────────────────────────────────────────────────────────
    # Hash commands
    # ─────────────────────────────────────────────────────────

    async def hset(self, name: str, mapping: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> int:
        h = self.hashes.setdefault(name, {})
        count = 0
        data: Dict[str, Any] = {}
        if mapping:
            data.update(mapping)
        if kwargs:
            data.update(kwargs)
        for k, v in data.items():
            if k not in h:
                count += 1
            h[k] = v
        return count

    async def hget(self, name: str, key: str) -> Optional[Any]:
        self._purge_expired()
        return self.hashes.get(name, {}).get(key)

    async def hdel(self, name: str, *keys: str) -> int:
        h = self.hashes.get(name, {})
        removed = 0
        for k in keys:
            if k in h:
                removed += 1
                del h[k]
        return removed

    async def hgetall(self, name: str) -> Dict[str, Any]:
        self._purge_expired()
        return dict(self.hashes.get(name, {}))

    # ─────────────────────────────────────────────────────────
    # Scans
    # ─────────────────────────────────────────────────────────

    async def keys(self, pattern: str = "*") -> List[str]:
        self._purge_expired()
        all_keys = set(self.store.keys()) | set(self.sets.keys()) | set(self.hashes.keys())
        return [k for k in all_keys if fnmatch(k, pattern)]

    async def scan(self, cursor: Union[int, str, bytes] = 0, match: Optional[str] = None, count: Optional[int] = None) -> Tuple[Union[int, str, bytes], List[str]]:
        # Deterministic: return all matches in one go.
        matched = await self.keys(match or "*")
        # Return cursor type consistent with input (tests sometimes check for "0" / b"0")
        if isinstance(cursor, (bytes, bytearray)):
            return b"0", matched
        if isinstance(cursor, str):
            return "0", matched
        return 0, matched

    async def scan_iter(self, match: Optional[str] = None, count: Optional[int] = None) -> AsyncIterator[str]:
        for k in await self.keys(match or "*"):
            yield k

    # ─────────────────────────────────────────────────────────
    # Lua: script_load / evalsha / eval (with keyword compatibility)
    # ─────────────────────────────────────────────────────────

    async def script_load(self, script: str) -> str:
        sha = hashlib.sha1(script.encode("utf-8")).hexdigest()
        self._sha_to_script[sha] = script
        return sha

    async def evalsha(self, sha: str, numkeys: int, *keys_and_args: Any) -> Any:
        script = self._sha_to_script.get(sha)
        if script is None:
            raise NotImplementedError("evalsha: unknown sha")
        return await self.eval(script, numkeys, *keys_and_args)

    async def eval(self, script: str, *args: Any, **kwargs: Any) -> Any:
        """
        Minimal `EVAL` supporting:
          • INCR + (first) EXPIRE  (rate-limit / attempts)     → numkeys == 1
          • GET + compare token + DEL (unlock)                 → numkeys == 1

        Accepts:
          eval(script, numkeys, *keys_and_args)
          eval(script, keys=[...], args=[...])
          eval(script, numkeys, keys_list, args_list)  # some mocks
        """
        # Normalize signature
        if "keys" in kwargs or "args" in kwargs:
            keys = list(kwargs.get("keys") or [])
            argv = list(kwargs.get("args") or [])
            numkeys = len(keys)
            keys_and_args: List[Any] = [*keys, *argv]
        else:
            if not args:
                raise ValueError("eval requires arguments")
            if isinstance(args[0], int):
                numkeys = int(args[0])
                keys_and_args = list(args[1:])
                # Allow some libs that pass (numkeys, keys_list, args_list)
                if len(keys_and_args) == 2 and isinstance(keys_and_args[0], (list, tuple)) and isinstance(keys_and_args[1], (list, tuple)):
                    keys_and_args = list(keys_and_args[0]) + list(keys_and_args[1])
            else:
                # Fallback: assume all in keys_and_args
                numkeys = 0
                keys_and_args = list(args)

        self._purge_expired()
        script_upper = script.upper()

        # Pattern 1: rate-limit / attempts (INCR + conditional EXPIRE) on KEYS[1], ARGV[1] = ttl
        if "INCR" in script_upper and "EXPIRE" in script_upper and numkeys == 1:
            if not keys_and_args:
                raise ValueError("eval expected at least a key")
            key = str(keys_and_args[0])
            ttl = int(keys_and_args[1]) if len(keys_and_args) > 1 else 0
            current = int(self.store.get(key, 0)) + 1
            self.store[key] = current
            if current == 1 and ttl > 0:
                self._set_expiration(key, ex=ttl)
            return current

        # Pattern 2: unlock script (compare-and-delete)
        if "GET" in script_upper and "DEL" in script_upper and numkeys == 1:
            if len(keys_and_args) < 2:
                raise ValueError("eval expected key and token")
            key = str(keys_and_args[0])
            token = str(keys_and_args[1])
            if self._expired(key):
                self.store.pop(key, None)
                self.expirations.pop(key, None)
                return 0
            if _ensure_text(self.store.get(key)) == token:
                self.store.pop(key, None)
                self.expirations.pop(key, None)
                return 1
            return 0

        # Any other scripts (e.g., ZSET sliding-window RL) are not implemented → allow caller fallback.
        raise NotImplementedError("MockRedisClient.eval: script pattern not supported")

    # ─────────────────────────────────────────────────────────
    # Pipeline
    # ─────────────────────────────────────────────────────────

    def pipeline(self) -> "MockPipeline":
        return MockPipeline(self)

    # ─────────────────────────────────────────────────────────
    # Lock API (permissive signature for wrapper fallbacks)
    # ─────────────────────────────────────────────────────────

    def lock(self, name: str, timeout: Optional[int] = None, blocking_timeout: Optional[int] = None, sleep: Optional[float] = None) -> "MockLock":
        # Extra kwargs are accepted for compatibility; only timeout is used by the mock.
        return MockLock(self, name, timeout or 10)


class MockPipeline:
    def __init__(self, client: MockRedisClient) -> None:
        self.client = client
        self.ops: List[Tuple[str, Tuple[Any, ...], Dict[str, Any]]] = []
        self._closed = False

    # queue helper
    def _queue(self, method: str, *args: Any, **kwargs: Any) -> "MockPipeline":
        self.ops.append((method, args, kwargs))
        return self

    # Mirror a subset of client methods for chaining
    def set(self, *args: Any, **kwargs: Any) -> "MockPipeline":       return self._queue("set", *args, **kwargs)
    def setex(self, *args: Any, **kwargs: Any) -> "MockPipeline":     return self._queue("setex", *args, **kwargs)
    def sadd(self, *args: Any, **kwargs: Any) -> "MockPipeline":      return self._queue("sadd", *args, **kwargs)
    def srem(self, *args: Any, **kwargs: Any) -> "MockPipeline":      return self._queue("srem", *args, **kwargs)
    def delete(self, *args: Any, **kwargs: Any) -> "MockPipeline":    return self._queue("delete", *args, **kwargs)
    def unlink(self, *args: Any, **kwargs: Any) -> "MockPipeline":    return self._queue("unlink", *args, **kwargs)
    def expire(self, *args: Any, **kwargs: Any) -> "MockPipeline":    return self._queue("expire", *args, **kwargs)
    def hset(self, *args: Any, **kwargs: Any) -> "MockPipeline":      return self._queue("hset", *args, **kwargs)
    def hdel(self, *args: Any, **kwargs: Any) -> "MockPipeline":      return self._queue("hdel", *args, **kwargs)

    async def execute(self) -> List[Any]:
        results: List[Any] = []
        for method, args, kwargs in self.ops:
            func = getattr(self.client, method)
            res = await func(*args, **kwargs)
            results.append(res)
        self.ops.clear()
        return results

    # async context manager support
    async def __aenter__(self) -> "MockPipeline":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self._closed = True


class MockLock:
    """
    Tiny async lock helper with SET NX semantics.

    Methods
    -------
    acquire(...): bool   # accepts extraneous kwargs (blocking/timeout) for compatibility
    release(): None
    async context manager support
    """

    def __init__(self, client: MockRedisClient, name: str, timeout: int) -> None:
        self.client = client
        self.name = name
        self.timeout = timeout
        self.token: Optional[str] = None
        self._key = f"lock:{name}"

    async def acquire(self, *_, **__) -> bool:
        token = self.token or secrets.token_urlsafe(12)
        ok = await self.client.set(self._key, token, ex=self.timeout, nx=True)
        if ok:
            self.token = token
        return bool(ok)

    async def release(self) -> None:
        val = await self.client.get(self._key)
        if val == self.token:
            await self.client.delete(self._key)
            self.token = None

    # async context manager
    async def __aenter__(self) -> "MockLock":
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.release()


__all__ = [
    "MockRedisClient",
    "MockPipeline",
    "MockLock",
]
