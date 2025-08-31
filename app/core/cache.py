from __future__ import annotations

import time
from typing import Any, Dict, Optional


class TTLMap:
    """In-memory TTL map for small caches.

    - get(key) -> Optional[Any]
    - set(key, value, ttl_seconds)
    """

    def __init__(self, maxsize: int = 4096):
        self.maxsize = maxsize
        self._data: Dict[str, Any] = {}
        self._exp: Dict[str, float] = {}

    def get(self, key: str) -> Optional[Any]:
        exp = self._exp.get(key)
        if exp is None:
            return None
        if time.time() >= exp:
            try:
                del self._data[key]
                del self._exp[key]
            except Exception:
                pass
            return None
        return self._data.get(key)

    def set(self, key: str, value: Any, ttl_seconds: int):
        if len(self._data) >= self.maxsize:
            try:
                old_key = next(iter(self._data))
                del self._data[old_key]
                self._exp.pop(old_key, None)
            except StopIteration:
                pass
        self._data[key] = value
        self._exp[key] = time.time() + ttl_seconds


class TTLCache:
    """Idempotency/deduplication TTL cache storing only expirations (seen semantics)."""

    def __init__(self, maxsize: int = 4096):
        self.maxsize = maxsize
        self._exp: Dict[str, float] = {}

    def set(self, key: str, ttl_seconds: int):
        if len(self._exp) >= self.maxsize:
            try:
                self._exp.pop(next(iter(self._exp)))
            except StopIteration:
                pass
        self._exp[key] = time.time() + ttl_seconds

    def seen(self, key: str) -> bool:
        exp = self._exp.get(key)
        if exp is None:
            return False
        if time.time() > exp:
            try:
                del self._exp[key]
            except Exception:
                pass
            return False
        return True

