# app/cache/invalidation.py
from __future__ import annotations

"""
# MoviesNow — Redis Cache Invalidation (production-grade)

Non-blocking, batched invalidation for catalog, playback/entitlement, and
personalization caches.

## Key properties
- Uses the shared `app.core.redis_client.redis_wrapper.client` (single pool).
- SCAN/scan_iter key discovery (no blocking KEYS).
- Prefers `UNLINK` (non-blocking) with `DEL` fallback.
- Bytes/str tolerant; safe batching; graceful partial failures.
- Low-cardinality metrics + structured logs (optional).

## Public API
- invalidate_title_related_caches(title_id, region=None, extra_patterns=(), batch=512) -> int
- invalidate_series_related_caches(series_id, extra_patterns=(), batch=512) -> int
- invalidate_entitlement_caches(user_id, title_id=None, batch=512) -> int
- invalidate_user_personalization_caches(user_id, batch=512) -> int

## Usage
>>> removed = await invalidate_title_related_caches(123)
>>> removed = await invalidate_entitlement_caches(user_id=42, title_id=123)
"""

from typing import AsyncIterable, List, Sequence, Optional
import logging

# ─────────────────────────────────────────────────────────────
# Redis wrapper (single source of truth)
# ─────────────────────────────────────────────────────────────
try:
    from app.core.redis_client import redis_wrapper  # type: ignore
except Exception:  # pragma: no cover
    redis_wrapper = None  # type: ignore

# ─────────────────────────────────────────────────────────────
# Observability (optional) with safe fallbacks
# ─────────────────────────────────────────────────────────────
try:  # pragma: no cover - optional dependency
    from app.observability import logger as obs_logger, metrics as obs_metrics  # type: ignore
except Exception:  # pragma: no cover
    obs_logger = logging.getLogger("cache-invalidation")

    class _NoopCounter:
        def labels(self, *_, **__): return self
        def inc(self, *_): return None

    class _NoopMetrics:
        def counter(self, *_args, **_kwargs): return _NoopCounter()

    obs_metrics = _NoopMetrics()  # type: ignore

# Low-cardinality counters : outcome in {success,error,no_client}
_cache_inval_total = obs_metrics.counter(
    "cache_invalidation_requests_total",
    "Total MoviesNow cache invalidation attempts",
    ("kind", "outcome"),
)
_cache_inval_deleted = obs_metrics.counter(
    "cache_invalidation_keys_deleted_total",
    "Number of Redis keys deleted during invalidation",
    ("kind",),
)

__all__ = [
    "invalidate_title_related_caches",
    "invalidate_series_related_caches",
    "invalidate_entitlement_caches",
    "invalidate_user_personalization_caches",
]

# ─────────────────────────────────────────────────────────────
# Small helpers
# ─────────────────────────────────────────────────────────────

def _rc():
    """Resolve the async Redis client from the shared wrapper (or None)."""
    try:
        return getattr(redis_wrapper, "client", None) if redis_wrapper else None
    except Exception:
        return None

def _ensure_text(v) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        return v.decode("utf-8", errors="replace")
    return str(v)

async def _scan_iter_keys(rc, pattern: str, *, count: int) -> AsyncIterable[str]:
    """
    Yield keys matching `pattern` using non-blocking iteration.

    Preference:
      1) rc.scan_iter(match=..., count=...)
      2) rc.scan(cursor=..., match=..., count=...)
    """
    if hasattr(rc, "scan_iter"):
        async for k in rc.scan_iter(match=pattern, count=count):  # type: ignore[attr-defined]
            s = _ensure_text(k)
            if s:
                yield s
        return

    cursor = 0
    while True:
        cursor, keys = await rc.scan(cursor=cursor, match=pattern, count=count)  # type: ignore[attr-defined]
        for k in keys or []:
            s = _ensure_text(k)
            if s:
                yield s
        if not cursor:
            break

async def _unlink_or_delete_many(rc, keys: List[str]) -> int:
    """Attempt non-blocking UNLINK; fallback to DEL. Chunked for safety."""
    if not keys:
        return 0
    deleted = 0
    try:
        if hasattr(rc, "unlink"):
            for i in range(0, len(keys), 512):
                try:
                    deleted += int(await rc.unlink(*keys[i:i + 512]))  # type: ignore[attr-defined]
                except Exception:
                    deleted += int(await rc.delete(*keys[i:i + 512]))
            return deleted
    except Exception:
        pass

    for i in range(0, len(keys), 512):
        try:
            deleted += int(await rc.delete(*keys[i:i + 512]))
        except Exception:
            # best-effort: skip failures in this chunk
            pass
    return deleted

async def _delete_by_patterns(kind: str, patterns: Sequence[str], *, batch: int) -> int:
    """Scan and delete keys for a set of patterns; returns total deleted."""
    rc = _rc()
    if rc is None:
        obs_logger.debug("cache_invalidation_no_redis_client", extra={"kind": kind})
        _cache_inval_total.labels(kind, "no_client").inc()
        return 0

    deleted_total = 0
    try:
        for pat in patterns:
            batch_keys: List[str] = []
            async for key in _scan_iter_keys(rc, pat, count=batch):
                batch_keys.append(key)
                if len(batch_keys) >= batch:
                    deleted_total += await _unlink_or_delete_many(rc, batch_keys)
                    batch_keys.clear()
            if batch_keys:
                deleted_total += await _unlink_or_delete_many(rc, batch_keys)

        _cache_inval_total.labels(kind, "success").inc()
        _cache_inval_deleted.labels(kind).inc(deleted_total)
        if deleted_total:
            obs_logger.info("cache_invalidation_done", extra={"kind": kind, "deleted": int(deleted_total)})
        else:
            obs_logger.debug("cache_invalidation_no_keys", extra={"kind": kind})
        return int(deleted_total)

    except Exception:
        _cache_inval_total.labels(kind, "error").inc()
        obs_logger.exception("cache_invalidation_failed", extra={"kind": kind})
        return int(deleted_total)

def _clamp_batch(batch: int) -> int:
    if not isinstance(batch, int):
        return 512
    return max(50, min(5000, batch))

# ─────────────────────────────────────────────────────────────
# Public invalidators — MoviesNow cache domains
# ─────────────────────────────────────────────────────────────

async def invalidate_title_related_caches(
    title_id: int,
    *,
    region: Optional[str] = None,
    extra_patterns: Sequence[str] = (),
    batch: int = 512,
) -> int:
    """
    Invalidate caches related to a **single title** (movie or series root).

    Behavior
    --------
    • Catalog metadata, assets & posters, captions, and title-scoped search index hints.
    • Region-scoped home rails when `region` is specified.
    • Optional extra patterns merged and deduped.

    Parameters
    ----------
    title_id : int
        Target title identifier.
    region : str, optional
        Region code (e.g., \"IN\", \"US\") to scope home rails invalidation.
    extra_patterns : Sequence[str], optional
        Additional Redis glob patterns to include.
    batch : int, default 512
        SCAN/UNLINK batch size (clamped 50..5000).

    Returns
    -------
    int
        Number of keys removed (best-effort).
    """
    batch = _clamp_batch(batch)

    base_patterns: List[str] = [
        # Catalog/title surfaces
        f"catalog:v1:title:{title_id}:*",
        f"assets:v1:title:{title_id}:*",
        f"captions:v1:title:{title_id}:*",
        f"imagecache:v1:title:{title_id}:*",

        # Search/discovery hints (title-scoped shards)
        f"search:v1:title:{title_id}:*",
        f"recommend:v1:title:{title_id}:*",

        # Playback metadata (NOT signed URLs; just cached manifests/meta)
        f"manifestmeta:v1:title:{title_id}:*",
    ]

    if region:
        base_patterns.append(f"rails:v1:home:region:{region}:*")

    # Deduplicate while preserving order
    seen = set()
    patterns: List[str] = []
    for p in [*base_patterns, *list(extra_patterns or [])]:
        if p not in seen:
            patterns.append(p)
            seen.add(p)

    return await _delete_by_patterns("title", patterns, batch=batch)


async def invalidate_series_related_caches(
    series_id: int,
    *,
    extra_patterns: Sequence[str] = (),
    batch: int = 512,
) -> int:
    """
    Invalidate caches for a **series** and its season/episode lists.

    Parameters
    ----------
    series_id : int
        Series root identifier.
    extra_patterns : Sequence[str], optional
        Additional patterns to include.
    batch : int, default 512
        SCAN/UNLINK batch size (clamped 50..5000).
    """
    batch = _clamp_batch(batch)

    base_patterns: List[str] = [
        f"catalog:v1:series:{series_id}:*",
        f"seasons:v1:series:{series_id}:*",
        f"episodes:v1:series:{series_id}:*",
        f"search:v1:series:{series_id}:*",
        f"rails:v1:series:{series_id}:*",
    ]
    seen = set()
    patterns: List[str] = []
    for p in [*base_patterns, *list(extra_patterns or [])]:
        if p not in seen:
            patterns.append(p)
            seen.add(p)

    return await _delete_by_patterns("series", patterns, batch=batch)


async def invalidate_entitlement_caches(
    user_id: int,
    title_id: Optional[int] = None,
    *,
    batch: int = 512,
) -> int:
    """
    Invalidate **entitlement/access** caches for a user (optionally scoped to a title).

    Typical triggers:
    - Payment success/refund, subscription state change
    - License window/region updates, manual admin grants
    - Device limit changes impacting access

    Parameters
    ----------
    user_id : int
        User/account identifier.
    title_id : int, optional
        If provided, narrows invalidation to specific title-related entries.
    batch : int, default 512
        SCAN/UNLINK batch size (clamped 50..5000).
    """
    batch = _clamp_batch(batch)

    base_patterns: List[str] = [
        f"entitlement:v1:user:{user_id}:*",
        f"play:access:v1:user:{user_id}:*",
        f"downloads:eligibility:v1:user:{user_id}:*",
        f"limits:concurrency:v1:user:{user_id}:*",
    ]
    if title_id is not None:
        base_patterns.extend([
            f"entitlement:v1:user:{user_id}:title:{title_id}",
            f"play:access:v1:user:{user_id}:title:{title_id}",
            f"downloads:eligibility:v1:user:{user_id}:title:{title_id}",
        ])

    return await _delete_by_patterns("entitlement", base_patterns, batch=batch)


async def invalidate_user_personalization_caches(
    user_id: int,
    *,
    batch: int = 512,
) -> int:
    """
    Invalidate **personalization** caches for a user.

    Typical triggers:
    - New watch events, ratings/likes, language/genre preference edits
    - Parental controls toggles
    - Profile changes impacting home rails

    Parameters
    ----------
    user_id : int
        User/account identifier.
    batch : int, default 512
        SCAN/UNLINK batch size (clamped 50..5000).
    """
    batch = _clamp_batch(batch)
    patterns: List[str] = [
        f"recommend:v1:user:{user_id}:*",
        f"continuewatching:v1:user:{user_id}:*",
        f"history:v1:user:{user_id}:*",
        f"rails:v1:home:user:{user_id}:*",
        f"search:recent:v1:user:{user_id}:*",
        f"downloads:list:v1:user:{user_id}:*",
    ]
    return await _delete_by_patterns("personalization", patterns, batch=batch)
