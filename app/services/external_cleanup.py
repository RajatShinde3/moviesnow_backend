# app/services/external_cleanup.py
from __future__ import annotations

"""
MoviesNow — External Artifact Cleanup (async, production-grade)
==============================================================

Best-effort removal of per-**session** artifacts after a stream ends, a
download is canceled, or a user signs out. This module is **org-free** and
tailored to MoviesNow’s domain.

What it cleans
--------------
- 🔑 Redis: transient tokens / session state / device & playback lanes
- 📦 Storage: per-session user artifacts (via app storage or S3)
- 🌐 CDN: cache entries for session/titles (optional)
- 🔎 Search: per-session search documents (optional)
- 🏷️ Cache tags: session/user/title tags (optional; aligns with `app.utils.cache`)

Design goals
------------
- Single source of truth for Redis via `app.core.redis_client.redis_wrapper`
- Non-blocking key discovery (SCAN/scan_iter), UNLINK preferred, DEL fallback
- Strictly **best-effort**: never raises to callers, returns a structured summary
- Pluggable providers (storage/search/cdn) with safe import guards
- Concurrency + bounded retries with jitter

Usage
-----
    from uuid import uuid4
    from app.services.external_cleanup import cleanup_external_artifacts

    result = await cleanup_external_artifacts(
        session_id=uuid4(),
        user_id=uuid4(),          # optional but recommended
        title_id=uuid4(),         # optional (when invalidating title CDN)
    )

Returned shape
--------------
{
  "session_id": "...", "user_id": "...", "title_id": "...",
  "started_at": "...", "finished_at": "...",
  "redis": {"deleted": 0, "errors": []},
  "storage": {"deleted_objects": 0, "errors": []},
  "cdn": {"invalidations": 0, "errors": []},
  "search": {"deleted_docs": 0, "errors": []},
  "cache": {"invalidated": 0, "errors": []},
}
"""

import asyncio
import logging
import os
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncIterable, Dict, List, Optional
from uuid import UUID

# ─────────────────────────────────────────────────────────────
# Optional / soft deps (import guarded; used if present)
# ─────────────────────────────────────────────────────────────
try:
    # Project’s single source of truth for Redis
    from app.core.redis_client import redis_wrapper  # type: ignore
except Exception:  # pragma: no cover
    redis_wrapper = None  # type: ignore

try:
    # App-level storage abstraction (preferred over direct S3)
    from app.services.storage import storage  # type: ignore
except Exception:  # pragma: no cover
    storage = None  # type: ignore

# S3 clients (either is fine; aioboto3 preferred)
try:
    import aioboto3  # type: ignore
except Exception:  # pragma: no cover
    aioboto3 = None  # type: ignore

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore

try:
    # Search index client with an async delete_document(index, id)
    from app.services.search_index import search_index  # type: ignore
except Exception:  # pragma: no cover
    search_index = None  # type: ignore

try:
    # Optional cache tag invalidation
    from app.utils.cache import cache_invalidate_tags  # type: ignore
except Exception:  # pragma: no cover
    cache_invalidate_tags = None  # type: ignore


__all__ = ["cleanup_external_artifacts", "CleanupConfig"]


# ─────────────────────────────────────────────────────────────
# ⚙️ Configuration
# ─────────────────────────────────────────────────────────────
@dataclass
class CleanupConfig:
    # Enable/disable specific steps
    purge_redis_tokens: bool = True
    purge_recordings_storage: bool = True
    purge_cdn_cache: bool = True
    purge_search_index: bool = True
    purge_cache_tags: bool = True

    # Redis scanning
    redis_scan_count: int = 500
    redis_max_delete_batch: int = 200

    # Redis key patterns (deduped at runtime); {session_id}/{user_id}/{title_id} available
    redis_key_patterns: List[str] = field(default_factory=lambda: [
        # Session scoped
        "mn:session:{session_id}:*",
        "mn:stream:{session_id}:*",
        "mn:token:{session_id}:*",
        "mn:dl:{session_id}:*",
        # User + session scoped
        "mn:user:{user_id}:session:{session_id}:*",
        "mn:playback:{user_id}:{session_id}:*",
        # Title scoped (if title_id supplied)
        "mn:title:{title_id}:session:{session_id}:*",
    ])

    # Storage (S3 or app.storage)
    s3_bucket: Optional[str] = None
    s3_region: Optional[str] = None
    # Multiple prefixes can be deleted; {user_id}/{session_id}/{title_id} are available
    s3_prefixes: List[str] = field(default_factory=lambda: [
        "users/{user_id}/sessions/{session_id}/",
        "sessions/{session_id}/",
        "titles/{title_id}/sessions/{session_id}/",
    ])

    # Concurrency & retry
    concurrency: int = 10
    retry_attempts: int = 3
    retry_base_delay: float = 0.25
    retry_max_delay: float = 2.0
    retry_jitter: float = 0.1

    # Search index
    search_index_name: Optional[str] = None
    search_doc_ids: List[str] = field(default_factory=lambda: [
        "{session_id}",
        "{user_id}:{session_id}",
        "{title_id}:{session_id}",
    ])

    # CDN invalidation (wire your client inside `_cleanup_cdn`)
    cdn_invalidate_paths: bool = True
    cdn_paths: List[str] = field(default_factory=lambda: [
        "/streams/{session_id}/*",
        "/users/{user_id}/sessions/{session_id}/*",
        "/titles/{title_id}/streams/*",
    ])


def _load_default_config() -> CleanupConfig:
    """Read environment overrides to construct a default config."""
    return CleanupConfig(
        purge_redis_tokens=os.getenv("CLEANUP_PURGE_REDIS", "1") == "1",
        purge_recordings_storage=os.getenv("CLEANUP_PURGE_STORAGE", "1") == "1",
        purge_cdn_cache=os.getenv("CLEANUP_PURGE_CDN", "1") == "1",
        purge_search_index=os.getenv("CLEANUP_PURGE_SEARCH", "1") == "1",
        purge_cache_tags=os.getenv("CLEANUP_PURGE_CACHE_TAGS", "1") == "1",
        redis_scan_count=int(os.getenv("CLEANUP_REDIS_SCAN_COUNT", "500")),
        redis_max_delete_batch=int(os.getenv("CLEANUP_REDIS_MAX_DEL", "200")),
        concurrency=int(os.getenv("CLEANUP_CONCURRENCY", "10")),
        retry_attempts=int(os.getenv("CLEANUP_RETRY_ATTEMPTS", "3")),
        retry_base_delay=float(os.getenv("CLEANUP_RETRY_BASE_DELAY", "0.25")),
        retry_max_delay=float(os.getenv("CLEANUP_RETRY_MAX_DELAY", "2.0")),
        s3_bucket=os.getenv("CLEANUP_S3_BUCKET") or None,
        s3_region=os.getenv("CLEANUP_S3_REGION") or None,
        search_index_name=os.getenv("CLEANUP_SEARCH_INDEX") or None,
    )


# ─────────────────────────────────────────────────────────────
# 🔁 Retry helper (exponential backoff + jitter)
# ─────────────────────────────────────────────────────────────
async def _retry(coro_factory, *, attempts: int, base_delay: float, max_delay: float, jitter: float) -> Any:
    """
    Retry an async operation with exponential backoff and small jitter.
    """
    last_exc: Optional[BaseException] = None
    delay = float(base_delay)
    for i in range(max(1, attempts)):
        try:
            return await coro_factory()
        except BaseException as e:  # noqa: BLE001
            last_exc = e
            if i >= attempts - 1:
                break
            await asyncio.sleep(delay + random.uniform(0, jitter))
            delay = min(max_delay, delay * 2)
    if last_exc:
        raise last_exc


# ─────────────────────────────────────────────────────────────
# 🧹 Public API
# ─────────────────────────────────────────────────────────────
async def cleanup_external_artifacts(
    *,
    session_id: UUID,
    user_id: Optional[UUID] = None,
    title_id: Optional[UUID] = None,
    config: Optional[CleanupConfig] = None,
    logger: Optional[logging.Logger] = None,
) -> Dict[str, Any]:
    """
    Best-effort external cleanup for a MoviesNow **session**.

    Providers
    ---------
    • Redis: SCAN + chunked UNLINK/DEL (mirrors cache/session_token patterns).
    • Storage: prefers app storage abstraction; falls back to S3 (aioboto3/boto3).
    • CDN: invalidate paths (wire your client in `_cleanup_cdn`).
    • Search: delete per-session docs (client provided by app).
    • Cache: invalidate session/user/title tags via `app.utils.cache`.

    Failure model
    -------------
    • Never raises; returns a structured summary with counts and error strings.
    • Each provider step is isolated and best-effort.
    """
    log = logger or logging.getLogger("moviesnow.cleanup")
    cfg = config or _load_default_config()
    started_at = datetime.now(timezone.utc)

    results: Dict[str, Any] = {
        "session_id": str(session_id),
        "user_id": str(user_id) if user_id else None,
        "title_id": str(title_id) if title_id else None,
        "started_at": started_at.isoformat(),
        "redis": {"deleted": 0, "errors": []},
        "storage": {"deleted_objects": 0, "errors": []},
        "cdn": {"invalidations": 0, "errors": []},
        "search": {"deleted_docs": 0, "errors": []},
        "cache": {"invalidated": 0, "errors": []},
    }

    # Bounded concurrency across providers
    sem = asyncio.Semaphore(max(1, int(cfg.concurrency)))
    tasks: List[asyncio.Task] = []

    tasks.append(asyncio.create_task(_with_sem(sem, _cleanup_redis_keys, log, session_id, user_id, title_id, cfg, results)))
    if cfg.purge_recordings_storage:
        tasks.append(asyncio.create_task(_with_sem(sem, _cleanup_storage, log, session_id, user_id, title_id, cfg, results)))
    if cfg.purge_cdn_cache:
        tasks.append(asyncio.create_task(_with_sem(sem, _cleanup_cdn, log, session_id, user_id, title_id, cfg, results)))
    if cfg.purge_search_index:
        tasks.append(asyncio.create_task(_with_sem(sem, _cleanup_search_index, log, session_id, user_id, title_id, cfg, results)))
    if cfg.purge_cache_tags:
        tasks.append(asyncio.create_task(_with_sem(sem, _cleanup_cache_tags, log, session_id, user_id, title_id, cfg, results)))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    results["finished_at"] = datetime.now(timezone.utc).isoformat()
    return results


async def _with_sem(sem: asyncio.Semaphore, func, *args):
    async with sem:
        try:
            return await func(*args)
        except Exception as e:  # safety net: never leak errors
            try:
                results = args[-1]
                bucket = results.setdefault("misc", {"errors": []})
                bucket["errors"].append(f"{func.__name__}:{type(e).__name__}")
            except Exception:
                pass
            return None


# ─────────────────────────────────────────────────────────────
# 🔑 Redis cleanup
# ─────────────────────────────────────────────────────────────
def _rc():
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
    """Yield keys via scan_iter if available; fallback to SCAN cursors."""
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
    """Prefer UNLINK; fallback to DEL. Chunked for safety."""
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
            pass
    return deleted


def _fmt(template: str, *, session_id: UUID, user_id: Optional[UUID], title_id: Optional[UUID]) -> Optional[str]:
    """Format a pattern/prefix; returns None if required placeholders are missing."""
    if "{user_id}" in template and not user_id:
        return None
    if "{title_id}" in template and not title_id:
        return None
    return template.format(session_id=session_id, user_id=user_id, title_id=title_id)


async def _cleanup_redis_keys(
    log: logging.Logger,
    session_id: UUID,
    user_id: Optional[UUID],
    title_id: Optional[UUID],
    cfg: CleanupConfig,
    results: Dict[str, Any],
) -> None:
    rc = _rc()
    if not rc or not cfg.purge_redis_tokens:
        return

    errors = results["redis"]["errors"]
    # Build concrete patterns from templates; drop Nones and dedupe
    raw_patterns = [
        _fmt(t, session_id=session_id, user_id=user_id, title_id=title_id)
        for t in (cfg.redis_key_patterns or [])
    ]
    patterns = [p for p in raw_patterns if p]
    seen = set()
    patterns = [p for p in patterns if not (p in seen or seen.add(p))]

    try:
        keys: List[str] = []
        for pat in patterns:
            async for k in _scan_iter_keys(rc, pat, count=cfg.redis_scan_count):
                keys.append(k)
                if len(keys) >= cfg.redis_max_delete_batch:
                    results["redis"]["deleted"] += await _unlink_or_delete_many(rc, keys)
                    keys.clear()

        if keys:
            results["redis"]["deleted"] += await _unlink_or_delete_many(rc, keys)

        if results["redis"]["deleted"]:
            log.info("[Cleanup][Redis] Deleted %s keys (patterns=%d)", results["redis"]["deleted"], len(patterns))
    except Exception as e:
        errors.append(f"redis_cleanup_error:{type(e).__name__}")


# ─────────────────────────────────────────────────────────────
# 📦 Storage cleanup (app storage or S3)
# ─────────────────────────────────────────────────────────────
async def _cleanup_storage(
    log: logging.Logger,
    session_id: UUID,
    user_id: Optional[UUID],
    title_id: Optional[UUID],
    cfg: CleanupConfig,
    results: Dict[str, Any],
) -> None:
    errors = results["storage"]["errors"]

    # Preferred: app storage abstraction with delete_prefix
    prefixes = [
        _fmt(p, session_id=session_id, user_id=user_id, title_id=title_id)
        for p in (cfg.s3_prefixes or [])
    ]
    prefixes = [p for p in prefixes if p]

    if storage and hasattr(storage, "delete_prefix"):
        for prefix in prefixes:
            try:
                deleted = await _retry(
                    lambda: storage.delete_prefix(prefix),  # type: ignore[misc]
                    attempts=cfg.retry_attempts,
                    base_delay=cfg.retry_base_delay,
                    max_delay=cfg.retry_max_delay,
                    jitter=cfg.retry_jitter,
                )
                if isinstance(deleted, int):
                    results["storage"]["deleted_objects"] += int(deleted)
                log.info("[Cleanup][Storage] Deleted under prefix '%s'", prefix)
            except Exception as e:
                errors.append(f"storage_delete_prefix_error:{type(e).__name__}")
        return  # prefer app storage and return

    # Fallback: S3
    bucket = cfg.s3_bucket
    if not bucket or not prefixes:
        return

    async def _aioboto3_delete_all(pref: str) -> int:
        deleted = 0
        # type: ignore[attr-defined]
        async with aioboto3.Session().client("s3", region_name=cfg.s3_region) as s3:
            continuation: Dict[str, Any] = {}
            while True:
                resp = await s3.list_objects_v2(Bucket=bucket, Prefix=pref, **continuation)
                contents = resp.get("Contents") or []
                if not contents:
                    break
                to_delete = [{"Key": obj["Key"]} for obj in contents]
                if to_delete:
                    await s3.delete_objects(Bucket=bucket, Delete={"Objects": to_delete, "Quiet": True})
                    deleted += len(to_delete)
                if resp.get("IsTruncated"):
                    continuation = {"ContinuationToken": resp.get("NextContinuationToken")}
                else:
                    break
        return deleted

    def _boto3_delete_all_sync(pref: str) -> int:
        deleted = 0
        # type: ignore[attr-defined]
        s3 = boto3.client("s3", region_name=cfg.s3_region)
        continuation: Dict[str, Any] = {}
        while True:
            resp = s3.list_objects_v2(Bucket=bucket, Prefix=pref, **continuation)
            contents = resp.get("Contents") or []
            if not contents:
                break
            to_delete = [{"Key": obj["Key"]} for obj in contents]
            if to_delete:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": to_delete, "Quiet": True})
                deleted += len(to_delete)
            if resp.get("IsTruncated"):
                continuation = {"ContinuationToken": resp.get("NextContinuationToken")}
            else:
                break
        return deleted

    for pref in prefixes:
        try:
            if aioboto3:
                deleted = await _retry(
                    lambda: _aioboto3_delete_all(pref),
                    attempts=cfg.retry_attempts,
                    base_delay=cfg.retry_base_delay,
                    max_delay=cfg.retry_max_delay,
                    jitter=cfg.retry_jitter,
                )
            elif boto3:
                deleted = await _retry(
                    lambda: asyncio.to_thread(_boto3_delete_all_sync, pref),
                    attempts=cfg.retry_attempts,
                    base_delay=cfg.retry_base_delay,
                    max_delay=cfg.retry_max_delay,
                    jitter=cfg.retry_jitter,
                )
            else:
                errors.append("no_storage_provider_available")
                continue

            results["storage"]["deleted_objects"] += int(deleted)
            if deleted:
                log.info("[Cleanup][S3] Deleted %s objects under s3://%s/%s", deleted, bucket, pref)
        except Exception as e:
            errors.append(f"s3_delete_error:{type(e).__name__}")


# ─────────────────────────────────────────────────────────────
# 🌐 CDN invalidation (wire your CDN client here)
# ─────────────────────────────────────────────────────────────
async def _cleanup_cdn(
    log: logging.Logger,
    session_id: UUID,
    user_id: Optional[UUID],
    title_id: Optional[UUID],
    cfg: CleanupConfig,
    results: Dict[str, Any],
) -> None:
    if not cfg.cdn_invalidate_paths:
        return

    try:
        paths = [
            _fmt(p, session_id=session_id, user_id=user_id, title_id=title_id)
            for p in (cfg.cdn_paths or [])
        ]
        paths = [p for p in paths if p]

        if not paths:
            return

        # Example integration (replace with your provider):
        # from app.services.cdn import cdn_client
        # await cdn_client.invalidate(paths=paths)

        # Placeholder success (remove once wired to real client):
        results["cdn"]["invalidations"] += len(paths)
        log.info("[Cleanup][CDN] Invalidated %d path(s)", len(paths))
    except Exception as e:
        results["cdn"]["errors"].append(f"cdn_invalidate_error:{type(e).__name__}")


# ─────────────────────────────────────────────────────────────
# 🔎 Search index cleanup (optional)
# ─────────────────────────────────────────────────────────────
async def _cleanup_search_index(
    log: logging.Logger,
    session_id: UUID,
    user_id: Optional[UUID],
    title_id: Optional[UUID],
    cfg: CleanupConfig,
    results: Dict[str, Any],
) -> None:
    if not (search_index and cfg.search_index_name):
        return

    doc_ids = [
        _fmt(t, session_id=session_id, user_id=user_id, title_id=title_id)
        for t in (cfg.search_doc_ids or [])
    ]
    doc_ids = [d for d in doc_ids if d]

    async def _delete_doc(did: str):
        # Contract: await search_index.delete_document(index_name, doc_id)
        return await search_index.delete_document(cfg.search_index_name, did)  # type: ignore[misc]

    for did in doc_ids:
        try:
            await _retry(
                lambda did=did: _delete_doc(did),
                attempts=cfg.retry_attempts,
                base_delay=cfg.retry_base_delay,
                max_delay=cfg.retry_max_delay,
                jitter=cfg.retry_jitter,
            )
            results["search"]["deleted_docs"] += 1
            log.info("[Cleanup][Search] Deleted doc id=%s from index=%s", did, cfg.search_index_name)
        except Exception as e:
            results["search"]["errors"].append(f"search_delete_error:{type(e).__name__}")


# ─────────────────────────────────────────────────────────────
# 🏷️ Cache tag invalidation (optional; aligns with app.utils.cache)
# ─────────────────────────────────────────────────────────────
async def _cleanup_cache_tags(
    log: logging.Logger,
    session_id: UUID,
    user_id: Optional[UUID],
    title_id: Optional[UUID],
    cfg: CleanupConfig,
    results: Dict[str, Any],
) -> None:
    if not cache_invalidate_tags:
        return
    try:
        tags = [f"session:{session_id}"]
        if user_id:
            tags.append(f"user:{user_id}:session:{session_id}")
        if title_id:
            tags.append(f"title:{title_id}:session:{session_id}")

        count = await cache_invalidate_tags(*tags)
        results["cache"]["invalidated"] += int(count or 0)
        if count:
            log.info("[Cleanup][Cache] Invalidated %s tagged keys", count)
    except Exception as e:
        results["cache"]["errors"].append(f"cache_invalidate_error:{type(e).__name__}")
