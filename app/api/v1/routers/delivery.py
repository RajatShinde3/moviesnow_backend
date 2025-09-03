"""
MoviesNow • Delivery (Presigned GET, Public)
============================================

Public endpoints to obtain short-lived presigned **GET** URLs for downloads and
bundles. Optionally redeems one-time Redis tokens when provided.

Endpoints
---------
- POST /delivery/download-url         → presigned GET for an allowed storage_key
- POST /delivery/batch-download-urls  → presigned GETs for multiple allowed keys
- POST /delivery/bundle-url           → presigned GET for a bundle (optional token)

Security & Rate Limits
----------------------
- Optional X-API-Key (via `enforce_public_api_key`).
- Per-IP rate limiting (via `rate_limit` dependency).
- Responses are `no-store` to avoid accidental caching of signed URLs.

Hardening
---------
- Strict key validation (no traversal, only whitelisted prefixes/extensions).
- Best-effort HEAD check before signing to fail fast on missing objects.
- One-time token redemption (atomic via Redis lock) when a token is provided.
- Never log or return presigned URLs in audit logs/errors.
"""

from __future__ import annotations

# ── [Imports] ─────────────────────────────────────────────────────────────────────────────
from typing import Optional, Dict, List, Tuple
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
import logging
import os
import re

from app.api.http_utils import (
    enforce_public_api_key,
    rate_limit,
    json_no_store,
    sanitize_filename,
)
from app.core.redis_client import redis_wrapper
from app.security_headers import set_sensitive_cache
from app.utils.aws import S3Client, S3StorageError
from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Delivery (Public)"])

# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Config & Validation Helpers
# ─────────────────────────────────────────────────────────────────────────────

# Allowed object spaces for public delivery (defense-in-depth)
_ALLOWED_PREFIXES: Tuple[str, ...] = ("bundles/", "downloads/")
_ALLOWED_ZIP_EXT = ".zip"
_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9/_\.\-]+$")  # pragmatic, single-bucket key space


def _s3() -> S3Client:
    """Return an initialized S3 client or raise 503 if storage is unavailable."""
    try:
        return S3Client()
    except S3StorageError as e:  # pragma: no cover
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))


def _clamp_ttl(ttl: int) -> int:
    """Clamp TTL by optional min/max from settings (still bounded by Pydantic)."""
    min_cfg = int(getattr(settings, "DELIVERY_MIN_TTL", os.environ.get("DELIVERY_MIN_TTL", "60")))
    max_cfg = int(getattr(settings, "DELIVERY_MAX_TTL", os.environ.get("DELIVERY_MAX_TTL", "3600")))
    if ttl < min_cfg:
        return min_cfg
    if ttl > max_cfg:
        return max_cfg
    return ttl


def _safe_key(key: str) -> str:
    """
    Normalize and validate a storage key:
    - forbid leading slash and '..' traversal
    - allow only a safe character set
    """
    k = (key or "").strip()
    if not k or k.startswith("/") or ".." in k or not _SAFE_KEY_RE.match(k):
        raise HTTPException(status_code=400, detail="Invalid storage_key")
    return k


def _is_allowed_public_download(key: str) -> bool:
    """
    Public downloads are restricted for cost control and anti-abuse:
    - Season bundles under `bundles/**.zip`
    - Extras zip under `downloads/**/extras/**.zip`
    """
    if not key.endswith(_ALLOWED_ZIP_EXT):
        return False
    if key.startswith("bundles/"):
        return True
    if key.startswith("downloads/") and "/extras/" in key:
        return True
    return False


async def _redeem_optional_token(token: Optional[str], *, expected_key: Optional[str] = None) -> None:
    """
    Atomically consume a one-time Redis token if provided.
    - When `expected_key` is supplied, ensure the token authorizes that key.
    - Best-effort delete under a short distributed lock.
    """
    if not token:
        return
    lock_key = f"lock:download:token:{token}"
    json_key = f"download:token:{token}"
    async with redis_wrapper.lock(lock_key, timeout=5, blocking_timeout=2):
        data = await redis_wrapper.json_get(json_key)
        if not data:
            raise HTTPException(status_code=404, detail="Token not found or expired")
        tok_key = (data.get("storage_key") if isinstance(data, dict) else None)
        if expected_key and tok_key and tok_key != expected_key:
            raise HTTPException(status_code=403, detail="Token does not authorize this resource")
        try:
            await redis_wrapper.client.delete(json_key)  # type: ignore
        except Exception:
            # Non-fatal: the lock above prevents immediate reuse, TTL will also expire
            pass


def _derive_download_filename(requested: Optional[str], key: str, fallback: str = "download.zip") -> Optional[str]:
    """
    Choose a safe attachment filename:
    - Prefer caller-provided (sanitized).
    - Else derive from last path segment of the key.
    """
    if requested:
        return sanitize_filename(requested, fallback=fallback)
    try:
        tail = key.rsplit("/", 1)[-1]
        return sanitize_filename(tail or fallback, fallback=fallback)
    except Exception:
        return fallback


# ─────────────────────────────────────────────────────────────────────────────
# 📦 Schemas
# ─────────────────────────────────────────────────────────────────────────────

class DownloadUrlIn(BaseModel):
    storage_key: str
    ttl_seconds: int = Field(600, ge=60, le=3600)
    attachment_filename: Optional[str] = Field(
        None, description="If set, browsers download as this name"
    )


class BatchItem(BaseModel):
    storage_key: str
    attachment_filename: Optional[str] = None


class BatchDownloadIn(BaseModel):
    items: List[BatchItem]
    ttl_seconds: int = Field(600, ge=60, le=3600)


class BundleUrlIn(BaseModel):
    storage_key: str
    ttl_seconds: int = Field(600, ge=60, le=3600)
    token: Optional[str] = Field(None, description="Optional one-time token to consume")
    attachment_filename: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# ⬇️ Single presigned GET
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/delivery/download-url", summary="Presigned GET for an asset")
async def delivery_download_url(
    payload: DownloadUrlIn,
    request: Request,
    response: Response,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> Dict[str, str]:
    """
    Return a short-lived presigned **GET** URL for a single allowed `storage_key`.

    Steps
    -----
    1) Cache hardening and TTL clamp.
    2) Validate `storage_key` (safe chars, no traversal, allowed prefixes/paths).
    3) HEAD check (fail fast when object is missing).
    4) Generate presigned GET with optional `Content-Disposition`.
    5) Return `{url}` with `no-store` headers.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)
    ttl = _clamp_ttl(int(payload.ttl_seconds))

    # ── [Step 1] Validate key ───────────────────────────────────────────────
    key = _safe_key(payload.storage_key)
    if not _is_allowed_public_download(key):
        raise HTTPException(status_code=403, detail="Downloads are restricted to season bundles and extras ZIPs")

    # ── [Step 2] HEAD existence check ───────────────────────────────────────
    s3 = _s3()
    try:
        s3.client.head_object(Bucket=s3.bucket, Key=key)  # type: ignore[attr-defined]
    except Exception:
        raise HTTPException(status_code=404, detail="File not found")

    # ── [Step 3] Presign (GET) ──────────────────────────────────────────────
    filename = _derive_download_filename(payload.attachment_filename, key)
    disposition = f'attachment; filename="{filename}"' if filename else None
    try:
        url = s3.presigned_get(
            key,
            expires_in=ttl,
            response_content_disposition=disposition,
            response_content_type="application/zip",  # assert ZIP for public delivery
        )
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))

    # ── [Step 4] Respond (no-store) ─────────────────────────────────────────
    return json_no_store({"url": url}, response=response)


# ─────────────────────────────────────────────────────────────────────────────
# 📚 Batch presigned GETs
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/delivery/batch-download-urls", summary="Presigned GET URLs for multiple assets")
async def delivery_batch_download_urls(
    payload: BatchDownloadIn,
    request: Request,
    response: Response,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> Dict[str, object]:
    """
    Return presigned **GET** URLs for multiple allowed `storage_key`s.

    Limits & Behavior
    -----------------
    - Max items are constrained by `BATCH_DOWNLOAD_MAX_ITEMS` (env or settings).
    - Duplicate keys are de-duplicated.
    - Each item is validated and HEAD-checked individually.
    - Response includes per-item successes or errors; overall 200.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)
    ttl = _clamp_ttl(int(payload.ttl_seconds))

    # ── [Step 1] Validate envelope & limits ─────────────────────────────────
    max_items = int(getattr(settings, "BATCH_DOWNLOAD_MAX_ITEMS", int(os.environ.get("BATCH_DOWNLOAD_MAX_ITEMS", "50"))))
    if not payload.items:
        raise HTTPException(status_code=400, detail="No items provided")
    if len(payload.items) > max_items:
        raise HTTPException(status_code=400, detail=f"Too many items (max {max_items})")

    # ── [Step 2] Process items ──────────────────────────────────────────────
    s3 = _s3()
    seen: set[str] = set()
    results: List[Dict[str, object]] = []
    for idx, it in enumerate(payload.items):
        try:
            key = _safe_key(it.storage_key)
            if key in seen:
                # Keep first result; mark later duplicates as ignored to be explicit
                results.append({"index": idx, "storage_key": it.storage_key, "ignored": True})
                continue
            seen.add(key)

            if not _is_allowed_public_download(key):
                results.append({"index": idx, "storage_key": it.storage_key, "error": "forbidden"})
                continue

            # HEAD (existence) before presign
            try:
                s3.client.head_object(Bucket=s3.bucket, Key=key)  # type: ignore[attr-defined]
            except Exception:
                results.append({"index": idx, "storage_key": it.storage_key, "error": "not_found"})
                continue

            fname = _derive_download_filename(it.attachment_filename, key)
            disp = f'attachment; filename="{fname}"' if fname else None
            url = s3.presigned_get(
                key,
                expires_in=ttl,
                response_content_disposition=disp,
                response_content_type="application/zip",
            )
            results.append({"index": idx, "storage_key": it.storage_key, "url": url})
        except Exception as e:
            # Never leak internals; return sanitized error
            results.append({"index": idx, "storage_key": it.storage_key, "error": "internal_error"})

    # ── [Step 3] Respond (no-store) ─────────────────────────────────────────
    return json_no_store({"results": results}, response=response)


# ─────────────────────────────────────────────────────────────────────────────
# 📦 Bundle presigned GET (with optional one-time token)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/delivery/bundle-url", summary="Presigned GET for a bundle (no rebuild)")
async def delivery_bundle_url(
    payload: BundleUrlIn,
    request: Request,
    response: Response,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> Dict[str, str]:
    """
    Return a short-lived presigned **GET** URL for a bundle ZIP.

    Steps
    -----
    1) Cache hardening and TTL clamp.
    2) Validate bundle key (`bundles/**.zip` only).
    3) HEAD check to ensure the bundle exists (no rebuilds in low-cost mode).
    4) If a token is provided, atomically redeem it (and verify the key).
    5) Presign the GET and return `{url}` with `no-store`.

    Notes
    -----
    - Token format matches admin-issued tokens (`download:token:{token}` JSON).
    - When supplied, token must authorize the same `storage_key`.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)
    ttl = _clamp_ttl(int(payload.ttl_seconds))

    # ── [Step 1] Validate key ───────────────────────────────────────────────
    key = _safe_key(payload.storage_key)
    key_norm = key.strip("/")
    if not (key_norm.startswith("bundles/") and key_norm.lower().endswith(_ALLOWED_ZIP_EXT)):
        raise HTTPException(status_code=400, detail="Invalid bundle key; expected bundles/{...}.zip")

    # ── [Step 2] HEAD existence check ───────────────────────────────────────
    s3 = _s3()
    try:
        s3.client.head_object(Bucket=s3.bucket, Key=key)  # type: ignore[attr-defined]
    except Exception:
        raise HTTPException(status_code=404, detail="Bundle not found or expired")

    # ── [Step 3] Optional token redemption ──────────────────────────────────
    await _redeem_optional_token(payload.token, expected_key=key)

    # ── [Step 4] Presign (GET) ──────────────────────────────────────────────
    filename = _derive_download_filename(payload.attachment_filename, key, fallback="bundle.zip")
    disp = f'attachment; filename="{filename}"' if filename else None
    try:
        url = s3.presigned_get(
            key,
            expires_in=ttl,
            response_content_disposition=disp,
            response_content_type="application/zip",
        )
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))

    # ── [Step 5] Respond (no-store) ─────────────────────────────────────────
    return json_no_store({"url": url}, response=response)
