from __future__ import annotations

"""
MoviesNow • Delivery (Presigned GET, Public)
============================================

Public endpoints to obtain short-lived presigned **GET** URLs for downloads and
bundles. Optionally redeems one-time Redis tokens when provided.

Route Index
-----------
- POST /delivery/download-url          → Presigned GET for a single allowed `storage_key`
- POST /delivery/batch-download-urls   → Presigned GETs for multiple allowed `storage_key`s
- POST /delivery/bundle-url            → Presigned GET for a bundle ZIP (optional one-time token)
- POST /delivery/mint-token            → Admin-only: mint a one-time token for a specific key

Security & Rate Limits
----------------------
- Optional X-API-Key via `enforce_public_api_key`.
- Per-IP rate limiting via `rate_limit` dependency (global SlowAPI handles actual limits).
- All responses are **no-store** to avoid caching signed URLs.

Hardening
---------
- Strict key validation (no traversal, only whitelisted prefixes/extensions).
- Best-effort HEAD check before signing to fail fast on missing objects.
- One-time token redemption (atomic via Redis lock) when provided.
- Availability gating (opt-in) inferred from `downloads/{title_id}/...` keys.
- Never log or return presigned URLs in audit logs/errors.
"""

# ── [Imports] ─────────────────────────────────────────────────────────────────────────────
from typing import Optional, Dict, List, Tuple
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
import logging
import os
import re
import time as _time

from app.api.http_utils import (
    enforce_public_api_key,
    rate_limit,
    json_no_store,
    sanitize_filename,
    require_admin,
    get_client_ip,
    enforce_availability_for_download,
)
from app.db.session import transactional_async_session
from app.core.redis_client import redis_wrapper
from app.security_headers import set_sensitive_cache
from app.utils.aws import S3Client, S3StorageError
from app.core.config import settings
from app.core.metrics import (
    inc_presign,
    inc_token_minted,
    observe_presign_seconds,
    inc_token_consumed,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Delivery (Public)"])
__all__ = ["router"]

# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Config & Validation Helpers
# ─────────────────────────────────────────────────────────────────────────────

# Allowed object spaces for public delivery (defense-in-depth)
_ALLOWED_PREFIXES: Tuple[str, ...] = ("bundles/", "downloads/")
_ALLOWED_ZIP_EXT = ".zip"
_ALLOWED_VIDEO_EXTS: Tuple[str, ...] = (".mp4", ".m4v", ".mov", ".webm")
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
    Normalize and validate a storage key.

    Rules
    -----
    - Forbid leading slash (`/`) and path traversal (`..`)
    - Allow only `_SAFE_KEY_RE` characters
    """
    k = (key or "").strip()
    if not k or k.startswith("/") or ".." in k or not _SAFE_KEY_RE.match(k):
        raise HTTPException(status_code=400, detail="Invalid storage_key")
    return k


def _is_allowed_public_download(key: str) -> bool:
    """
    Public downloads are restricted for cost control and anti-abuse:

    • Season bundles under ``bundles/**.zip``
    • Extras zip under ``downloads/**/extras/**.zip``
    • Curated video files under ``downloads/**`` with allowed extensions
    """
    k = key.strip()
    # Bundles (ZIP only)
    if k.startswith("bundles/") and k.lower().endswith(_ALLOWED_ZIP_EXT):
        return True
    # Extras ZIPs
    if k.startswith("downloads/") and "/extras/" in k and k.lower().endswith(_ALLOWED_ZIP_EXT):
        return True
    # Video files under downloads
    if k.startswith("downloads/") and any(k.lower().endswith(ext) for ext in _ALLOWED_VIDEO_EXTS):
        return True
    return False


def _guess_mime_from_ext(key: str) -> str:
    """Return a reasonable Content-Type based on file extension."""
    kl = key.lower()
    if kl.endswith(".zip"):
        return "application/zip"
    if kl.endswith(".mp4") or kl.endswith(".m4v"):
        return "video/mp4"
    if kl.endswith(".webm"):
        return "video/webm"
    if kl.endswith(".mov"):
        return "video/quicktime"
    return "application/octet-stream"


def _build_content_disposition(filename: Optional[str], *, fallback: str = "download.bin") -> Optional[str]:
    """Return Content-Disposition with RFC 5987 filename* for non-ASCII names."""
    if not filename:
        return None
    safe = sanitize_filename(filename, fallback=fallback)
    cd = f'attachment; filename="{safe}"'
    try:
        if any(ord(c) > 127 for c in filename):
            from urllib.parse import quote
            cd += f"; filename*=UTF-8''{quote(filename, encoding='utf-8', safe='')}"
    except Exception:
        pass
    return cd


async def _enforce_ip_quota(request: Request, *, keyspace: str, amount: int = 1) -> None:
    """Per-IP daily quota using Redis counters. Fail-open on errors."""
    try:
        ip = get_client_ip(request)
        import datetime as _dt
        now = _dt.datetime.utcnow()
        day = now.strftime("%Y%m%d")
        rk = f"quota:delivery:{keyspace}:{ip}:{day}"
        # choose limits per keyspace
        if keyspace == "bundles":
            limit = int(os.getenv("DELIVERY_DAILY_IP_QUOTA_BUNDLES", "200"))
        else:
            limit = int(os.getenv("DELIVERY_DAILY_IP_QUOTA_DOWNLOADS", "500"))
        tomorrow = (now + _dt.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        ttl = int((tomorrow - now).total_seconds())
        curr = await redis_wrapper.client.incrby(rk, amount)  # type: ignore
        if curr == amount:
            try:
                await redis_wrapper.client.expire(rk, ttl)  # type: ignore
            except Exception:
                pass
        if curr > limit:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Quota exceeded")
    except HTTPException:
        raise
    except Exception:
        return


async def _redeem_optional_token(token: Optional[str], *, expected_key: Optional[str] = None) -> None:
    """
    Atomically consume a one-time Redis token if provided.

    Behavior
    --------
    - When ``expected_key`` is supplied, ensure the token authorizes that key.
    - Enforces usage caps (``max_uses``).
    - Uses a short distributed lock to avoid double-spend races.
    """
    if not token:
        return
    lock_key = f"lock:download:token:{token}"
    json_key = f"download:token:{token}"
    async with redis_wrapper.lock(lock_key, timeout=5, blocking_timeout=2):
        data = await redis_wrapper.json_get(json_key)
        if not data:
            inc_token_consumed("missing")
            raise HTTPException(status_code=404, detail="Token not found or expired")
        tok_key = (data.get("storage_key") if isinstance(data, dict) else None)
        if expected_key and tok_key and tok_key != expected_key:
            inc_token_consumed("forbidden")
            raise HTTPException(status_code=403, detail="Token does not authorize this resource")
        # Enforce per-token usage caps
        try:
            max_uses = int(data.get("max_uses") or 1)
            used = int(data.get("used") or 0)
        except Exception:
            max_uses, used = 1, 0
        if used >= max_uses:
            inc_token_consumed("exhausted")
            raise HTTPException(status_code=403, detail="Token uses exhausted")
        data["used"] = used + 1
        try:
            await redis_wrapper.json_set(json_key, data)
        except Exception:
            pass
        if data["used"] >= max_uses:
            try:
                await redis_wrapper.client.delete(json_key)  # type: ignore
            except Exception:
                pass
        try:
            inc_token_consumed("ok")
        except Exception:
            pass


def _derive_download_filename(requested: Optional[str], key: str, fallback: str = "download.zip") -> Optional[str]:
    """
    Choose a safe attachment filename:

    Priority
    --------
    1) Caller-provided (sanitized)
    2) Last path segment of the key
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
    attachment_filename: Optional[str] = Field(None, description="If set, browsers download as this name")
    token: Optional[str] = Field(None, description="Optional one-time token to consume")


class PresignedUrlOut(BaseModel):
    url: str


class BatchItem(BaseModel):
    storage_key: str
    attachment_filename: Optional[str] = None


class BatchDownloadIn(BaseModel):
    items: List[BatchItem]
    ttl_seconds: int = Field(600, ge=60, le=3600)


class BatchItemResult(BaseModel):
    index: int
    storage_key: str
    url: Optional[str] = None
    error: Optional[str] = Field(None, description="forbidden|not_found|internal_error")
    ignored: Optional[bool] = None


class BatchDownloadOut(BaseModel):
    results: List[BatchItemResult]


class BundleUrlIn(BaseModel):
    storage_key: str
    ttl_seconds: int = Field(600, ge=60, le=3600)
    token: Optional[str] = Field(None, description="Optional one-time token to consume")
    attachment_filename: Optional[str] = None


class MintTokenIn(BaseModel):
    storage_key: str
    ttl_seconds: int = Field(600, ge=60, le=86400, description="Token TTL in seconds")


class MintTokenOut(BaseModel):
    token: str
    storage_key: str
    expires_at: int


# ╔════════════════════════════════ Route: Single Presigned GET ══════════════╗
# ║ ⬇️🔐  POST /delivery/download-url                                         ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
@router.post(
    "/delivery/download-url",
    summary="Presigned GET for an asset",
    response_model=PresignedUrlOut,
    responses={
        200: {"description": "OK"},
        400: {"description": "Invalid storage_key"},
        401: {"description": "Unauthorized (API key)"},
        403: {"description": "Forbidden (namespace/policy or token)"},
        404: {"description": "File not found"},
        429: {"description": "Quota exceeded"},
        503: {"description": "Storage or token verification unavailable"},
    },
)
async def delivery_download_url(
    payload: DownloadUrlIn,
    request: Request,
    response: Response,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> Dict[str, str]:
    """
    Return a short-lived presigned **GET** URL for a single allowed ``storage_key``.

    Steps
    -----
    1) Cache hardening & TTL clamp
    2) Validate key (safe chars, namespace, extension)
    3) Redeem optional token (bound to the same key)
    4) Optional availability gating inferred from ``downloads/{title_id}/...``
    5) HEAD check (existence) and presign GET with optional Content-Disposition

    Returns
    -------
    ``{"url": "<signed GET>"}`` with strict no-store headers.
    """
    # ── Cache hardening ─────────────────────────────────────────────────────
    set_sensitive_cache(response)
    ttl = _clamp_ttl(int(payload.ttl_seconds))

    # ── Validate key ────────────────────────────────────────────────────────
    key = _safe_key(payload.storage_key)
    if not _is_allowed_public_download(key):
        raise HTTPException(
            status_code=403,
            detail="Downloads restricted to bundles/extras ZIPs and curated video files under downloads/",
        )

    # ── Optional token redemption (bound to this key) ───────────────────────
    try:
        await _redeem_optional_token(getattr(payload, "token", None), expected_key=key)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="Token verification unavailable")

    # ── Optional availability gating (title/episode inferred) ───────────────
    try:
        if os.environ.get("FEATURE_ENFORCE_AVAILABILITY") in {"1", "true", "True"}:
            parts = key.split("/")
            if len(parts) >= 2 and parts[0] == "downloads":
                title_id = parts[1]
                episode_id = parts[2] if len(parts) >= 3 and len(parts[2]) >= 36 else None
                async with transactional_async_session() as db:
                    await enforce_availability_for_download(request, db, title_id=title_id, episode_id=episode_id)
    except HTTPException:
        raise
    except Exception:
        pass

    # ── HEAD existence check ────────────────────────────────────────────────
    s3 = _s3()
    try:
        s3.client.head_object(Bucket=s3.bucket, Key=key)  # type: ignore[attr-defined]
    except Exception:
        raise HTTPException(status_code=404, detail="File not found")

    # ── Presign (GET) ───────────────────────────────────────────────────────
    filename = _derive_download_filename(payload.attachment_filename, key)
    disposition = _build_content_disposition(filename)
    keyspace = "bundles" if key.startswith("bundles/") else ("downloads" if key.startswith("downloads/") else "other")
    _t0 = _time.perf_counter()
    try:
        ctype = _guess_mime_from_ext(key)
        await _enforce_ip_quota(request, keyspace=keyspace, amount=1)
        url = s3.presigned_get(
            key,
            expires_in=ttl,
            response_content_disposition=disposition,
            response_content_type=ctype,
        )
        inc_presign(keyspace, "ok")
        observe_presign_seconds(keyspace, "ok", _time.perf_counter() - _t0)
    except S3StorageError as e:
        inc_presign(keyspace, "error")
        observe_presign_seconds(keyspace, "error", _time.perf_counter() - _t0)
        raise HTTPException(status_code=503, detail=str(e))

    # ── Respond (no-store) ──────────────────────────────────────────────────
    return json_no_store({"url": url}, response=response)


# ╔════════════════════════════════ Route: Admin Mint One-time Token ═════════╗
# ║ 🔑🪙  POST /delivery/mint-token                                           ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
@router.post(
    "/delivery/mint-token",
    summary="Mint one-time token for a download (admin)",
    response_model=MintTokenOut,
    responses={
        200: {"description": "OK"},
        400: {"description": "Forbidden key namespace"},
        401: {"description": "Unauthorized (admin)"},
        403: {"description": "Forbidden"},
        503: {"description": "Token store unavailable"},
    },
)
async def delivery_mint_token(
    payload: MintTokenIn,
    request: Request,
    response: Response,
    _rl=Depends(rate_limit),
    _adm=Depends(require_admin),
) -> Dict[str, object]:
    """
    Mint a one-time token bound to a specific ``storage_key``.

    Usage
    -----
    - Clients present the token to `/delivery/bundle-url` or `/delivery/download-url`.
    - Tokens are JSON records: ``{"storage_key": "...", "expires_at": <epoch>}``.

    Notes
    -----
    - The token is **not** a JWT; it is a Redis-backed opaque handle.
    - Admin-only endpoint.
    """
    set_sensitive_cache(response)
    key = _safe_key(payload.storage_key)
    if not _is_allowed_public_download(key):
        raise HTTPException(status_code=403, detail="Forbidden key namespace")

    # Generate token
    try:
        import secrets
        token = secrets.token_urlsafe(24)
    except Exception:  # pragma: no cover
        import uuid
        token = uuid.uuid4().hex

    ttl = _clamp_ttl(int(payload.ttl_seconds))
    expires_at = int(_time.time()) + ttl
    data = {"storage_key": key, "expires_at": expires_at}
    try:
        await redis_wrapper.json_set(f"download:token:{token}", data)
        await redis_wrapper.client.expire(f"download:token:{token}", ttl)  # type: ignore
    except Exception:
        try:
            await redis_wrapper.client.setex(f"download:token:{token}", ttl, "1")  # type: ignore
        except Exception:
            raise HTTPException(status_code=503, detail="Token store unavailable")

    inc_token_minted()
    return json_no_store({"token": token, "storage_key": key, "expires_at": expires_at}, response=response)


# ╔════════════════════════════════ Route: Batch Presigned GETs ══════════════╗
# ║ 📚🔐  POST /delivery/batch-download-urls                                  ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
@router.post(
    "/delivery/batch-download-urls",
    summary="Presigned GET URLs for multiple assets",
    response_model=BatchDownloadOut,
    responses={
        200: {"description": "OK"},
        400: {"description": "No items or too many"},
        401: {"description": "Unauthorized (API key)"},
        403: {"description": "Forbidden item(s)"},
        404: {"description": "One or more files not found"},
        429: {"description": "Quota exceeded"},
        503: {"description": "Storage unavailable"},
    },
)
async def delivery_batch_download_urls(
    payload: BatchDownloadIn,
    request: Request,
    response: Response,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> Dict[str, object]:
    """
    Return presigned **GET** URLs for multiple allowed ``storage_key`` items.

    Limits & Behavior
    -----------------
    - Max items constrained by ``BATCH_DOWNLOAD_MAX_ITEMS`` (env or settings).
    - Duplicate keys are de-duplicated (later duplicates marked ``ignored``).
    - Each item validated and HEAD-checked individually.
    - Response includes per-item successes or sanitized errors; overall 200.
    """
    # ── Cache hardening ─────────────────────────────────────────────────────
    set_sensitive_cache(response)
    ttl = _clamp_ttl(int(payload.ttl_seconds))

    # ── Validate envelope & limits ──────────────────────────────────────────
    max_items = int(getattr(settings, "BATCH_DOWNLOAD_MAX_ITEMS", int(os.environ.get("BATCH_DOWNLOAD_MAX_ITEMS", "50"))))
    if not payload.items:
        raise HTTPException(status_code=400, detail="No items provided")
    if len(payload.items) > max_items:
        raise HTTPException(status_code=400, detail=f"Too many items (max {max_items})")

    # ── Process items ───────────────────────────────────────────────────────
    s3 = _s3()
    seen: set[str] = set()
    results: List[Dict[str, object]] = []
    for idx, it in enumerate(payload.items):
        try:
            key = _safe_key(it.storage_key)
            if key in seen:
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
            disp = _build_content_disposition(fname)
            ctype = _guess_mime_from_ext(key)
            await _enforce_ip_quota(request, keyspace=("bundles" if key.startswith("bundles/") else "downloads"), amount=1)
            _t0 = _time.perf_counter()
            url = s3.presigned_get(
                key,
                expires_in=ttl,
                response_content_disposition=disp,
                response_content_type=ctype,
            )
            observe_presign_seconds(
                "bundles" if key.startswith("bundles/") else ("downloads" if key.startswith("downloads/") else "other"),
                "ok",
                _time.perf_counter() - _t0,
            )
            results.append({"index": idx, "storage_key": it.storage_key, "url": url})
        except Exception:
            # Never leak internals; return sanitized error
            results.append({"index": idx, "storage_key": it.storage_key, "error": "internal_error"})

    # ── Respond (no-store) ──────────────────────────────────────────────────
    return json_no_store({"results": results}, response=response)


# ╔════════════════════════════════ Route: Bundle Presigned GET ══════════════╗
# ║ 📦🔐  POST /delivery/bundle-url                                           ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
@router.post(
    "/delivery/bundle-url",
    summary="Presigned GET for a bundle (no rebuild)",
    response_model=PresignedUrlOut,
    responses={
        200: {"description": "OK"},
        400: {"description": "Invalid bundle key"},
        401: {"description": "Unauthorized (API key)"},
        403: {"description": "Forbidden (token)"},
        404: {"description": "Bundle not found or expired"},
        429: {"description": "Quota exceeded"},
        503: {"description": "Storage unavailable"},
    },
)
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
    1) Cache hardening & TTL clamp
    2) Validate bundle key (``bundles/**.zip`` only)
    3) HEAD check (existence) — no bundle rebuilds
    4) If token provided, atomically redeem it and verify key match
    5) Presign GET and return ``{"url": ...}`` with no-store headers
    """
    # ── Cache hardening ─────────────────────────────────────────────────────
    set_sensitive_cache(response)
    ttl = _clamp_ttl(int(payload.ttl_seconds))

    # ── Validate key ────────────────────────────────────────────────────────
    key = _safe_key(payload.storage_key)
    key_norm = key.strip("/")
    if not (key_norm.startswith("bundles/") and key_norm.lower().endswith(_ALLOWED_ZIP_EXT)):
        raise HTTPException(status_code=400, detail="Invalid bundle key; expected bundles/{...}.zip")

    # ── HEAD existence check ────────────────────────────────────────────────
    s3 = _s3()
    try:
        s3.client.head_object(Bucket=s3.bucket, Key=key)  # type: ignore[attr-defined]
    except Exception:
        raise HTTPException(status_code=404, detail="Bundle not found or expired")

    # ── Optional token redemption ───────────────────────────────────────────
    await _redeem_optional_token(payload.token, expected_key=key)

    # ── Presign (GET) ───────────────────────────────────────────────────────
    filename = _derive_download_filename(payload.attachment_filename, key, fallback="bundle.zip")
    disp = _build_content_disposition(filename, fallback="bundle.zip")
    _t0 = _time.perf_counter()
    try:
        await _enforce_ip_quota(request, keyspace="bundles", amount=1)
        url = s3.presigned_get(
            key,
            expires_in=ttl,
            response_content_disposition=disp,
            response_content_type="application/zip",
        )
        observe_presign_seconds("bundles", "ok", _time.perf_counter() - _t0)
    except S3StorageError as e:
        observe_presign_seconds("bundles", "error", _time.perf_counter() - _t0)
        raise HTTPException(status_code=503, detail=str(e))

    # ── Respond (no-store) ──────────────────────────────────────────────────
    return json_no_store({"url": url}, response=response)
