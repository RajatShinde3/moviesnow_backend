from __future__ import annotations

"""
MoviesNow • Delivery (Presigned GET)
===================================

Public endpoints to obtain short-lived presigned GET URLs for downloads and
bundles. Optionally redeems one-time Redis tokens when provided.

Endpoints
---------
- POST /delivery/download-url  → presigned GET for any storage_key
- POST /delivery/bundle-url    → presigned GET for bundle (optional token)

Security & Rate Limits
----------------------
- Optional X-API-Key (`enforce_public_api_key`).
- Per-IP rate limiting (`rate_limit`).
- Responses are `no-store` to avoid accidental caching of signed URLs.
"""

from typing import Optional, Dict, List
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Request, Response
import logging

from app.api.http_utils import enforce_public_api_key, rate_limit, json_no_store, sanitize_filename
from app.core.redis_client import redis_wrapper
from app.security_headers import set_sensitive_cache
from app.utils.aws import S3Client, S3StorageError
from app.core.config import settings  # imported for settings defaults elsewhere
"""
Minimal-cost delivery mode:
- No server-side bundle rebuilds.
- Only allow presigned GET for season bundles and extras ZIPs.
"""

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Delivery"])


class DownloadUrlIn(BaseModel):
    storage_key: str
    ttl_seconds: int = Field(600, ge=60, le=3600)
    attachment_filename: Optional[str] = Field(None, description="If set, browsers download as this name")


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


def _s3() -> S3Client:
    try:
        return S3Client()
    except S3StorageError as e:  # pragma: no cover
        raise HTTPException(status_code=503, detail=str(e))



@router.post("/delivery/download-url", summary="Presigned GET for an asset")
async def delivery_download_url(
    payload: DownloadUrlIn,
    request: Request,
    response: Response,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> Dict[str, str]:
    set_sensitive_cache(response)
    # Restrict keys to bundles and extras ZIPs to avoid per-episode downloads
    key = payload.storage_key.strip("/")
    allowed = (
        (key.startswith("bundles/") and key.lower().endswith(".zip"))
        or (key.startswith("downloads/") and "/extras/" in key and key.lower().endswith(".zip"))
    )
    if not allowed:
        raise HTTPException(status_code=403, detail="Downloads are restricted to season bundles and extras ZIPs")

    s3 = _s3()
    filename = sanitize_filename(payload.attachment_filename, fallback="download.bin") if payload.attachment_filename else None
    disp = f'attachment; filename="{filename}"' if filename else None
    try:
        url = s3.presigned_get(payload.storage_key, expires_in=payload.ttl_seconds, response_content_disposition=disp)
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return json_no_store({"url": url}, response=response)


@router.post("/delivery/batch-download-urls", summary="Presigned GET URLs for multiple assets")
async def delivery_batch_download_urls(
    payload: BatchDownloadIn,
    request: Request,
    response: Response,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> Dict[str, object]:
    set_sensitive_cache(response)
    max_items = int(getattr(settings, "BATCH_DOWNLOAD_MAX_ITEMS", int(os.environ.get("BATCH_DOWNLOAD_MAX_ITEMS", "50"))))
    if not payload.items or len(payload.items) == 0:
        raise HTTPException(status_code=400, detail="No items provided")
    if len(payload.items) > max_items:
        raise HTTPException(status_code=400, detail=f"Too many items (max {max_items})")
    s3 = _s3()
    results: List[Dict[str, str]] = []
    seen: set[str] = set()
    for idx, it in enumerate(payload.items):
        if it.storage_key in seen:
            continue
        seen.add(it.storage_key)
        # Enforce same restriction per item
        key = it.storage_key.strip("/")
        allowed = (
            (key.startswith("bundles/") and key.lower().endswith(".zip"))
            or (key.startswith("downloads/") and "/extras/" in key and key.lower().endswith(".zip"))
        )
        if not allowed:
            results.append({"index": idx, "storage_key": it.storage_key, "error": "forbidden"})
            continue
        try:
            fname = sanitize_filename(it.attachment_filename, fallback=None) if it.attachment_filename else None
            disp = f'attachment; filename="{fname}"' if fname else None
            url = s3.presigned_get(it.storage_key, expires_in=payload.ttl_seconds, response_content_disposition=disp)
            results.append({"index": idx, "storage_key": it.storage_key, "url": url})
        except Exception as e:
            results.append({"index": idx, "storage_key": it.storage_key, "error": str(e)})
    return json_no_store({"results": results}, response=response)


@router.post("/delivery/bundle-url", summary="Presigned GET for a bundle (no rebuild)")
async def delivery_bundle_url(
    payload: BundleUrlIn,
    request: Request,
    response: Response,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> Dict[str, str]:
    set_sensitive_cache(response)
    # Only consume token once we know we can return
    # Enforce bundle key format to avoid arbitrary file presigning via this endpoint
    key_norm = payload.storage_key.strip("/")
    if not (key_norm.startswith("bundles/") and key_norm.lower().endswith(".zip")):
        raise HTTPException(status_code=400, detail="Invalid bundle key; expected bundles/{title_id}/Sxx.zip")
    s3 = _s3()
    filename = sanitize_filename(payload.attachment_filename, fallback=f"S{(payload.season_number or 1):02}.zip") if payload.attachment_filename else None
    disp = f'attachment; filename="{filename}"' if filename else None
    # Check existence first
    try:
        s3.client.head_object(Bucket=s3.bucket, Key=payload.storage_key)  # type: ignore[attr-defined]
        url = s3.presigned_get(payload.storage_key, expires_in=payload.ttl_seconds, response_content_disposition=disp)
        # Now consume token (success path)
        if payload.token:
            try:
                await redis_wrapper.client.delete(f"download:token:{payload.token}")  # type: ignore
            except Exception:
                pass
        return json_no_store({"url": url}, response=response)
    except Exception:
        # Not found or not accessible. No rebuilds in minimal-cost mode.
        raise HTTPException(status_code=404, detail="Bundle not found or expired")


    # End of handler
