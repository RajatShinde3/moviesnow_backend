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

from typing import Optional, Dict, List, Tuple
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Request, Response, BackgroundTasks
import asyncio
import os
import tempfile
import zipfile
import hashlib
from datetime import datetime, timedelta, timezone
import logging

from app.api.http_utils import enforce_public_api_key, rate_limit, json_no_store, sanitize_filename
from app.core.redis_client import redis_wrapper
from app.security_headers import set_sensitive_cache
from app.utils.aws import S3Client, S3StorageError
from app.core.config import settings
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import transactional_async_session
from app.db.models.season import Season
from app.db.models.episode import Episode
from app.db.models.media_asset import MediaAsset
from app.schemas.enums import MediaAssetKind

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
    rebuild_if_missing: bool = Field(False, description="If true, trigger rebuild when ZIP not found")
    title_id: Optional[str] = Field(None, description="Title ID (UUID) if rebuild is requested")
    season_number: Optional[int] = Field(None, ge=1, description="Season number if rebuild is requested")


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
        try:
            fname = sanitize_filename(it.attachment_filename, fallback=None) if it.attachment_filename else None
            disp = f'attachment; filename="{fname}"' if fname else None
            url = s3.presigned_get(it.storage_key, expires_in=payload.ttl_seconds, response_content_disposition=disp)
            results.append({"index": idx, "storage_key": it.storage_key, "url": url})
        except Exception as e:
            results.append({"index": idx, "storage_key": it.storage_key, "error": str(e)})
    return json_no_store({"results": results}, response=response)


@router.post("/delivery/bundle-url", summary="Presigned GET for a bundle (optionally consume token)")
async def delivery_bundle_url(
    payload: BundleUrlIn,
    request: Request,
    response: Response,
    background: BackgroundTasks,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> Dict[str, str]:
    set_sensitive_cache(response)
    # Only consume token once we know we can return (avoid losing it during rebuild)

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
        # Not found or not accessible
        if not payload.rebuild_if_missing:
            raise HTTPException(status_code=404, detail="Bundle not found or expired")
        # Rebuild requested but may be disabled by settings
        if not bool(getattr(settings, "BUNDLE_ENABLE_REBUILD", False)):
            raise HTTPException(status_code=404, detail="Bundle not available; server-side rebuilds are disabled. Upload the ZIP via admin API.")

    # Rebuild requested: need title/season
    if not payload.title_id or not payload.season_number:
        # Try to parse from key: bundles/{title_id}/Sxx.zip
        parts = payload.storage_key.strip("/").split("/")
        if len(parts) >= 2 and parts[0] == "bundles":
            title_guess = parts[1]
            try:
                name = parts[-1]
                if name.lower().startswith("s") and name.lower().endswith(".zip"):
                    num = int(name[1:-4])
                    payload.title_id = payload.title_id or title_guess
                    payload.season_number = payload.season_number or num
            except Exception:
                pass
    if not payload.title_id or not payload.season_number:
        raise HTTPException(status_code=400, detail="title_id and season_number required for rebuild")

    # Enqueue rebuild (idempotent lock)
    lock_key = f"lock:bundle:rebuild:{payload.title_id}:{payload.season_number}"
    status_key = f"bundle:rebuild:{payload.title_id}:{payload.season_number}"
    cooldown_key = f"cooldown:bundle:rebuild:{payload.title_id}:{payload.season_number}"

    # Cooldown to keep costs low and avoid stampedes (default 1 hour)
    cd_secs = int(getattr(settings, "BUNDLE_REBUILD_COOLDOWN_SECONDS", int(os.environ.get("BUNDLE_REBUILD_COOLDOWN_SECONDS", "3600"))))
    try:
        ttl_val = await redis_wrapper.client.ttl(cooldown_key)  # type: ignore
    except Exception:
        ttl_val = -2
    if isinstance(ttl_val, int) and ttl_val > 0:
        response.status_code = 202
        return json_no_store({"status": "COOLDOWN", "retry_after_seconds": max(15, ttl_val)}, response=response)
    # Mark QUEUED and schedule background task (best-effort)
    await redis_wrapper.json_set(status_key, {"status": "QUEUED", "storage_key": payload.storage_key}, ttl_seconds=1800)

    async def _run() -> None:
        async with redis_wrapper.lock(lock_key, timeout=60, blocking_timeout=5):
            try:
                await redis_wrapper.json_set(status_key, {"status": "IN_PROGRESS", "storage_key": payload.storage_key}, ttl_seconds=1800)
                await _rebuild_bundle_and_upload(
                    title_id=payload.title_id, season_number=int(payload.season_number), dest_key=payload.storage_key
                )
                await redis_wrapper.json_set(status_key, {"status": "READY", "storage_key": payload.storage_key}, ttl_seconds=1800)
            except Exception as e:  # pragma: no cover
                logger.exception("bundle rebuild failed: %s", e)
                await redis_wrapper.json_set(status_key, {"status": "ERROR", "error": str(e)}, ttl_seconds=600)

    # Set cooldown best-effort
    try:
        await redis_wrapper.client.setex(cooldown_key, cd_secs, "1")  # type: ignore
    except Exception:
        pass
    background.add_task(asyncio.create_task, _run())
    response.status_code = 202
    return json_no_store({"status": "REBUILDING", "retry_after_seconds": 15}, response=response)


class RequestBundleIn(BaseModel):
    title_id: str
    season_number: int
    ttl_seconds: int = Field(600, ge=60, le=3600)


@router.post("/delivery/request-bundle", summary="Request a season bundle; rebuild if missing")
async def delivery_request_bundle(
    payload: RequestBundleIn,
    request: Request,
    response: Response,
    background: BackgroundTasks,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> Dict[str, object]:
    set_sensitive_cache(response)
    storage_key = f"bundles/{payload.title_id}/S{int(payload.season_number):02}.zip"
    # Try immediate sign if exists
    s3 = _s3()
    try:
        s3.client.head_object(Bucket=s3.bucket, Key=storage_key)  # type: ignore
        url = s3.presigned_get(storage_key, expires_in=payload.ttl_seconds)
        return json_no_store({"status": "READY", "storage_key": storage_key, "url": url}, response=response)
    except Exception:
        # Missing; if rebuilds are disabled, return 404 instructing upload
        if not bool(getattr(settings, "BUNDLE_ENABLE_REBUILD", False)):
            raise HTTPException(status_code=404, detail="Bundle not available; server-side rebuilds are disabled. Upload the ZIP via admin API.")

    # Schedule rebuild via existing mechanism
    body = BundleUrlIn(storage_key=storage_key, ttl_seconds=payload.ttl_seconds, token=None, attachment_filename=None, rebuild_if_missing=True, title_id=payload.title_id, season_number=payload.season_number)
    # Reuse the same handler path without consuming tokens
    # Cooldown and locking are enforced in delivery_bundle_url
    result = await delivery_bundle_url(body, request, response, background)  # type: ignore
    result["storage_key"] = storage_key
    return result


@router.get("/delivery/bundle-status", summary="Check bundle rebuild status")
async def delivery_bundle_status(
    title_id: Optional[str] = None,
    season_number: Optional[int] = None,
    storage_key: Optional[str] = None,
    presign: bool = False,
    ttl_seconds: int = 300,
    request: Request = None,
    response: Response = None,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> Dict[str, object]:
    set_sensitive_cache(response)
    # Derive keys
    if (not title_id or not season_number) and storage_key:
        parts = storage_key.strip("/").split("/")
        if len(parts) >= 2 and parts[0] == "bundles":
            title_id = title_id or parts[1]
            try:
                name = parts[-1]
                if name.lower().startswith("s") and name.lower().endswith(".zip"):
                    season_number = season_number or int(name[1:-4])
            except Exception:
                pass
    if not title_id or not season_number:
        raise HTTPException(status_code=400, detail="Provide title_id+season_number or storage_key")

    status_key = f"bundle:rebuild:{title_id}:{season_number}"
    st = await redis_wrapper.json_get(status_key) or {}
    status = st.get("status") if isinstance(st, dict) else None
    key = storage_key or (st.get("storage_key") if isinstance(st, dict) else None)

    # If unknown, try to see if object exists
    if not status:
        try:
            s3 = _s3()
            if not key:
                key = f"bundles/{title_id}/S{int(season_number):02}.zip"
            s3.client.head_object(Bucket=s3.bucket, Key=key)  # type: ignore
            status = "READY"
        except Exception:
            status = "MISSING"

    result: Dict[str, object] = {"status": status, "storage_key": key}
    if status == "READY" and presign and key:
        s3 = _s3()
        try:
            url = s3.presigned_get(key, expires_in=ttl_seconds)
            result["url"] = url
        except Exception:
            pass
    return json_no_store(result, response=response)


async def _rebuild_bundle_and_upload(*, title_id: str, season_number: int, dest_key: str) -> None:
    """Rebuild a season ZIP from episode video assets and upload to S3.

    Steps
    1) Query season and episodes in order.
    2) Pick one video-like asset per episode (ORIGINAL/DOWNLOAD/VIDEO), prefer is_primary.
    3) Stream each object to a temporary file and add to a ZIP.
    4) Upload ZIP to S3 (multipart via boto3 transfer), set SSE-S3.
    5) Update/Create Bundle row with size, sha256, and new expires_at.
    """
    s3 = _s3()
    with tempfile.TemporaryDirectory() as tmpd:
        zip_path = os.path.join(tmpd, f"bundle_S{season_number:02}.zip")
        sha = hashlib.sha256()

        # Gather episode assets
        episodes: List[Tuple[int, str, str]] = []  # (episode_number, storage_key, arcname)
        async with transactional_async_session() as db:  
            season = (await db.execute(
                select(Season).where(Season.title_id == title_id, Season.season_number == season_number)
            )).scalar_one_or_none()
            if not season:
                raise HTTPException(status_code=404, detail="Season not found")
            eps = (await db.execute(
                select(Episode).where(Episode.season_id == season.id, Episode.title_id == title_id).order_by(Episode.episode_number.asc())
            )).scalars().all()
            for ep in eps:
                ma = (await db.execute(
                    select(MediaAsset)
                    .where(
                        MediaAsset.episode_id == ep.id,
                        MediaAsset.kind.in_([MediaAssetKind.ORIGINAL, MediaAssetKind.DOWNLOAD, MediaAssetKind.VIDEO]),
                    )
                    .order_by(MediaAsset.is_primary.desc(), MediaAsset.sort_order.asc(), MediaAsset.created_at.asc())
                )).scalars().first()
                if not ma or not ma.storage_key:
                    continue
                base = os.path.basename(ma.storage_key)
                arc = f"S{season_number:02}E{getattr(ep, 'episode_number', 0):02}-{base}"
                episodes.append((getattr(ep, 'episode_number', 0), ma.storage_key, arc))

        # Build ZIP incrementally (low memory)
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for _, key, arc in episodes:
                # Stream to temp file to avoid RAM spikes
                part_path = os.path.join(tmpd, arc)
                os.makedirs(os.path.dirname(part_path), exist_ok=True)
                with open(part_path, "wb") as fh:
                    s3.client.download_fileobj(s3.bucket, key, fh)  # type: ignore
                zf.write(part_path, arcname=arc)

        # Compute SHA + size
        size = os.path.getsize(zip_path)
        with open(zip_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                sha.update(chunk)
        sha_hex = sha.hexdigest()

        # Upload with multipart
        extra = {"ContentType": "application/zip", "ServerSideEncryption": "AES256"}
        s3.client.upload_file(zip_path, s3.bucket, dest_key, ExtraArgs=extra)  # type: ignore

        # Upload a manifest next to the ZIP for audit/debug
        manifest_key = dest_key[:-4] + "_manifest.json" if dest_key.lower().endswith(".zip") else dest_key + ".manifest.json"
        manifest = {
            "title_id": title_id,
            "season_number": season_number,
            "storage_key": dest_key,
            "size_bytes": size,
            "sha256": sha_hex,
            "items": [
                {"arcname": arc, "source_key": key} for (_, key, arc) in episodes
            ],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        import json as _json
        s3.put_bytes(manifest_key, _json.dumps(manifest).encode("utf-8"), content_type="application/json", extra_args={"ServerSideEncryption": "AES256"})

        # Update Bundle row
        exp_days = int(getattr(settings, "BUNDLE_DEFAULT_TTL_DAYS", 14))
        expires_at = datetime.now(timezone.utc) + timedelta(days=exp_days)
        async with transactional_async_session() as db:
            from app.db.models.bundle import Bundle  # local import to avoid circular
            row = (await db.execute(
                select(Bundle).where(Bundle.title_id == title_id, Bundle.season_number == season_number)
            )).scalar_one_or_none()
            if row:
                row.storage_key = dest_key
                row.size_bytes = size
                row.sha256 = sha_hex
                row.expires_at = expires_at
            else:
                b = Bundle(
                    title_id=title_id,
                    season_number=season_number,
                    storage_key=dest_key,
                    size_bytes=size,
                    sha256=sha_hex,
                    expires_at=expires_at,
                )
                db.add(b)
            await db.flush()
