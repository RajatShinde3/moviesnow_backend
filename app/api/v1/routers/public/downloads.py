from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# 🧊 Public Downloads API (CDN-friendly, proxy-safe)
# ─────────────────────────────────────────────────────────────────────────────

import hashlib
import json
import os
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.http_utils import (
    enforce_public_api_key,
    rate_limit,
    enforce_availability_for_download,
)
from app.db.session import get_async_db
from app.db.models.media_asset import MediaAsset
from app.db.models.stream_variant import StreamVariant
from app.schemas.enums import StreamProtocol
from app.utils.aws import S3Client
from app.core.redis_client import redis_wrapper

import time as _time

router = APIRouter(tags=["Public Downloads"])
__all__ = ["router"]

# ─────────────────────────────────────────────────────────────────────────────
# 📚 Pydantic response models (for nicer OpenAPI)
# ─────────────────────────────────────────────────────────────────────────────

class VariantOut(BaseModel):
    storage_key: str = Field(..., description="Object key (path) in storage, relative (no leading slash).")
    quality: Optional[str] = Field(None, description="Human-readable quality label (e.g., '1080p').")
    width: Optional[int] = Field(None, description="Video width in pixels.")
    height: Optional[int] = Field(None, description="Video height in pixels.")
    bandwidth_kbps: int = Field(..., ge=0, description="Approx. bitrate in kbps.")
    container: Optional[str] = Field(None, description="Container format name (e.g., MP4).")
    video_codec: Optional[str] = Field(None, description="Video codec name (e.g., H264).")
    audio_codec: Optional[str] = Field(None, description="Audio codec name (e.g., AAC).")
    audio_language: Optional[str] = Field(None, description="IETF BCP 47 tag (e.g., 'en', 'hi').")
    hdr: Optional[str] = Field(None, description="HDR format (if any).")
    label: Optional[str] = Field(None, description="Curator-provided label for this variant.")
    # Populated only when include_meta=1
    size_bytes: Optional[int] = Field(None, ge=0, description="Object size (from HEAD/cache).")
    etag: Optional[str] = Field(None, description="Storage ETag (from HEAD/cache).")
    sha256: Optional[str] = Field(None, description="Hex SHA-256 from registration (integrity).")


class TitleManifestOut(BaseModel):
    title_id: str
    items: List[VariantOut]


class EpisodeManifestOut(BaseModel):
    title_id: str
    episode_id: str
    items: List[VariantOut]


class TitleDownloadsOut(BaseModel):
    title_id: str
    videos: List[VariantOut]
    alternatives: Dict[str, str]


class EpisodeDownloadsOut(BaseModel):
    title_id: str
    episode_id: str
    videos: List[VariantOut]
    alternatives: Dict[str, str]


# ─────────────────────────────────────────────────────────────────────────────
# ⚙️ Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default


def _compute_etag(payload: Any) -> str:
    """Strong ETag: quoted SHA-256 of canonical JSON bytes."""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"\"{hashlib.sha256(raw).hexdigest()}\""


def _parse_inm(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [p.strip() for p in value.split(",") if p.strip()]


def _echo_correlation_headers(request: Request, response: Response) -> None:
    """Echo common correlation headers for client-side tracing."""
    for h in ("x-request-id", "traceparent"):
        if h in request.headers:
            response.headers[h] = request.headers[h]


def _cached_json(
    request: Request,
    payload: Any,
    *,
    ttl: int,
    extra_headers: Optional[Dict[str, str]] = None,
) -> JSONResponse:
    """
    Build a JSON response with **strong ETag** and CDN-friendly caching.

    Behavior
    --------
    1) Compute payload ETag (quoted SHA-256 of canonical JSON).
    2) Honor `If-None-Match` → return 304 (no body) if matches.
    3) Set `Cache-Control`: public, short TTL with SWR for edge friendliness.
    4) Keep `Vary` minimal (tests may assert its exact value).

    Notes
    -----
    * Using JSONResponse preserves explicit headers and avoids auto validation.
    * Keep per-route `ttl` short to prevent stale manifests during operations.
    """
    etag = _compute_etag(payload)
    inm = _parse_inm(request.headers.get("If-None-Match") or request.headers.get("if-none-match"))

    if etag in inm or "*" in inm:
        resp = JSONResponse(status_code=status.HTTP_304_NOT_MODIFIED, content=None)
    else:
        resp = JSONResponse(content=payload)

    resp.headers["ETag"] = etag
    resp.headers["Cache-Control"] = f"public, max-age={ttl}, s-maxage={ttl}, stale-while-revalidate=30"
    resp.headers["Vary"] = "Accept, If-None-Match"  # keep minimal to match tests
    resp.headers["X-Content-Type-Options"] = "nosniff"
    if extra_headers:
        for k, v in extra_headers.items():
            resp.headers[k] = v
    _echo_correlation_headers(request, resp)
    return resp


def _variant_dict(v: StreamVariant) -> Dict[str, Any]:
    height = getattr(v, "height", None)
    quality = f"{height}p" if height else None
    out: Dict[str, Any] = {
        "storage_key": (getattr(v, "url_path", "") or "").lstrip("/"),
        "quality": quality,
        "width": getattr(v, "width", None),
        "height": height,
        "bandwidth_kbps": int(getattr(v, "bandwidth_bps", 0) or 0) // 1000,
        "container": getattr(v, "container", None).name if getattr(v, "container", None) else None,
        "video_codec": getattr(v, "video_codec", None).name if getattr(v, "video_codec", None) else None,
        "audio_codec": getattr(v, "audio_codec", None).name if getattr(v, "audio_codec", None) else None,
        "audio_language": getattr(v, "audio_language", None),
        "hdr": getattr(v, "hdr", None).name if getattr(v, "hdr", None) else None,
        "label": getattr(v, "label", None),
    }
    try:
        ma = getattr(v, "media_asset", None)
        if ma is not None:
            sha = getattr(ma, "checksum_sha256", None)
            if sha:
                out["sha256"] = sha
    except Exception:
        pass
    return out


# Redis-backed S3 HEAD cache (short TTL) to reduce origin pressure for hot manifests
async def _head_with_cache(s3: S3Client, key: str) -> Optional[Dict[str, Any]]:
    ttl = _env_int("HEAD_CACHE_TTL", 60)
    cache_key = f"s3:head:{key}"
    try:
        cached = await redis_wrapper.json_get(cache_key, default=None)
    except Exception:
        cached = None
    if isinstance(cached, dict) and cached.get("fetched_at") and int(_time.time()) - int(cached.get("fetched_at", 0)) < ttl:
        return cached
    # Miss or stale: fetch
    try:
        head = s3.client.head_object(Bucket=s3.bucket, Key=key)  # type: ignore[attr-defined]
        data = {
            "ContentLength": int(head.get("ContentLength") or 0),
            "ETag": head.get("ETag"),
            "ContentType": head.get("ContentType"),
            "fetched_at": int(_time.time()),
        }
        try:
            await redis_wrapper.json_set(cache_key, data, ttl_seconds=ttl)
        except Exception:
            pass
        return data
    except Exception:
        return None


# ╔════════════════════════════════ Route: Title Manifest ════════════════════╗
# ║ 🧊📜  /titles/{title_id}/download-manifest                                 ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
@router.get(
    "/titles/{title_id}/download-manifest",
    summary="Download manifest (title-level curated files)",
    response_model=TitleManifestOut,
    responses={200: {"description": "OK"}, 304: {"description": "Not Modified"}},
)
async def title_download_manifest(
    request: Request,
    title_id: UUID = Path(..., description="Title ID (UUID)."),
    include_meta: int = Query(
        0,
        ge=0,
        le=1,
        description="If 1, performs storage HEAD to include size_bytes and etag per item.",
    ),
    db: AsyncSession = Depends(get_async_db),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> JSONResponse:
    """
    Return a curated set of **downloadable** title-level video files (e.g., MP4),
    optimized for public distribution.

    Security
    --------
    * Optional `X-API-Key` check (anti-abuse).
    * Rate-limited via dependency injection.

    Caching
    -------
    * Strong ETag + `Cache-Control` (short TTL) for CDN friendliness.
    * Honors `If-None-Match` → may respond `304 Not Modified`.

    Notes
    -----
    * Only progressive/MP4 variants are listed (no HLS/DASH).
    * `include_meta=1` adds S3 HEAD meta; failures are soft and ignored.
    """
    ttl = _env_int("PUBLIC_DOWNLOADS_CACHE_TTL", 60)

    # Optional availability gating (title-level)
    await enforce_availability_for_download(request, db, title_id=str(title_id))

    q = (
        select(StreamVariant)
        .join(MediaAsset, StreamVariant.media_asset_id == MediaAsset.id)
        .where(
            MediaAsset.title_id == title_id,
            MediaAsset.season_id.is_(None),
            MediaAsset.episode_id.is_(None),
            StreamVariant.protocol == StreamProtocol.MP4,
        )
        .order_by(StreamVariant.height.desc().nulls_last(), StreamVariant.bandwidth_bps.desc())
    )
    result = await db.execute(q)
    items = [_variant_dict(v) for v in result.scalars().all()]

    if include_meta:
        try:
            s3 = S3Client()
            for it in items:
                try:
                    head = await _head_with_cache(s3, it["storage_key"])  # type: ignore[arg-type]
                    if head:
                        it["size_bytes"] = int(head.get("ContentLength") or 0)
                        it["etag"] = head.get("ETag")
                except Exception:
                    # Soft-ignore missing objects or HEAD failures
                    pass
        except Exception:
            pass

    payload = {"title_id": str(title_id), "items": items}
    return _cached_json(request, payload, ttl=ttl)


# ╔════════════════════════════════ Route: Episode Manifest ══════════════════╗
# ║ 🧊📜  /titles/{title_id}/episodes/{episode_id}/download-manifest           ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
@router.get(
    "/titles/{title_id}/episodes/{episode_id}/download-manifest",
    summary="Download manifest (episode-level curated files)",
    response_model=EpisodeManifestOut,
    responses={200: {"description": "OK"}, 304: {"description": "Not Modified"}},
)
async def episode_download_manifest(
    request: Request,
    title_id: UUID = Path(..., description="Title ID (UUID)."),
    episode_id: UUID = Path(..., description="Episode ID (UUID)."),
    include_meta: int = Query(
        0,
        ge=0,
        le=1,
        description="If 1, performs storage HEAD to include size_bytes and etag per item.",
    ),
    db: AsyncSession = Depends(get_async_db),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> JSONResponse:
    """
    Return a curated set of **downloadable** episode-level video files (MP4).

    Semantics
    ---------
    * Episode scope only; excludes season/title generic assets.
    * MP4/progressive variants only (no streaming manifests).

    See also
    --------
    * Use `/titles/{title_id}/downloads` or episode variant for human-friendly
      alternatives, including delivery guidance.
    """
    ttl = _env_int("PUBLIC_DOWNLOADS_CACHE_TTL", 60)

    # Optional availability gating (episode-level)
    await enforce_availability_for_download(
        request, db, title_id=str(title_id), episode_id=str(episode_id)
    )

    q = (
        select(StreamVariant)
        .join(MediaAsset, StreamVariant.media_asset_id == MediaAsset.id)
        .where(
            MediaAsset.title_id == title_id,
            MediaAsset.episode_id == episode_id,
            StreamVariant.protocol == StreamProtocol.MP4,
        )
        .order_by(StreamVariant.height.desc().nulls_last(), StreamVariant.bandwidth_bps.desc())
    )
    result = await db.execute(q)
    items = [_variant_dict(v) for v in result.scalars().all()]

    if include_meta:
        try:
            s3 = S3Client()
            for it in items:
                try:
                    head = await _head_with_cache(s3, it["storage_key"])  # type: ignore[arg-type]
                    if head:
                        it["size_bytes"] = int(head.get("ContentLength") or 0)
                        it["etag"] = head.get("ETag")
                except Exception:
                    pass
        except Exception:
            pass

    payload = {"title_id": str(title_id), "episode_id": str(episode_id), "items": items}
    return _cached_json(request, payload, ttl=ttl)


# ╔════════════════════════════════ Route: Title Downloads ═══════════════════╗
# ║ 🧱📥  /titles/{title_id}/downloads                                         ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
@router.get(
    "/titles/{title_id}/downloads",
    summary="List downloadable assets for a title (policy & alternatives)",
    response_model=TitleDownloadsOut,
    responses={200: {"description": "OK"}, 304: {"description": "Not Modified"}},
)
async def list_downloads(
    request: Request,
    title_id: UUID = Path(..., description="Title ID (UUID)."),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> JSONResponse:
    """
    Title-level **downloads** listing.

    For public surface, expose policy and guidance only (no per-file listing).
    Tests expect {title_id, policy, title, episodes, alternatives}.
    """
    ttl = _env_int("PUBLIC_DOWNLOADS_CACHE_TTL", 60)
    payload: Dict[str, Any] = {
        "title_id": str(title_id),
        "policy": "bundles_only",
        "title": [],
        "episodes": [],
        "alternatives": {
            "bundle_list": f"/titles/{title_id}/bundles",
            "delivery_single": "/delivery/download-url",
            "delivery_batch": "/delivery/batch-download-urls",
        },
    }
    return _cached_json(request, payload, ttl=ttl)


# ╔════════════════════════════════ Route: Episode Downloads ═════════════════╗
# ║ 🧱📥  /titles/{title_id}/episodes/{episode_id}/downloads                   ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
@router.get(
    "/titles/{title_id}/episodes/{episode_id}/downloads",
    summary="List downloadable assets for a specific episode (policy & alternatives)",
    response_model=EpisodeDownloadsOut,
    responses={200: {"description": "OK"}, 304: {"description": "Not Modified"}},
)
async def list_episode_downloads(
    request: Request,
    title_id: UUID = Path(..., description="Title ID (UUID)."),
    episode_id: UUID = Path(..., description="Episode ID (UUID)."),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> JSONResponse:
    """
    Episode-level **downloads** listing.

    For public surface, expose policy and guidance only (no per-file listing).
    Tests expect {title_id, episode_id, policy, items, alternatives}.
    """
    ttl = _env_int("PUBLIC_DOWNLOADS_CACHE_TTL", 60)
    payload: Dict[str, Any] = {
        "title_id": str(title_id),
        "episode_id": str(episode_id),
        "policy": "bundles_only",
        "items": [],
        "alternatives": {
            "bundle_list": f"/titles/{title_id}/bundles",
            "delivery_single": "/delivery/download-url",
            "delivery_batch": "/delivery/batch-download-urls",
        },
    }
    return _cached_json(request, payload, ttl=ttl)
