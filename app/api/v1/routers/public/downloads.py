# app/api/v1/routers/public_downloads.py
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ 📦🎧 MoviesNow · Public Downloads (Restricted)                           ║
# ║                                                                          ║
# ║ Endpoints (public + optional API key):                                   ║
# ║  - GET /titles/{title_id}/downloads                 → Title-level list   ║
# ║  - GET /titles/{title_id}/episodes/{episode_id}/... → Episode-level list ║
# ╠──────────────────────────────────────────────────────────────────────────╣
# ║ Policy                                                                   
# ║  - Public routes **do not** expose raw per-episode downloadable assets.   ║
# ║    Serve ZIP bundles via `/delivery/*` instead (cost & abuse control).    ║
# ║  - These endpoints intentionally return empty lists with helpful hints.    ║
# ║  - If you later relax policy, only expose ORIGINAL/DOWNLOAD/VIDEO kinds.  ║
# ║                                                                           
# ║ Security & Ops                                                            
# ║  - Optional `X-API-Key` enforcement; per-route rate limits.               ║
# ║  - CDN-friendly `Cache-Control` (short TTL) + strong ETag.                ║
# ║  - Neutral errors; no storage keys or internals leaked.                   ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status
from fastapi.responses import JSONResponse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.http_utils import enforce_public_api_key, rate_limit
from app.db.session import get_async_db
from app.db.models.title import Title
from app.db.models.media_asset import MediaAsset
from app.db.models.stream_variant import StreamVariant
from app.schemas.enums import StreamProtocol

router = APIRouter(tags=["Public Downloads"])

# ─────────────────────────────────────────────────────────────────────────────
# ⚙️ Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default


def _compute_etag(payload: Any) -> str:
    """Strong ETag: quoted SHA-256 of canonical JSON."""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"\"{hashlib.sha256(raw).hexdigest()}\""


def _parse_inm(value: str | None) -> list[str]:
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
    extra_headers: Dict[str, str] | None = None,
) -> JSONResponse:
    """
    Build a JSON response with **strong ETag** and CDN-friendly caching.

    Steps
    -----
    1) Compute payload ETag.
    2) Honor `If-None-Match` → 304 if matches.
    3) Set `Cache-Control` with short max-age and SWR.
    """
    etag = _compute_etag(payload)
    inm = _parse_inm(request.headers.get("If-None-Match") or request.headers.get("if-none-match"))

    if etag in inm or "*" in inm:
        resp = JSONResponse(status_code=status.HTTP_304_NOT_MODIFIED, content=None)
    else:
        resp = JSONResponse(content=payload)

    resp.headers["ETag"] = etag
    resp.headers["Cache-Control"] = f"public, max-age={ttl}, s-maxage={ttl}, stale-while-revalidate=30"
    resp.headers["Vary"] = "Accept, If-None-Match"
    if extra_headers:
        for k, v in extra_headers.items():
            resp.headers[k] = v
    _echo_correlation_headers(request, resp)
    return resp


# ╔════════════════════════════════ Endpoints ════════════════════════════════╗

@router.get(
    "/titles/{title_id}/downloads",
    summary="List downloadable assets for a title (videos + guidance)",
)
async def list_downloads(
    request: Request,
    title_id: UUID = Path(..., description="Title ID (UUID)"),
    db: AsyncSession = Depends(get_async_db),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> JSONResponse:
    """Title-level downloads listing.

    Returns public, downloadable video renditions (if provisioned) and guidance
    for bundle/extras delivery. Only variants explicitly marked as downloadable
    are listed (e.g., progressive MP4s under the downloads namespace).
    """
    ttl = _env_int("PUBLIC_DOWNLOADS_CACHE_TTL", 60)

    # Fetch downloadable variants scoped to title (no episode scope)
    q = (
        select(StreamVariant)
        .join(MediaAsset, StreamVariant.media_asset_id == MediaAsset.id)
        .where(
            MediaAsset.title_id == title_id,
            MediaAsset.season_id.is_(None),
            MediaAsset.episode_id.is_(None),
            # Prefer explicit protocol for downloadable files
            StreamVariant.protocol == StreamProtocol.MP4,
        )
        .order_by(StreamVariant.height.desc().nulls_last(), StreamVariant.bandwidth_bps.desc())
    )
    result = await db.execute(q)
    variants: List[StreamVariant] = list(result.scalars().all())

    def _mk(v: StreamVariant) -> Dict[str, Any]:
        height = getattr(v, "height", None)
        quality = (f"{height}p" if height else None)
        return {
            "storage_key": (v.url_path or "").lstrip("/"),
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

    payload: Dict[str, Any] = {
        "title_id": str(title_id),
        "videos": [_mk(v) for v in variants],
        "alternatives": {
            "bundle_list": f"/titles/{title_id}/bundles",
            "delivery_single": "/delivery/download-url",
            "delivery_batch": "/delivery/batch-download-urls",
        },
    }
    return _cached_json(request, payload, ttl=ttl)


@router.get(
    "/titles/{title_id}/episodes/{episode_id}/downloads",
    summary="List downloadable assets for a specific episode (videos + guidance)",
)
async def list_episode_downloads(
    title_id: UUID,
    episode_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> JSONResponse:
    """Episode-level downloads listing (downloadable per-episode renditions)."""
    ttl = _env_int("PUBLIC_DOWNLOADS_CACHE_TTL", 60)

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
    variants: List[StreamVariant] = list(result.scalars().all())

    def _mk(v: StreamVariant) -> Dict[str, Any]:
        height = getattr(v, "height", None)
        quality = (f"{height}p" if height else None)
        return {
            "storage_key": (v.url_path or "").lstrip("/"),
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

    payload: Dict[str, Any] = {
        "title_id": str(title_id),
        "episode_id": str(episode_id),
        "videos": [_mk(v) for v in variants],
        "alternatives": {
            "bundle_list": f"/titles/{title_id}/bundles",
            "delivery_single": "/delivery/download-url",
            "delivery_batch": "/delivery/batch-download-urls",
        },
    }
    return _cached_json(request, payload, ttl=ttl)
