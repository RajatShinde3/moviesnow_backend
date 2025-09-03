from __future__ import annotations

"""
MoviesNow • Public Downloads
===========================

Public endpoint to list downloadable assets for a title.

Policy
------
- Only lists ORIGINAL/DOWNLOAD/VIDEO kinds (no artwork/subtitles here).
- Provides codec/container/label/size/sha256 when available.
- For series, groups by episode with episode_number if available.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.http_utils import enforce_public_api_key, rate_limit
from app.db.session import get_async_db
from app.db.models.media_asset import MediaAsset
from app.db.models.episode import Episode
from app.schemas.enums import MediaAssetKind

router = APIRouter(tags=["Public Downloads"])


def _asset_public_dict(a: MediaAsset) -> Dict[str, Any]:
    return {
        "asset_id": str(a.id),
        "storage_key": a.storage_key,
        "label": a.label,
        "container": str(getattr(a, "container", "") or ""),
        "video_codec": str(getattr(a, "video_codec", "") or ""),
        "audio_codec": str(getattr(a, "audio_codec", "") or ""),
        "width": a.width,
        "height": a.height,
        "bitrate_bps": a.bitrate_bps,
        "size_bytes": a.bytes_size,
        "sha256": a.checksum_sha256,
        "kind": str(a.kind.value if hasattr(a.kind, 'value') else a.kind),
    }


@router.get("/titles/{title_id}/downloads", summary="List downloadable assets for a title")
async def list_downloads(
    title_id: UUID = Path(..., description="Title ID"),
    request: Request = None,
    response: Response = None,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
    db: AsyncSession = Depends(get_async_db),
) -> Dict[str, Any]:
    # Title-scope assets without episode_id
    title_assets = (await db.execute(
        select(MediaAsset).where(
            MediaAsset.title_id == title_id,
            MediaAsset.episode_id.is_(None),
            MediaAsset.kind.in_([MediaAssetKind.ORIGINAL, MediaAssetKind.DOWNLOAD, MediaAssetKind.VIDEO]),
        ).order_by(MediaAsset.sort_order.asc(), MediaAsset.created_at.asc())
    )).scalars().all()

    items_title: List[Dict[str, Any]] = [_asset_public_dict(a) for a in title_assets]

    # Episode-scope assets
    eps = (await db.execute(
        select(Episode).where(Episode.title_id == title_id)
    )).scalars().all()
    episode_map = {e.id: e for e in eps}

    ep_assets = (await db.execute(
        select(MediaAsset).where(
            MediaAsset.title_id == title_id,
            MediaAsset.episode_id.is_not(None),
            MediaAsset.kind.in_([MediaAssetKind.ORIGINAL, MediaAssetKind.DOWNLOAD, MediaAssetKind.VIDEO]),
        ).order_by(MediaAsset.episode_id.asc(), MediaAsset.sort_order.asc(), MediaAsset.created_at.asc())
    )).scalars().all()

    episodes: Dict[str, Dict[str, Any]] = {}
    for a in ep_assets:
        eid = str(a.episode_id)
        e = episode_map.get(a.episode_id)
        bucket = episodes.setdefault(eid, {
            "episode_id": eid,
            "episode_number": getattr(e, 'episode_number', None) if e else None,
            "items": [],
        })
        bucket["items"].append(_asset_public_dict(a))

    # Light caching header (10 minutes)
    if response is not None:
        response.headers["Cache-Control"] = "public, max-age=600, s-maxage=600, stale-while-revalidate=60"
    return {"title": items_title, "episodes": list(episodes.values())}


@router.get(
    "/titles/{title_id}/episodes/{episode_id}/downloads",
    summary="List downloadable assets for a specific episode",
)
async def list_episode_downloads(
    title_id: UUID,
    episode_id: UUID,
    request: Request = None,
    response: Response = None,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
    db: AsyncSession = Depends(get_async_db),
) -> Dict[str, Any]:
    arows = (await db.execute(
        select(MediaAsset).where(
            MediaAsset.title_id == title_id,
            MediaAsset.episode_id == episode_id,
            MediaAsset.kind.in_([MediaAssetKind.ORIGINAL, MediaAssetKind.DOWNLOAD, MediaAssetKind.VIDEO]),
        ).order_by(MediaAsset.sort_order.asc(), MediaAsset.created_at.asc())
    )).scalars().all()
    items: List[Dict[str, Any]] = [_asset_public_dict(a) for a in arows]
    if response is not None:
        response.headers["Cache-Control"] = "public, max-age=600, s-maxage=600, stale-while-revalidate=60"
    return {"episode_id": str(episode_id), "items": items}
