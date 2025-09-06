from __future__ import annotations

"""
Public Schedule API
-------------------
Lists upcoming releases per region (country) or worldwide, based on
Availability windows. Includes poster and trailer URLs when available.

Routes
- GET /schedule/upcoming         -> upcoming releases for a region (auto-detect or ?country=IN)
- GET /schedule/worldwide        -> upcoming releases with GLOBAL availability

Caching
- Strong ETag + Cache-Control similar to public discovery endpoints.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.http_utils import (
    enforce_public_api_key,
    rate_limit,
    get_request_country,
)
from app.db.session import get_async_db
from app.db.models.availability import Availability
from app.db.models.title import Title
from app.db.models.media_asset import MediaAsset
from app.schemas.enums import TitleType, TerritoryMode
from app.schemas.schedule import ScheduleItem, ScheduleResponse
from app.utils.aws import S3Client, S3StorageError

# Reuse public discovery cache helpers for strong ETag and CDN headers
from .discovery import cache_json_response  # type: ignore


log = logging.getLogger(__name__)
router = APIRouter(prefix="", tags=["Public Schedule"])


def _epoch(dt: datetime) -> int:
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


async def _build_asset_urls(
    db: AsyncSession,
    *,
    poster_asset_id: Optional[str],
    trailer_asset_id: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    if not poster_asset_id and not trailer_asset_id:
        return None, None

    poster_url: Optional[str] = None
    trailer_url: Optional[str] = None

    ids: List[str] = [i for i in [poster_asset_id, trailer_asset_id] if i]
    if not ids:
        return None, None

    rows = (
        await db.execute(
            select(MediaAsset.id, MediaAsset.storage_key, MediaAsset.cdn_url).where(MediaAsset.id.in_(ids))
        )
    ).all()
    asset_map: Dict[str, Tuple[Optional[str], Optional[str]]] = {
        str(r[0]): (r[1], r[2]) for r in rows
    }

    try:
        s3 = S3Client()
    except S3StorageError:
        s3 = None  # type: ignore

    def _url_for(storage_key: Optional[str], cdn_url: Optional[str]) -> Optional[str]:
        if not storage_key and not cdn_url:
            return None
        if cdn_url:
            return cdn_url
        if s3 and storage_key:
            # Prefer non-signed public URL if CDN_BASE_URL or endpoint available
            cdn = s3.cdn_url(storage_key)
            return cdn or s3.object_url(storage_key)
        return None

    if poster_asset_id and poster_asset_id in asset_map:
        sk, cdn = asset_map[poster_asset_id]
        poster_url = _url_for(sk, cdn)
    if trailer_asset_id and trailer_asset_id in asset_map:
        sk, cdn = asset_map[trailer_asset_id]
        trailer_url = _url_for(sk, cdn)

    return poster_url, trailer_url


async def _query_upcoming(
    request: Request,
    db: AsyncSession,
    *,
    country: Optional[str],
    days: int,
    type_filter: Optional[TitleType],
    only_worldwide: bool = False,
    limit: int = 100,
) -> ScheduleResponse:
    now = datetime.now(timezone.utc)
    until = now + timedelta(days=days)

    # Base query: upcoming availability windows joined with published, non-deleted titles
    q = (
        select(
            Availability.id,
            Availability.title_id,
            Availability.season_id,
            Availability.episode_id,
            Availability.territory_mode,
            Availability.countries,
            Availability.window_start,
            Title.id,
            Title.type,
            Title.name,
            Title.slug,
            Title.is_published,
            Title.deleted_at,
            Title.poster_asset_id,
            Title.trailer_asset_id,
        )
        .join(Title, Title.id == Availability.title_id)
        .where(Title.is_published.is_(True))
        .where(Title.deleted_at.is_(None))
        .where(Availability.window_start >= func.timezone("UTC", func.now()))
        .where(Availability.window_start <= until)
    )

    if type_filter:
        q = q.where(Title.type == type_filter)

    if only_worldwide:
        q = q.where(Availability.territory_mode == TerritoryMode.GLOBAL)

    q = q.order_by(Availability.window_start.asc()).limit(limit * 5)  # wider net, we group later

    rows = (await db.execute(q)).all()
    if not rows:
        return ScheduleResponse(items=[], total=0)

    # Group by title -> earliest applicable window for the region predicate
    items: List[ScheduleItem] = []
    seen_title: set[str] = set()
    cc = (country or "").strip().upper()

    # Fast path: if no country provided and not worldwide endpoint, try headers
    if not cc and not only_worldwide:
        try:
            cc = get_request_country(request)
        except Exception:
            cc = ""

    for (
        _av_id,
        title_id,
        season_id,
        episode_id,
        territory_mode,
        countries,
        window_start,
        _t_id,
        t_type,
        t_name,
        t_slug,
        _pub,
        _del,
        poster_asset_id,
        trailer_asset_id,
    ) in rows:
        # Apply region gating in-process when country is provided
        is_world = territory_mode == TerritoryMode.GLOBAL
        if not only_worldwide:
            if cc:
                if territory_mode == TerritoryMode.INCLUDE:
                    if not countries or cc not in [x.upper() for x in countries or []]:
                        continue
                elif territory_mode == TerritoryMode.EXCLUDE:
                    if countries and cc in [x.upper() for x in countries or []]:
                        continue
                # GLOBAL passes
        # Keep only the first (earliest) per title
        tid = str(title_id)
        if tid in seen_title:
            continue

        poster_url, trailer_url = await _build_asset_urls(
            db, poster_asset_id=str(poster_asset_id) if poster_asset_id else None, trailer_asset_id=str(trailer_asset_id) if trailer_asset_id else None
        )

        items.append(
            ScheduleItem(
                id=tid,
                type=t_type,
                name=t_name,
                slug=t_slug,
                release_at=_epoch(window_start),
                region=("WW" if is_world else (cc or "")),
                is_worldwide=bool(is_world),
                poster_url=poster_url,
                trailer_url=trailer_url,
            )
        )
        seen_title.add(tid)
        if len(items) >= limit:
            break

    items.sort(key=lambda x: x.release_at)
    return ScheduleResponse(items=items, total=len(items))


@router.get(
    "/schedule/upcoming",
    response_model=ScheduleResponse,
    response_model_exclude_none=True,
    summary="Upcoming releases for a region (with poster/trailer)",
)
async def upcoming_schedule(
    request: Request,
    days: int = Query(30, ge=1, le=180),
    country: Optional[str] = Query(None, min_length=2, max_length=2, description="ISO country code, e.g. IN, US"),
    type: Optional[TitleType] = Query(None, description="Filter by title type: MOVIE or SERIES"),
    limit: int = Query(50, ge=1, le=200),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
    db: AsyncSession = Depends(get_async_db),
):
    """Return earliest upcoming release per title for the specified region.

    Region is taken from `?country=..` or detected from geo headers as a fallback.
    """
    payload = await _query_upcoming(
        request,
        db,
        country=(country.upper() if country else None),
        days=days,
        type_filter=type,
        only_worldwide=False,
        limit=limit,
    )
    # Cache 30s by default for public schedule
    return cache_json_response(request, 30, payload.model_dump())


@router.get(
    "/schedule/worldwide",
    response_model=ScheduleResponse,
    response_model_exclude_none=True,
    summary="Upcoming worldwide releases (GLOBAL availability)",
)
async def worldwide_schedule(
    request: Request,
    days: int = Query(30, ge=1, le=180),
    type: Optional[TitleType] = Query(None, description="Filter by title type: MOVIE or SERIES"),
    limit: int = Query(50, ge=1, le=200),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
    db: AsyncSession = Depends(get_async_db),
):
    """Return upcoming titles with GLOBAL availability windows."""
    payload = await _query_upcoming(
        request,
        db,
        country=None,
        days=days,
        type_filter=type,
        only_worldwide=True,
        limit=limit,
    )
    return cache_json_response(request, 30, payload.model_dump())


__all__ = ["router"]
