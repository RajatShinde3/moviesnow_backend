from __future__ import annotations

import hashlib
import logging
import os
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response, status
from fastapi.responses import JSONResponse

from app.api.http_utils import enforce_public_api_key, rate_limit, sanitize_title_id
from app.core.cache import TTLMap
from app.repositories.titles import get_titles_repository
from app.schemas.titles import (
    TitleSummary,
    TitleDetail,
    StreamVariant,
    SubtitleTrack,
    Credit,
    PaginatedTitles,
    QualityEnum,
)
from app.services.signing import SignedURL, QualityEnum as SignedQualityEnum, generate_signed_url


logger = logging.getLogger(__name__)


router = APIRouter(prefix="", tags=["Public Discovery"], responses={404: {"description": "Not found"}})


def _compute_etag(data: Any) -> str:
    import json

    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


_resp_cache = TTLMap(maxsize=4096)


def _cache_key(request: Request) -> str:
    query = "&".join(sorted([f"{k}={v}" for k, v in request.query_params.multi_items()]))
    return f"{request.method}:{request.url.path}?{query}"


def cache_json_response(request: Request, ttl: int, payload: Any) -> JSONResponse:
    etag = _compute_etag(payload)
    inm = request.headers.get("if-none-match") or request.headers.get("If-None-Match")
    if inm and inm == etag:
        return JSONResponse(status_code=status.HTTP_304_NOT_MODIFIED, content=None)

    resp = JSONResponse(content=payload)
    resp.headers["ETag"] = etag
    resp.headers["Cache-Control"] = (
        f"public, max-age={ttl}, s-maxage={ttl}, stale-while-revalidate=60, stale-if-error=300"
    )
    resp.headers["Vary"] = "Accept, If-None-Match"
    _resp_cache.set(_cache_key(request), {"payload": payload, "etag": etag}, ttl)
    return resp


def _map_quality(q: QualityEnum) -> SignedQualityEnum:
    return SignedQualityEnum(q.value)


@router.get("/titles", response_model=PaginatedTitles)
def list_titles(
    request: Request,
    response: Response,
    q: Optional[str] = Query(None, min_length=1, max_length=128, description="Search query"),
    page: int = Query(1, ge=1),
    page_size: int = Query(24, ge=1, le=100),
    sort: Optional[str] = Query("popularity", description="popularity|year|rating|name|released_at"),
    order: Optional[str] = Query("desc", description="asc|desc"),
    genres: Optional[List[str]] = Query(None, description="Filter by genre(s)"),
    year_gte: Optional[int] = Query(None, ge=1800, le=2100),
    year_lte: Optional[int] = Query(None, ge=1800, le=2100),
    rating_gte: Optional[float] = Query(None, ge=0.0, le=10.0),
    rating_lte: Optional[float] = Query(None, ge=0.0, le=10.0),
    cast: Optional[List[str]] = Query(None, description="Filter by credited names"),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """List titles for public discovery.

    - Supports full-text `q`, filters (genres/year/rating/cast), sorting and pagination.
    - Caching: ETag + Cache-Control with CDN-friendly directives and short TTL.
    - Security: optional `X-API-Key` if `PUBLIC_API_KEY` is set; rate limited.
    """
    cache_ttl = int(os.environ.get("PUBLIC_CACHE_TTL_SECONDS", "30"))
    cached = _resp_cache.get(_cache_key(request))
    if cached:
        imm = request.headers.get("if-none-match") or request.headers.get("If-None-Match")
        et = cached.get("etag")
        if imm and et and imm == et:
            return JSONResponse(status_code=status.HTTP_304_NOT_MODIFIED, content=None)
        payload = cached.get("payload")
        if payload is not None:
            resp = JSONResponse(content=payload)
            if et:
                resp.headers["ETag"] = et
            resp.headers["Cache-Control"] = (
                f"public, max-age={cache_ttl}, s-maxage={cache_ttl}, stale-while-revalidate=60, stale-if-error=300"
            )
            resp.headers["Vary"] = "Accept, If-None-Match"
            return resp

    repo = get_titles_repository()
    filters: Dict[str, Any] = {
        "genres": genres,
        "year_gte": year_gte,
        "year_lte": year_lte,
        "rating_gte": rating_gte,
        "rating_lte": rating_lte,
        "cast": cast,
    }
    try:
        items, total, facets = repo.search_titles(q=q, filters=filters, sort=sort, order=order, page=page, page_size=page_size)
    except Exception as e:
        logger.exception("titles search failed: %s", e)
        raise HTTPException(status_code=500, detail="Search failed")

    payload = PaginatedTitles(
        items=[TitleSummary(**i) if not isinstance(i, TitleSummary) else i for i in items],
        page=page,
        page_size=page_size,
        total=int(total or 0),
        facets=facets or {},
    ).dict()
    return cache_json_response(request, cache_ttl, payload)


@router.get("/titles/{title_id}", response_model=TitleDetail)
def get_title(
    title_id: str = Path(..., description="Title ID or slug"),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """Return title details.

    - Security: optional `X-API-Key` if configured; rate limited.
    - Not cached here; rely on reverse-proxy if needed.
    """
    tid = sanitize_title_id(title_id)
    repo = get_titles_repository()
    try:
        data = repo.get_title(tid)
        if not data:
            raise HTTPException(status_code=404, detail="Title not found")
        if not isinstance(data, TitleDetail):
            data = TitleDetail(**data)
        return data
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("get title failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch title")


@router.get("/titles/{title_id}/streams", response_model=List[StreamVariant])
def list_stream_variants(
    title_id: str = Path(..., description="Title ID or slug"),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """List available stream variants for a title (public view)."""
    sanitize_title_id(title_id)
    repo = get_titles_repository()
    try:
        if repo and hasattr(repo, "get_stream_variants"):
            variants = repo.get_stream_variants(title_id)
            return [StreamVariant(**v) if not isinstance(v, StreamVariant) else v for v in variants]
    except Exception as e:
        logger.exception("get stream variants failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch stream variants")

    return [
        StreamVariant(quality=QualityEnum.auto, container="m3u8", codec="h264"),
        StreamVariant(quality=QualityEnum.q480p, bitrate_kbps=1500, container="mp4", codec="h264"),
        StreamVariant(quality=QualityEnum.q720p, bitrate_kbps=3000, container="mp4", codec="h264"),
        StreamVariant(quality=QualityEnum.q1080p, bitrate_kbps=6000, container="mp4", codec="h265"),
    ]


@router.get("/titles/{title_id}/subtitles", response_model=List[SubtitleTrack])
def list_subtitles(
    title_id: str = Path(..., description="Title ID or slug"),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """List available subtitle tracks for a title."""
    sanitize_title_id(title_id)
    repo = get_titles_repository()
    try:
        if repo and hasattr(repo, "get_subtitles"):
            subs = repo.get_subtitles(title_id)
            return [SubtitleTrack(**s) if not isinstance(s, SubtitleTrack) else s for s in subs]
    except Exception as e:
        logger.exception("get subtitles failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch subtitles")

    return []


@router.get("/search", response_model=PaginatedTitles)
def search(
    request: Request,
    q: str = Query(..., min_length=1, max_length=128),
    page: int = Query(1, ge=1),
    page_size: int = Query(24, ge=1, le=100),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """Search titles by text query.

    - Caching: ETag + Cache-Control with short TTL.
    - Security: optional API key; rate limited.
    """
    repo = get_titles_repository()
    cache_ttl = int(os.environ.get("PUBLIC_CACHE_TTL_SECONDS", "30"))
    try:
        items, total, facets = repo.search_titles(q=q, filters={}, sort="popularity", order="desc", page=page, page_size=page_size)
    except Exception as e:
        logger.exception("search failed: %s", e)
        raise HTTPException(status_code=500, detail="Search failed")
    payload = PaginatedTitles(
        items=[TitleSummary(**i) if not isinstance(i, TitleSummary) else i for i in items],
        page=page,
        page_size=page_size,
        total=int(total or 0),
        facets=facets or {},
    ).dict()
    return cache_json_response(request, cache_ttl, payload)


@router.get("/genres", response_model=List[str])
def list_genres(_rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """List known genres for discovery facets."""
    repo = get_titles_repository()
    try:
        if repo and hasattr(repo, "list_genres"):
            genres = repo.list_genres()
            return [str(g) for g in genres]
    except Exception as e:
        logger.exception("list genres failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch genres")
    return [
        "Action",
        "Adventure",
        "Comedy",
        "Drama",
        "Horror",
        "Romance",
        "Sci-Fi",
        "Thriller",
        "Animation",
        "Documentary",
    ]


@router.get("/credits", response_model=List[Credit])
def list_credits(
    title_id: str = Query(..., description="Title ID or slug"),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """List public credits for a title."""
    tid = sanitize_title_id(title_id)
    repo = get_titles_repository()
    try:
        if repo and hasattr(repo, "get_credits"):
            credits = repo.get_credits(tid)
            return [Credit(**c) if not isinstance(c, Credit) else c for c in credits]
    except Exception as e:
        logger.exception("list credits failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch credits")
    return []


@router.get("/similar/{title_id}", response_model=List[TitleSummary])
def similar_titles(
    title_id: str = Path(..., description="Title ID or slug"),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """Recommend related titles (simple similarity or repo-provided)."""
    tid = sanitize_title_id(title_id)
    repo = get_titles_repository()
    try:
        if repo and hasattr(repo, "get_similar"):
            items = repo.get_similar(tid)
            return [TitleSummary(**i) if not isinstance(i, TitleSummary) else i for i in items]
    except Exception as e:
        logger.exception("get similar failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch similar titles")
    return []


@router.get("/stream/{title_id}/{quality}", response_model=SignedURL)
def get_stream_url(
    title_id: str = Path(..., description="Title ID or slug"),
    quality: QualityEnum = Path(...),
    expires_in: int = Query(3600, ge=60, le=86400),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """Return a signed stream URL for the requested quality.

    - Security: HMAC-signed URL; set `STREAM_URL_SIGNING_SECRET`.
    - TTL: configured via `expires_in` (defaults to 1 hour).
    """
    tid = sanitize_title_id(title_id)
    repo = get_titles_repository()
    resource_path = f"stream/{tid}"
    try:
        if repo and hasattr(repo, "get_stream_resource_path"):
            resource_path = str(repo.get_stream_resource_path(tid))
    except Exception as e:
        logger.warning("get_stream_resource_path failed, using default: %s", e)
    return generate_signed_url(resource_path=resource_path, quality=_map_quality(quality), expires_in=expires_in, purpose="stream")


@router.get("/download/{title_id}/{quality}", response_model=SignedURL)
def get_download_url(
    title_id: str = Path(..., description="Title ID or slug"),
    quality: QualityEnum = Path(...),
    expires_in: int = Query(3600, ge=60, le=86400),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """Return a signed download URL for the requested quality."""
    tid = sanitize_title_id(title_id)
    repo = get_titles_repository()
    resource_path = f"download/{tid}"
    try:
        if repo and hasattr(repo, "get_download_resource_path"):
            resource_path = str(repo.get_download_resource_path(tid))
    except Exception as e:
        logger.warning("get_download_resource_path failed, using default: %s", e)
    return generate_signed_url(resource_path=resource_path, quality=_map_quality(quality), expires_in=expires_in, purpose="download")
