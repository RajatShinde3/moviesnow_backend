
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ MoviesNow · Public Discovery API                                         ║
# ║                                                                          ║
# ║ Endpoints (public + optional API key):                                   ║
# ║  - GET /titles                           → Paginated discovery list      ║
# ║  - GET /titles/{title_id}                → Title detail                  ║
# ║  - GET /titles/{title_id}/streams        → Public stream variants        ║
# ║  - GET /titles/{title_id}/subtitles      → Public subtitle tracks        ║
# ║  - GET /search                           → Text search (paginated)       ║
# ║  - GET /genres                           → Available genres              ║
# ║  - GET /credits?title_id=...             → Public credits                ║
# ║  - GET /similar/{title_id}               → Related titles                ║
# ║  - GET /stream/{title_id}/{quality}      → Signed stream URL (no-store)  ║
# ║  - GET /download/{title_id}/{quality}    → Signed download URL (no-store)║
# ╠──────────────────────────────────────────────────────────────────────────╣
# ║ Security & Ops                                                           
# ║  - Optional `X-API-Key` enforcement (if configured).                      
# ║  - Rate limited via dependency.                                           
# ║  - Strong ETag + Cache-Control (CDN-friendly) where safe.                 
# ║  - RFC 5988 pagination headers (`Link`) + `X-Total-Count`.                
# ║  - Neutral errors; no internal details leaked.                            
# ║  - Structured logging (best-effort) without blocking request flow.        
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Public discovery endpoints for titles, streams, subtitles and related data.

Provides consistent caching (ETag + Cache-Control), optional public API key
enforcement, and rate limiting. Designed to be CDN-friendly.
"""

import hashlib
import json
import logging
import os
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse

from app.api.http_utils import (
    enforce_public_api_key,
    rate_limit,
    sanitize_title_id,
    json_no_store,  # used for signed URL responses (no-store)
)
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
from app.services.signing import SignedURL, generate_signed_url

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="",
    tags=["Public Discovery"],
    responses={
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        429: {"description": "Too Many Requests"},
        500: {"description": "Internal Server Error"},
    },
)

# ─────────────────────────────────────────────────────────────────────────────
# Cache & ETag helpers
# ─────────────────────────────────────────────────────────────────────────────

_resp_cache = TTLMap(maxsize=4096)

def _compute_etag(data: Any) -> str:
    """
    Compute a **strong** ETag (quoted SHA-256 hex of a canonicalized JSON payload).

    Returns
    -------
    str
        A quoted ETag value per RFC 7232, e.g. `"abc123..."`.
    """
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"\"{hashlib.sha256(raw).hexdigest()}\""


def _parse_if_none_match(header_val: Optional[str]) -> List[str]:
    """
    Parse `If-None-Match` which may contain a list of ETags separated by commas.

    Returns a list of trimmed values (keeps quotes if present).
    """
    if not header_val:
        return []
    return [part.strip() for part in header_val.split(",") if part.strip()]


def _cache_key(request: Request) -> str:
    """
    Build a stable cache key from method, path, and sorted query params.

    Note: Authentication is not considered here because these endpoints are public.
    If you add auth-sensitive variants in the future, include auth state in this key.
    """
    query = "&".join(sorted([f"{k}={v}" for k, v in request.query_params.multi_items()]))
    return f"{request.method}:{request.url.path}?{query}"


def _pagination_header_values(request: Request, *, page: int, page_size: int, total: int) -> Dict[str, str]:
    """Return RFC 5988 `Link` and `X-Total-Count` header values for pagination."""
    headers: Dict[str, str] = {}
    headers["X-Total-Count"] = str(total)

    def _q(p: int) -> str:
        qd = dict(request.query_params)
        qd["page"] = str(p)
        qd["page_size"] = str(page_size)
        return urlencode(qd)

    base_url = str(request.url).split("?")[0]
    last_page = max(1, (total + page_size - 1) // page_size)
    links: List[str] = []
    if page > 1:
        links.append(f'<{base_url}?{_q(1)}>; rel="first"')
        links.append(f'<{base_url}?{_q(page - 1)}>; rel="prev"')
    if page < last_page:
        links.append(f'<{base_url}?{_q(page + 1)}>; rel="next"')
        links.append(f'<{base_url}?{_q(last_page)}>; rel="last"')
    if links:
        headers["Link"] = ", ".join(links)
    return headers


def cache_json_response(
    request: Request,
    ttl: int,
    payload: Any,
    extra_headers: Optional[Dict[str, str]] = None,
) -> JSONResponse:
    """
    Return a JSONResponse with strong ETag + CDN-friendly Cache-Control.

    Handles conditional requests: returns 304 if `If-None-Match` matches.

    Parameters
    ----------
    request : Request
        Incoming request (used for conditional logic and cache key).
    ttl : int
        Cache TTL in seconds (applies to both max-age & s-maxage).
    payload : Any
        JSON-serializable payload.
    extra_headers : Optional[Dict[str, str]]
        Additional headers (e.g., pagination).

    Returns
    -------
    JSONResponse
    """
    etag = _compute_etag(payload)
    inm_values = _parse_if_none_match(request.headers.get("If-None-Match") or request.headers.get("if-none-match"))
    if etag in inm_values or "*" in inm_values:
        resp = JSONResponse(status_code=status.HTTP_304_NOT_MODIFIED, content=None)
        resp.headers["ETag"] = etag
        resp.headers["Cache-Control"] = (
            f"public, max-age={ttl}, s-maxage={ttl}, stale-while-revalidate=60, stale-if-error=300"
        )
        resp.headers["Vary"] = "Accept, If-None-Match"
        if extra_headers:
            for k, v in extra_headers.items():
                resp.headers[k] = v
        return resp

    resp = JSONResponse(content=payload)
    resp.headers["ETag"] = etag
    resp.headers["Cache-Control"] = (
        f"public, max-age={ttl}, s-maxage={ttl}, stale-while-revalidate=60, stale-if-error=300"
    )
    resp.headers["Vary"] = "Accept, If-None-Match"
    if extra_headers:
        for k, v in extra_headers.items():
            resp.headers[k] = v

    _resp_cache.set(_cache_key(request), {"payload": payload, "etag": etag}, ttl)
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# Public discovery endpoints: titles, streams, subtitles, credits, search
# ─────────────────────────────────────────────────────────────────────────────

_ALLOWED_SORT = {"popularity", "year", "rating", "name", "released_at"}
_ALLOWED_ORDER = {"asc", "desc"}

def _validated_sort(sort: Optional[str]) -> str:
    return sort if sort in _ALLOWED_SORT else "popularity"

def _validated_order(order: Optional[str]) -> str:
    return order if order in _ALLOWED_ORDER else "desc"


@router.get(
    "/titles",
    response_model=PaginatedTitles,
    response_model_exclude_none=True,
    summary="List titles for public discovery (paginated, cached)",
)
def list_titles(
    request: Request,
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
    """
    List titles for public discovery.

    Caching
    -------
    - Strong ETag + `Cache-Control` with short TTL (CDN-friendly).
    - Conditional GET with `If-None-Match` → `304 Not Modified`.

    Security
    --------
    - Optional `X-API-Key` if configured; always rate-limited.
    """
    cache_ttl = int(os.environ.get("PUBLIC_CACHE_TTL_SECONDS", "30"))

    # 1) Attempt to serve from in-memory TTL cache (still validates ETag)
    cached = _resp_cache.get(_cache_key(request))
    if cached and cached.get("payload") is not None:
        headers = _pagination_header_values(request, page=page, page_size=page_size, total=cached["payload"].get("total", 0))
        return cache_json_response(request, cache_ttl, cached["payload"], extra_headers=headers)  # type: ignore[index]

    # 2) Sanitize sort/order inputs
    sort = _validated_sort(sort)
    order = _validated_order(order)

    # 3) Query repository
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
        items, total, facets = repo.search_titles(
            q=q, filters=filters, sort=sort, order=order, page=page, page_size=page_size
        )
    except Exception as e:
        logger.exception("titles search failed: %s", e)
        raise HTTPException(status_code=500, detail="Search failed")

    # 4) Build payload and respond with cache headers + pagination headers
    payload = PaginatedTitles(
        items=[TitleSummary(**i) if not isinstance(i, TitleSummary) else i for i in items],
        page=page,
        page_size=page_size,
        total=int(total or 0),
        facets=facets or {},
    ).dict()
    headers = _pagination_header_values(request, page=page, page_size=page_size, total=payload["total"])
    return cache_json_response(request, cache_ttl, payload, extra_headers=headers)


@router.get(
    "/titles/{title_id}",
    response_model=TitleDetail,
    response_model_exclude_none=True,
    summary="Get title detail (optionally cached)",
)
def get_title(
    request: Request,
    title_id: str = Path(..., description="Title ID or slug"),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Return title details.

    Caching
    -------
    - If `PUBLIC_ITEM_CACHE_TTL_SECONDS` > 0, response is ETagged and cached.
      Otherwise, relies on outer CDN/reverse proxy policy.
    """
    tid = sanitize_title_id(title_id)
    repo = get_titles_repository()
    try:
        data = repo.get_title(tid)
        if not data:
            raise HTTPException(status_code=404, detail="Title not found")
        detail = data if isinstance(data, TitleDetail) else TitleDetail(**data)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("get title failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch title")

    ttl = int(os.environ.get("PUBLIC_ITEM_CACHE_TTL_SECONDS", "0"))
    if ttl > 0:
        return cache_json_response(request, ttl, detail.dict())
    return detail


@router.get(
    "/titles/{title_id}/streams",
    response_model=List[StreamVariant],
    response_model_exclude_none=True,
    summary="List available stream variants for a title",
)
def list_stream_variants(
    request: Request,
    title_id: str = Path(..., description="Title ID or slug"),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    List available stream variants for a title (public view).

    Caching
    -------
    - Uses short CDN-friendly cache if `PUBLIC_ITEM_CACHE_TTL_SECONDS` set.
    """
    tid = sanitize_title_id(title_id)
    repo = get_titles_repository()
    try:
        if repo and hasattr(repo, "get_stream_variants"):
            variants = repo.get_stream_variants(tid)
            data = [StreamVariant(**v) if not isinstance(v, StreamVariant) else v for v in variants]
        else:
            data = []
    except Exception as e:
        logger.exception("get stream variants failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch stream variants")

    ttl = int(os.environ.get("PUBLIC_ITEM_CACHE_TTL_SECONDS", "0"))
    payload = [v.dict() if isinstance(v, StreamVariant) else v for v in data]
    if ttl > 0:
        return cache_json_response(request, ttl, payload)
    return data


@router.get(
    "/titles/{title_id}/subtitles",
    response_model=List[SubtitleTrack],
    response_model_exclude_none=True,
    summary="List available subtitle tracks for a title",
)
def list_subtitles(
    request: Request,
    title_id: str = Path(..., description="Title ID or slug"),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    List available subtitle tracks for a title.

    Caching
    -------
    - Uses short CDN-friendly cache if `PUBLIC_ITEM_CACHE_TTL_SECONDS` set.
    """
    tid = sanitize_title_id(title_id)
    repo = get_titles_repository()
    try:
        if repo and hasattr(repo, "get_subtitles"):
            subs = repo.get_subtitles(tid)
            data = [SubtitleTrack(**s) if not isinstance(s, SubtitleTrack) else s for s in subs]
        else:
            data = []
    except Exception as e:
        logger.exception("get subtitles failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to fetch subtitles")

    ttl = int(os.environ.get("PUBLIC_ITEM_CACHE_TTL_SECONDS", "0"))
    payload = [s.dict() if isinstance(s, SubtitleTrack) else s for s in data]
    if ttl > 0:
        return cache_json_response(request, ttl, payload)
    return data


@router.get(
    "/search",
    response_model=PaginatedTitles,
    response_model_exclude_none=True,
    summary="Search titles by text query (paginated, cached)",
)
def search(
    request: Request,
    q: str = Query(..., min_length=1, max_length=128),
    page: int = Query(1, ge=1),
    page_size: int = Query(24, ge=1, le=100),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Search titles by text query.

    Caching
    -------
    - Strong ETag + `Cache-Control` with short TTL (CDN-friendly).
    """
    cache_ttl = int(os.environ.get("PUBLIC_CACHE_TTL_SECONDS", "30"))
    repo = get_titles_repository()
    try:
        items, total, facets = repo.search_titles(
            q=q, filters={}, sort="popularity", order="desc", page=page, page_size=page_size
        )
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
    headers = _pagination_header_values(request, page=page, page_size=page_size, total=payload["total"])
    return cache_json_response(request, cache_ttl, payload, extra_headers=headers)


@router.get(
    "/genres",
    response_model=List[str],
    summary="List known genres for discovery facets",
)
def list_genres(
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    List known genres for discovery facets.

    Notes
    -----
    - Falls back to a static list if the repository does not provide genres.
    """
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


@router.get(
    "/credits",
    response_model=List[Credit],
    response_model_exclude_none=True,
    summary="List public credits for a title",
)
def list_credits(
    title_id: str = Query(..., description="Title ID or slug"),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    List public credits for a title.
    """
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


@router.get(
    "/similar/{title_id}",
    response_model=List[TitleSummary],
    response_model_exclude_none=True,
    summary="Recommend related titles",
)
def similar_titles(
    title_id: str = Path(..., description="Title ID or slug"),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Recommend related titles (simple similarity or repo-provided).
    """
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


# ╭───────────────────────────────────────────────────────────────────────────╮
# │ Signed URL endpoints (no-store, private semantics)                         │
# ╰───────────────────────────────────────────────────────────────────────────╯

@router.get(
    "/stream/{title_id}/{quality}",
    response_model=SignedURL,
    response_model_exclude_none=True,
    summary="Return a signed stream URL for the requested quality",
)
def get_stream_url(
    title_id: str = Path(..., description="Title ID or slug"),
    quality: QualityEnum = Path(...),
    expires_in: int = Query(3600, ge=60, le=86400),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Return a signed stream URL for the requested quality.

    Security
    --------
    - HMAC-signed URL; set `STREAM_URL_SIGNING_SECRET`.
    - Response is `Cache-Control: no-store` to prevent intermediaries caching.
    """
    tid = sanitize_title_id(title_id)
    repo = get_titles_repository()
    resource_path = f"stream/{tid}"
    try:
        if repo and hasattr(repo, "get_stream_resource_path"):
            resource_path = str(repo.get_stream_resource_path(tid))
    except Exception as e:
        logger.warning("get_stream_resource_path failed, using default: %s", e)
    # Restrict to fixed cost-friendly variants
    if quality not in {QualityEnum.q480p, QualityEnum.q720p, QualityEnum.q1080p}:
        raise HTTPException(status_code=400, detail="Unsupported quality; allowed: 480p, 720p, 1080p")
    payload = generate_signed_url(
        resource_path=resource_path,
        quality=quality,
        expires_in=expires_in,
        purpose="stream",
    ).dict()
    # Ensure signed URLs are not cached anywhere
    return json_no_store(payload)


@router.get(
    "/download/{title_id}/{quality}",
    response_model=SignedURL,
    response_model_exclude_none=True,
    summary="Return a signed download URL for the requested quality",
)
def get_download_url(
    title_id: str = Path(..., description="Title ID or slug"),
    quality: QualityEnum = Path(...),
    expires_in: int = Query(3600, ge=60, le=86400),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Return a signed download URL for the requested quality.

    Security
    --------
    - HMAC-signed URL; set `STREAM_URL_SIGNING_SECRET`.
    - Response is `Cache-Control: no-store` to prevent intermediaries caching.
    """
    tid = sanitize_title_id(title_id)
    repo = get_titles_repository()
    resource_path = f"download/{tid}"
    try:
        if repo and hasattr(repo, "get_download_resource_path"):
            resource_path = str(repo.get_download_resource_path(tid))
    except Exception as e:
        logger.warning("get_download_resource_path failed, using default: %s", e)
    if quality not in {QualityEnum.q480p, QualityEnum.q720p, QualityEnum.q1080p}:
        raise HTTPException(status_code=400, detail="Unsupported quality; allowed: 480p, 720p, 1080p")
    payload = generate_signed_url(
        resource_path=resource_path,
        quality=quality,
        expires_in=expires_in,
        purpose="download",
    ).dict()
    return json_no_store(payload)
