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
from typing import Any, Dict
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status
from fastapi.responses import JSONResponse

from app.api.http_utils import enforce_public_api_key, rate_limit

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
    summary="List downloadable assets for a title (restricted; use bundles)",
)
async def list_downloads(
    request: Request,
    title_id: UUID = Path(..., description="Title ID (UUID)"),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> JSONResponse:
    """
    Title-level downloads listing (restricted).

    Why restricted?
    ---------------
    - Prevents hotlinking & cost spikes from enumerating raw per-episode files.
    - Encourages low-churn delivery via season **ZIP bundles** or **extras**.

    Steps
    -----
    1) Build a neutral payload (no storage keys).
    2) Return with short `Cache-Control` and strong ETag.
    """
    if not request:
        # Shouldn't happen in FastAPI, but keep types honest.
        raise HTTPException(status_code=500, detail="Request context missing")

    ttl = _env_int("PUBLIC_DOWNLOADS_CACHE_TTL", 60)
    payload: Dict[str, Any] = {
        "title_id": str(title_id),
        "policy": "bundles_only",
        "title": [],          # reserved for future relaxation (ORIGINAL/DOWNLOAD/VIDEO kinds only)
        "episodes": [],       # reserved for future relaxation (group by episode)
        "alternatives": {
            "bundle_list": f"/titles/{title_id}/bundles",
            "delivery_single": "/delivery/download-url",
            "delivery_batch": "/delivery/batch-download-urls",
        },
    }
    return _cached_json(request, payload, ttl=ttl)


@router.get(
    "/titles/{title_id}/episodes/{episode_id}/downloads",
    summary="List downloadable assets for a specific episode (restricted; use bundles)",
)
async def list_episode_downloads(
    title_id: UUID,
    episode_id: UUID,
    request: Request,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> JSONResponse:
    """
    Episode-level downloads listing (restricted).

    Notes
    -----
    - Intentionally returns an empty list with guidance to use bundles.
    - Keeps response cacheable briefly for CDN friendliness.

    Steps
    -----
    1) Construct neutral payload (no storage_key exposure).
    2) Return 200 with ETag + short cache TTL.
    """
    if not request:
        raise HTTPException(status_code=500, detail="Request context missing")

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
