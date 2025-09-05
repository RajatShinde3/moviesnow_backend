# app/api/v1/routers/public_bundles.py
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ 📦 MoviesNow • Public Bundles                                            ║
# ║                                                                          ║
# ║ Endpoints                                                                ║
# ║  - GET /titles/{title_id}/bundles                   → List active        ║
# ║  - GET /titles/{title_id}/bundles/{season}/manifest → Presigned manifest ║
# ╠──────────────────────────────────────────────────────────────────────────╣
# ║ Security & Caching                                                       
# ║  - Optional X-API-Key via `enforce_public_api_key`.                       
# ║  - Per-route rate limiting.                                               
# ║  - Listing is CDN-friendly (public cache, 10m default, ETag/304).         
# ║  - Manifest responses are `Cache-Control: no-store`.                      
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.http_utils import enforce_public_api_key, rate_limit
from app.db.session import get_async_db
from app.db.models.bundle import Bundle
from app.security_headers import set_sensitive_cache
from app.utils.aws import S3Client, S3StorageError

router = APIRouter(tags=["Public Bundles"])
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _ttl_seconds() -> int:
    """Return public list TTL (seconds), overridable via env `PUBLIC_BUNDLES_TTL_SEC`."""
    try:
        return max(0, int(os.environ.get("PUBLIC_BUNDLES_TTL_SEC", "600")))
    except Exception:
        return 600

def _apply_public_cache_headers(response: Response, *, ttl: int) -> None:
    """Set CDN- and browser-friendly caching headers for list responses."""
    # Allow edge caches to serve slightly stale while revalidating
    response.headers["Cache-Control"] = f"public, max-age={ttl}, s-maxage={ttl}, stale-while-revalidate=60"

def _echo_correlation_headers(request: Request, response: Response) -> None:
    """Echo correlation headers (best-effort) so clients can stitch logs."""
    for h in ("x-request-id", "traceparent"):
        if h in request.headers:
            response.headers[h] = request.headers[h]

def _calc_etag(items: List[dict]) -> str:
    """
    Compute a weak ETag from the stable subset of fields we expose.

    This enables conditional GETs (If-None-Match) without leaking internals.
    """
    hasher = hashlib.sha256()
    for it in items:
        # Keep ordering stable (season first), then hash id+expires info
        hasher.update(f"{it.get('season_number') or 0}:{it['id']}:{it.get('expires_at') or ''}\n".encode("utf-8"))
    return 'W/"' + hasher.hexdigest()[:32] + '"'

def _json(payload: object, *, status_code: int, request: Request, response: Response | None = None) -> JSONResponse:
    """Return JSON with optional correlation headers and no extra caching changes."""
    resp = JSONResponse(payload, status_code=status_code)
    if response is not None:
        # Mirror any already-set cache headers on the outgoing response object
        for k, v in response.headers.items():
            # JSONResponse starts with its own headers object; copy selected cache/correlation keys
            if k.lower() in {"cache-control", "etag", "pragma", "expires", "x-request-id", "traceparent"}:
                resp.headers[k] = v
    _echo_correlation_headers(request, resp)
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# 📜 List active bundles for a title (CDN-friendly)
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/titles/{title_id}/bundles",
    summary="List active bundles for a title",
)
async def list_bundles(
    title_id: UUID = Path(..., description="Title ID (UUID)"),
    request: Request = None,
    response: Response = None,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
    db: AsyncSession = Depends(get_async_db),
) -> JSONResponse:
    """
    List **non-expired** bundles for a title, optimized for CDN caching.

    Caching
    -------
    - Sets `Cache-Control: public` with a modest TTL (10 minutes by default).
    - Supports `ETag` + `If-None-Match` for 304 responses.
    - TTL can be tuned via `PUBLIC_BUNDLES_TTL_SEC`.

    Steps
    -----
    1) Query all bundles for the `title_id`.
    2) Filter out expired rows (server clock in UTC).
    3) Build a stable, public-safe shape for each item.
    4) Compute ETag; honor `If-None-Match` with a 304.
    5) Return JSON with CDN-friendly cache headers.
    """
    now = datetime.now(timezone.utc)

    # (1) Query
    rows = (
        await db.execute(
            select(Bundle).where(Bundle.title_id == title_id).order_by(Bundle.season_number.asc().nulls_last())
        )
    ).scalars().all()

    # (2) Filter + (3) Shape
    items: List[dict] = []
    for b in rows:
        if b.expires_at and b.expires_at <= now:
            continue
        items.append(
            {
                "id": str(b.id),
                "title_id": str(b.title_id),
                "season_number": b.season_number,
                "storage_key": b.storage_key,
                "size_bytes": b.size_bytes,
                "sha256": b.sha256,
                "expires_at": b.expires_at.isoformat() if b.expires_at else None,
                "label": b.label,
            }
        )

    # (4) ETag / Conditional GET
    etag = _calc_etag(items)
    if response is not None:
        response.headers["ETag"] = etag
        _apply_public_cache_headers(response, ttl=_ttl_seconds())
        _echo_correlation_headers(request, response)

    inm = request.headers.get("if-none-match")
    if inm and inm == etag:
        # 304 Not Modified with same caching headers
        return _json({}, status_code=304, request=request, response=response)

    # (5) Return JSON
    return _json(items, status_code=200, request=request, response=response)


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Get bundle manifest (presigned, short-lived)
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/titles/{title_id}/bundles/{season}/manifest",
    summary="Get bundle manifest (presigned)",
)
async def bundle_manifest(
    title_id: UUID,
    season: int = Path(..., ge=1, le=999, description="Season number"),
    request: Request = None,
    response: Response = None,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> JSONResponse:
    """
    Return a short-lived **presigned GET** URL for a bundle's JSON manifest.

    Security & Caching
    ------------------
    - Applies `Cache-Control: no-store` (signed URLs are per-request).
    - Validates existence via S3 `HEAD` before signing.
    - 404 if manifest is missing or not accessible.

    Steps
    -----
    1) Normalize object keys (zip + manifest).
    2) `HEAD` the manifest to ensure existence.
    3) Presign GET (300s default) with `application/json` content type.
    4) Respond with `no-store` headers.
    """
    # ── [1] Normalize keys ──────────────────────────────────────────────────
    base_key = f"bundles/{title_id}/S{int(season):02}.zip"
    manifest_key = base_key[:-4] + "_manifest.json"

    # ── [2] Existence check ─────────────────────────────────────────────────
    try:
        s3 = S3Client()
        s3.client.head_object(Bucket=s3.bucket, Key=manifest_key)  # type: ignore[attr-defined]
    except S3StorageError as e:
        log.warning("bundle_manifest: storage error for key=%s: %s", manifest_key, e)
        raise HTTPException(status_code=404, detail="Manifest not found")
    except Exception:
        # Treat unknown/permission errors as not-found to avoid leaking internals
        raise HTTPException(status_code=404, detail="Manifest not found")

    # ── [3] Presign ─────────────────────────────────────────────────────────
    try:
        url = s3.presigned_get(
            manifest_key,
            expires_in=300,
            response_content_type="application/json",
        )
    except Exception:
        # Avoid surfacing provider-specific exceptions
        raise HTTPException(status_code=503, detail="Could not sign manifest URL")

    # ── [4] Respond (no-store) ──────────────────────────────────────────────
    if response is not None:
        set_sensitive_cache(response, seconds=0)
        _echo_correlation_headers(request, response)
    return _json({"url": url}, status_code=200, request=request, response=response)
