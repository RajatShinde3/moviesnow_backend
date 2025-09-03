
"""
MoviesNow • Public Bundles
==========================

Public listing of active season bundles for a title.

Endpoint
--------
- GET /titles/{title_id}/bundles → List active bundles (with expires_at)

Security & Caching
------------------
- Optional X-API-Key via enforce_public_api_key.
- Rate limited via dependency.
- Sets modest Cache-Control (10 minutes) to align with CDN TTL guidance.
"""

from datetime import datetime, timezone
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.http_utils import enforce_public_api_key, rate_limit
from app.db.session import get_async_db
from app.db.models.bundle import Bundle
from app.security_headers import set_sensitive_cache
from app.utils.aws import S3Client, S3StorageError

router = APIRouter(tags=["Public Bundles"])


@router.get("/titles/{title_id}/bundles", summary="List active bundles for a title")
async def list_bundles(
    title_id: UUID = Path(..., description="Title ID (UUID)"),
    request: Request = None,
    response: Response = None,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
    db: AsyncSession = Depends(get_async_db),
) -> List[dict]:
    now = datetime.now(timezone.utc)
    rows = (await db.execute(
        select(Bundle).where(Bundle.title_id == title_id).order_by(Bundle.season_number.asc().nulls_last())
    )).scalars().all()

    # Filter: only non-expired bundles
    items = []
    for b in rows:
        if b.expires_at and b.expires_at <= now:
            continue
        items.append({
            "id": str(b.id),
            "title_id": str(b.title_id),
            "season_number": b.season_number,
            "storage_key": b.storage_key,
            "size_bytes": b.size_bytes,
            "sha256": b.sha256,
            "expires_at": b.expires_at.isoformat() if b.expires_at else None,
            "label": b.label,
        })

    # CDN-friendly TTL (aligned with /bundles/* behavior): 10 minutes
    if response is not None:
        response.headers["Cache-Control"] = "public, max-age=600, s-maxage=600, stale-while-revalidate=60"
    return items


@router.get("/titles/{title_id}/bundles/{season}/manifest", summary="Get bundle manifest (presigned)")
async def bundle_manifest(
    title_id: UUID,
    season: int = Path(..., ge=1),
    request: Request = None,
    response: Response = None,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
) -> dict:
    set_sensitive_cache(response)
    key = f"bundles/{title_id}/S{int(season):02}.zip"
    manifest_key = key[:-4] + "_manifest.json"
    try:
        s3 = S3Client()
        # HEAD to ensure it exists
        s3.client.head_object(Bucket=s3.bucket, Key=manifest_key)  # type: ignore
        url = s3.presigned_get(manifest_key, expires_in=300, response_content_type="application/json")
    except Exception:
        raise HTTPException(status_code=404, detail="Manifest not found")
    return {"url": url}
