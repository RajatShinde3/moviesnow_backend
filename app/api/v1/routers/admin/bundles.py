from __future__ import annotations

"""
MoviesNow • Admin Bundles
=========================

Admin endpoints to provision season ZIP bundles and manage lifecycle.

Endpoints
---------
- POST   /admin/titles/{title_id}/bundles   → Create DB row + presigned PUT
- DELETE /admin/bundles/{bundle_id}         → Delete DB row + best-effort S3 delete

Security
--------
- Requires ADMIN + MFA.
- Rate limited.
- Idempotency via `Idempotency-Key` header for create.
- Audit logged (best-effort; non-blocking).
"""

from datetime import datetime, timedelta, timezone
import asyncio
from typing import Optional, Dict
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.routers.admin_assets import _ensure_mfa, _ensure_admin, _safe_prefix  # reuse helpers
from app.core.config import settings
from app.core.limiter import rate_limit
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.db.models.title import Title
from app.db.models.bundle import Bundle
from app.db.models.user import User
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event
from app.utils.aws import S3Client, S3StorageError

router = APIRouter(tags=["Admin Bundles"])


class BundleCreateIn(BaseModel):
    season_number: Optional[int] = Field(None, ge=0)
    episode_ids: Optional[list[UUID]] = None
    ttl_days: Optional[int] = Field(None, ge=1, le=60, description="Override default expiry days (7–30 recommended)")
    label: Optional[str] = Field(None, max_length=128)


class BundlePatchIn(BaseModel):
    label: Optional[str] = Field(None, max_length=128)
    expires_at: Optional[datetime] = None  # allow admin to extend expiry


def _ensure_s3() -> S3Client:
    try:
        return S3Client()
    except S3StorageError as e:  # pragma: no cover
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/titles/{title_id}/bundles", summary="Create bundle (presigned PUT)")
@rate_limit("10/minute")
async def create_bundle(
    title_id: UUID,
    payload: BundleCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(lambda: None),  # resolved in legacy deps
) -> Dict[str, str]:
    """Provision a bundle row and return a presigned PUT for uploading the ZIP.

    Steps
    -----
    1) Enforce ADMIN + MFA; apply no-store cache headers.
    2) Validate title exists; normalize key under bundles/ prefix.
    3) Compute expiry from default TTL (env override allowed).
    4) Create DB row (idempotent when Idempotency-Key present) and sign PUT.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)

    # Validate title
    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")

    # Idempotency (optional)
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:bundles:create:{title_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    # Compute key
    season = payload.season_number
    prefix = f"bundles/{title_id}/"
    if season is not None:
        key = f"{prefix}S{int(season):02}.zip"
    else:
        key = f"{prefix}bundle_{uuid4().hex[:12]}.zip"

    # TTL
    default_days = int(getattr(settings, "BUNDLE_DEFAULT_TTL_DAYS", 14))
    days = int(payload.ttl_days or default_days)
    days = max(1, min(days, 60))
    expires_at = datetime.now(timezone.utc) + timedelta(days=days)

    # Create row
    b = Bundle(
        title_id=title_id,
        season_number=season,
        episode_ids=[str(e) for e in (payload.episode_ids or [])] or None,
        storage_key=key,
        expires_at=expires_at,
        label=(payload.label or (f"Season {season}" if season is not None else None)),
        created_by_id=getattr(current_user, "id", None),
    )
    db.add(b)
    await db.flush()

    # Presign PUT
    s3 = _ensure_s3()
    try:
        url = s3.presigned_put(key, content_type="application/zip", public=False)
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))

    await db.commit()
    body = {"upload_url": url, "storage_key": key, "bundle_id": str(b.id), "expires_at": expires_at.isoformat()}

    try:
        await log_audit_event(db, user=current_user, action="BUNDLE_CREATE", status="SUCCESS", request=request,
                              meta_data={"title_id": str(title_id), "bundle_id": str(b.id), "expires_at": expires_at.isoformat()})
    except Exception:
        pass

    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    return body


@router.delete("/bundles/{bundle_id}", summary="Delete bundle (row + best-effort S3)")
@rate_limit("10/minute")
async def delete_bundle(
    bundle_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(lambda: None),
) -> Dict[str, str]:
    await _ensure_admin(current_user); await _ensure_mfa(request)
    # Fetch
    b = (await db.execute(select(Bundle).where(Bundle.id == bundle_id))).scalar_one_or_none()
    if not b:
        raise HTTPException(status_code=404, detail="Bundle not found")

    # Lock to avoid concurrent delete attempts
    lock_key = f"lock:bundle:delete:{bundle_id}"
    async with redis_wrapper.lock(lock_key, timeout=5, blocking_timeout=3):
        key = b.storage_key
        # Best-effort S3 delete
        try:
            s3 = _ensure_s3()
            s3.delete(key)
        except Exception:
            pass
        # Remove row
        await db.execute(delete(Bundle).where(Bundle.id == bundle_id))
        await db.commit()

    try:
        await log_audit_event(db, user=current_user, action="BUNDLE_DELETE", status="SUCCESS", request=request,
                              meta_data={"bundle_id": str(bundle_id), "storage_key": key})
    except Exception:
        pass
    return {"status": "DELETED", "bundle_id": str(bundle_id)}


@router.get("/titles/{title_id}/bundles", summary="List bundles (admin view)")
@rate_limit("60/minute")
async def admin_list_bundles(
    title_id: UUID,
    include_expired: bool = False,
    request: Request = None,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(lambda: None),
) -> list[dict]:
    await _ensure_admin(current_user); await _ensure_mfa(request)
    now = datetime.now(timezone.utc)
    rows = (await db.execute(select(Bundle).where(Bundle.title_id == title_id))).scalars().all()
    out = []
    for b in rows:
        if not include_expired and b.expires_at and b.expires_at <= now:
            continue
        out.append({
            "id": str(b.id),
            "title_id": str(b.title_id),
            "season_number": b.season_number,
            "storage_key": b.storage_key,
            "size_bytes": b.size_bytes,
            "sha256": b.sha256,
            "expires_at": b.expires_at.isoformat() if b.expires_at else None,
            "label": b.label,
            "created_by_id": str(b.created_by_id) if b.created_by_id else None,
            "created_at": b.created_at.isoformat() if b.created_at else None,
        })
    return out


@router.get("/bundles/{bundle_id}", summary="Get bundle (admin)")
@rate_limit("60/minute")
async def admin_get_bundle(
    bundle_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(lambda: None),
) -> dict:
    await _ensure_admin(current_user); await _ensure_mfa(request)
    b = (await db.execute(select(Bundle).where(Bundle.id == bundle_id))).scalar_one_or_none()
    if not b:
        raise HTTPException(status_code=404, detail="Bundle not found")
    return {
        "id": str(b.id),
        "title_id": str(b.title_id),
        "season_number": b.season_number,
        "storage_key": b.storage_key,
        "size_bytes": b.size_bytes,
        "sha256": b.sha256,
        "expires_at": b.expires_at.isoformat() if b.expires_at else None,
        "label": b.label,
        "created_by_id": str(b.created_by_id) if b.created_by_id else None,
        "created_at": b.created_at.isoformat() if b.created_at else None,
        "updated_at": b.updated_at.isoformat() if b.updated_at else None,
    }


@router.patch("/bundles/{bundle_id}", summary="Update bundle metadata (label/expiry)")
@rate_limit("30/minute")
async def admin_patch_bundle(
    bundle_id: UUID,
    payload: BundlePatchIn,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(lambda: None),
) -> dict:
    await _ensure_admin(current_user); await _ensure_mfa(request)
    b = (await db.execute(select(Bundle).where(Bundle.id == bundle_id))).scalar_one_or_none()
    if not b:
        raise HTTPException(status_code=404, detail="Bundle not found")
    updates = {}
    if payload.label is not None:
        b.label = payload.label or None
        updates["label"] = b.label
    if payload.expires_at is not None:
        if b.created_at and payload.expires_at <= b.created_at:
            raise HTTPException(status_code=400, detail="expires_at must be after created_at")
        b.expires_at = payload.expires_at
        updates["expires_at"] = b.expires_at.isoformat() if b.expires_at else None
    await db.flush(); await db.commit()
    try:
        await log_audit_event(db, user=current_user, action="BUNDLE_PATCH", status="SUCCESS", request=request, meta_data={"bundle_id": str(bundle_id), **updates})
    except Exception:
        pass
    return await admin_get_bundle(bundle_id, request, db, current_user)


@router.post("/titles/{title_id}/rebuild-bundle", summary="Rebuild bundle now (async)")
@rate_limit("10/minute")
async def admin_rebuild_bundle(
    title_id: UUID,
    season_number: int,
    request: Request,
    response: Response,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(lambda: None),
) -> dict:
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)
    # Respect settings: allow disabling server-side rebuilds (minimal-cost mode)
    from app.core.config import settings
    if not bool(getattr(settings, "BUNDLE_ENABLE_REBUILD", False)):
        raise HTTPException(status_code=405, detail="Rebuild is disabled. Build and upload ZIP locally via admin API.")
    # Ensure title exists
    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")
    dest_key = f"bundles/{title_id}/S{int(season_number):02}.zip"

    # Cooldown
    cd_key = f"cooldown:bundle:rebuild:{title_id}:{season_number}"
    cd_secs = int(getattr(settings, "BUNDLE_REBUILD_COOLDOWN_SECONDS", 3600))
    try:
        ttl = await redis_wrapper.client.ttl(cd_key)  # type: ignore
    except Exception:
        ttl = -2
    if isinstance(ttl, int) and ttl > 0:
        response.status_code = 202
        return {"status": "COOLDOWN", "retry_after_seconds": ttl}

    # Schedule via shared helper
    from app.api.v1.routers.delivery import _rebuild_bundle_and_upload  # local import to avoid cycles

    async def _run():
        await _rebuild_bundle_and_upload(title_id=str(title_id), season_number=int(season_number), dest_key=dest_key)

    try:
        await redis_wrapper.client.setex(cd_key, cd_secs, "1")  # type: ignore
    except Exception:
        pass
    background.add_task(asyncio.create_task, _run())
    response.status_code = 202
    return {"status": "REBUILDING", "storage_key": dest_key}
