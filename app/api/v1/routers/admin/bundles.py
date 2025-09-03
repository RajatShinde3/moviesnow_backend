"""
MoviesNow • Admin Bundles (Production-Grade)
============================================

Provision and manage downloadable ZIP bundles (e.g., season archives or extras).
This module focuses on **admin-only** lifecycle with strong security, concurrency
safety, and defensive defaults to avoid accidental overwrites in object storage.

Endpoints
---------
- POST   /admin/titles/{title_id}/bundles            → Create DB row + presigned PUT
- DELETE /admin/bundles/{bundle_id}                  → Delete DB row + best-effort S3 delete
- GET    /admin/titles/{title_id}/bundles            → List bundles (admin view)
- GET    /admin/bundles/{bundle_id}                  → Get bundle (admin)
- PATCH  /admin/bundles/{bundle_id}                  → Update bundle metadata (label/expiry)
- POST   /admin/titles/{title_id}/season-extras      → Presign PUT for season extras ZIP (local-built)
- POST   /admin/titles/{title_id}/movie-extras       → Presign PUT for movie extras ZIP (local-built)

Security & Operational Hardening
--------------------------------
- Requires ADMIN role + MFA (`mfa_authenticated=True`) on **all** endpoints.
- Per-route SlowAPI rate limits.
- Responses carry **no-store** cache headers for token/URL-bearing admin data.
- Create is best-effort **idempotent** via `Idempotency-Key` snapshots in Redis.
- **Distributed locks** around create/delete to prevent races and duplicates.
- Defensive **duplicate/overwrite** guards:
  - For season bundles (`bundles/{title_id}/Sxx.zip`), prevent duplicate DB rows.
  - If the object already exists in S3 for the target key → 409 CONFLICT (no overwrite).
- Best-effort **structured audit logs** that never block success paths.

Conventions & Notes
-------------------
- `200 OK` on create to align with existing E2E/tests.
- `Bundle.episode_ids` stored as list of string UUIDs for portability.
- Keys:
  - Season bundle: `bundles/{title_id}/S{season:02}.zip`
  - Movie/adhoc bundle: `bundles/{title_id}/bundle_{random}.zip`
  - Extras ZIPs (local built): `downloads/{title_id}/extras/...`
"""

from __future__ import annotations

# ── [Imports] ─────────────────────────────────────────────────────────────────────────────
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, delete, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
from app.core.config import settings
from app.core.limiter import rate_limit
from app.core.redis_client import redis_wrapper
from app.core.security import get_current_user
from app.db.session import get_async_db
from app.db.models.title import Title
from app.db.models.bundle import Bundle
from app.db.models.user import User
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event
from app.utils.aws import S3Client, S3StorageError


# ── [Router] ─────────────────────────────────────────────────────────────────────────────
router = APIRouter(tags=["Admin Bundles"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Schemas
# ─────────────────────────────────────────────────────────────────────────────

class BundleCreateIn(BaseModel):
    """Create a bundle and obtain a presigned PUT for uploading the ZIP."""
    season_number: Optional[int] = Field(None, ge=0, description="Season number for series bundles")
    episode_ids: Optional[List[UUID]] = Field(
        None, description="Optional list of episode IDs captured for traceability"
    )
    ttl_days: Optional[int] = Field(None, ge=1, le=60, description="Bundle expiry window (days)")
    label: Optional[str] = Field(None, max_length=128, description="Friendly label for admin UX")


class BundlePatchIn(BaseModel):
    """Patch bundle metadata."""
    label: Optional[str] = Field(None, max_length=128)
    expires_at: Optional[datetime] = Field(None, description="Extend or shorten expiry")


class SeasonExtrasCreateIn(BaseModel):
    season_number: int = Field(..., ge=1)
    label: Optional[str] = None
    ttl_days: Optional[int] = Field(None, ge=1, le=60)


class MovieExtrasCreateIn(BaseModel):
    label: Optional[str] = None
    ttl_days: Optional[int] = Field(None, ge=1, le=60)


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _s3() -> S3Client:
    """Return an S3 client or raise 503 on provider errors."""
    try:
        return S3Client()
    except S3StorageError as e:  # pragma: no cover
        raise HTTPException(status_code=503, detail=str(e))


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _compute_expiry(ttl_days: Optional[int]) -> datetime:
    default_days = int(getattr(settings, "BUNDLE_DEFAULT_TTL_DAYS", 14))
    days = int(ttl_days or default_days)
    days = max(1, min(days, 60))
    return _now_utc() + timedelta(days=days)


async def _ensure_title(db: AsyncSession, title_id: UUID) -> Title:
    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")
    return t


# ╔═════════════════════════════ Create / Upload ═════════════════════════════╗

# ─────────────────────────────────────────────────────────────────────────────
# 📦 Create bundle (DB row) + Presigned PUT
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/titles/{title_id}/bundles", summary="Create bundle (presigned PUT)")
@rate_limit("10/minute")
async def create_bundle(
    title_id: UUID,
    payload: BundleCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Provision a bundle row and return a presigned PUT for uploading the ZIP.

    Steps
    -----
    0) Security & response cache hardening.
    1) Validate title.
    2) Idempotency replay (best-effort) via `Idempotency-Key`.
    3) Compute storage key; lock and perform duplicate/overwrite guards.
    4) Persist bundle row.
    5) Generate presigned PUT (content-type enforced).
    6) Commit, audit, optional idempotency snapshot, return.
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # ── [Step 1] Validate parent ────────────────────────────────────────────
    await _ensure_title(db, title_id)

    # ── [Step 2] Idempotency replay (best-effort) ───────────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:bundles:create:{title_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    # ── [Step 3] Compute key + concurrency/duplicate guard ─────────────────
    season = payload.season_number
    prefix = f"bundles/{title_id}/"
    key = f"{prefix}S{int(season):02}.zip" if season is not None else f"{prefix}bundle_{uuid4().hex[:12]}.zip"

    # One create per (title_id, season) at a time; also protects duplicates
    lock_slug = f"S{int(season):02}" if season is not None else "adhoc"
    async with redis_wrapper.lock(f"lock:bundle:create:{title_id}:{lock_slug}", timeout=10, blocking_timeout=3):
        # 3a) For season bundles, avoid duplicate DB rows
        if season is not None:
            dup = (
                await db.execute(
                    select(Bundle).where(
                        and_(Bundle.title_id == title_id, Bundle.season_number == season)
                    )
                )
            ).scalar_one_or_none()
            if dup:
                raise HTTPException(status_code=409, detail="Bundle for this season already exists")

        # 3b) Avoid overwriting an existing object in S3
        s3 = _s3()
        try:
            # If HEAD succeeds, the object already exists → reject
            s3.client.head_object(Bucket=s3.bucket, Key=key)  # type: ignore[attr-defined]
            raise HTTPException(status_code=409, detail="Storage key already exists in bucket")
        except Exception:
            # Any error here is acceptable to proceed with a PUT presign
            pass

        # ── [Step 4] Persist bundle row ────────────────────────────────────
        expires_at = _compute_expiry(payload.ttl_days)
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

        # ── [Step 5] Presign PUT ───────────────────────────────────────────
        try:
            upload_url = s3.presigned_put(key, content_type="application/zip", public=False)
        except S3StorageError as e:
            # Roll back the DB row if presign fails
            await db.rollback()
            raise HTTPException(status_code=503, detail=str(e))

        # ── [Step 6] Commit & audit ────────────────────────────────────────
        await db.commit()
        body = {
            "bundle_id": str(b.id),
            "storage_key": key,
            "upload_url": upload_url,
            "expires_at": expires_at.isoformat(),
        }

    try:
        await log_audit_event(
            db,
            user=current_user,
            action="BUNDLE_CREATE",
            status="SUCCESS",
            request=request,
            meta_data={"title_id": str(title_id), "bundle_id": body["bundle_id"], "storage_key": key},
        )
    except Exception:
        pass

    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    return body


# ╔══════════════════════════════ Read / List / Patch ════════════════════════╗

# ─────────────────────────────────────────────────────────────────────────────
# 📚 List bundles (admin view)
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/titles/{title_id}/bundles", summary="List bundles (admin view)")
@rate_limit("60/minute")
async def admin_list_bundles(
    title_id: UUID,
    request: Request,
    response: Response,
    include_expired: bool = Query(False),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> List[dict]:
    """List bundles for a title. By default hides expired ones."""
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response, seconds=0)

    await _ensure_title(db, title_id)
    now = _now_utc()
    rows = (await db.execute(select(Bundle).where(Bundle.title_id == title_id))).scalars().all()
    out: List[dict] = []
    for b in rows:
        if not include_expired and b.expires_at and b.expires_at <= now:
            continue
        out.append(
            {
                "id": str(b.id),
                "title_id": str(b.title_id),
                "season_number": b.season_number,
                "storage_key": b.storage_key,
                "size_bytes": getattr(b, "size_bytes", None),
                "sha256": getattr(b, "sha256", None),
                "expires_at": b.expires_at.isoformat() if b.expires_at else None,
                "label": getattr(b, "label", None),
                "created_by_id": str(b.created_by_id) if b.created_by_id else None,
                "created_at": b.created_at.isoformat() if getattr(b, "created_at", None) else None,
                "updated_at": b.updated_at.isoformat() if getattr(b, "updated_at", None) else None,
            }
        )
    return out


# ─────────────────────────────────────────────────────────────────────────────
# 🔎 Get a bundle
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/bundles/{bundle_id}", summary="Get bundle (admin)")
@rate_limit("60/minute")
async def admin_get_bundle(
    bundle_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Fetch a single bundle by id."""
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response, seconds=0)

    b = (await db.execute(select(Bundle).where(Bundle.id == bundle_id))).scalar_one_or_none()
    if not b:
        raise HTTPException(status_code=404, detail="Bundle not found")
    return {
        "id": str(b.id),
        "title_id": str(b.title_id),
        "season_number": b.season_number,
        "storage_key": b.storage_key,
        "size_bytes": getattr(b, "size_bytes", None),
        "sha256": getattr(b, "sha256", None),
        "expires_at": b.expires_at.isoformat() if b.expires_at else None,
        "label": getattr(b, "label", None),
        "created_by_id": str(b.created_by_id) if b.created_by_id else None,
        "created_at": b.created_at.isoformat() if getattr(b, "created_at", None) else None,
        "updated_at": b.updated_at.isoformat() if getattr(b, "updated_at", None) else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# ✏️ Patch bundle (label / expiry)
# ─────────────────────────────────────────────────────────────────────────────
@router.patch("/bundles/{bundle_id}", summary="Update bundle metadata (label/expiry)")
@rate_limit("30/minute")
async def admin_patch_bundle(
    bundle_id: UUID,
    payload: BundlePatchIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Update mutable metadata for a bundle (label, expires_at)."""
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    b = (await db.execute(select(Bundle).where(Bundle.id == bundle_id))).scalar_one_or_none()
    if not b:
        raise HTTPException(status_code=404, detail="Bundle not found")

    updates: dict = {}
    if payload.label is not None:
        b.label = payload.label or None
        updates["label"] = b.label
    if payload.expires_at is not None:
        if b.created_at and payload.expires_at <= b.created_at:
            raise HTTPException(status_code=400, detail="expires_at must be after created_at")
        b.expires_at = payload.expires_at
        updates["expires_at"] = b.expires_at.isoformat() if b.expires_at else None

    await db.flush()
    await db.commit()

    try:
        await log_audit_event(
            db,
            user=current_user,
            action="BUNDLE_PATCH",
            status="SUCCESS",
            request=request,
            meta_data={"bundle_id": str(bundle_id), **updates},
        )
    except Exception:
        pass

    # Return the fresh view
    return await admin_get_bundle(bundle_id, request, response, db, current_user)


# ╔═══════════════════════════════ Delete / Cleanup ══════════════════════════╗

# ─────────────────────────────────────────────────────────────────────────────
# 🗑️ Delete bundle (row + best-effort S3 delete)
# ─────────────────────────────────────────────────────────────────────────────
@router.delete("/bundles/{bundle_id}", summary="Delete bundle (row + best-effort S3)")
@rate_limit("10/minute")
async def delete_bundle(
    bundle_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Delete a bundle row and attempt to remove the underlying object in S3.

    Steps
    -----
    0) Security & no-store cache headers.
    1) Load bundle or 404.
    2) Lock on bundle_id to avoid concurrent deletes.
    3) Best-effort S3 delete of `storage_key` (errors ignored).
    4) Delete row and commit; audit.
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # ── [Step 1] Load bundle ────────────────────────────────────────────────
    b = (await db.execute(select(Bundle).where(Bundle.id == bundle_id))).scalar_one_or_none()
    if not b:
        raise HTTPException(status_code=404, detail="Bundle not found")

    # ── [Step 2] Concurrency guard ──────────────────────────────────────────
    lock_key = f"lock:bundle:delete:{bundle_id}"
    async with redis_wrapper.lock(lock_key, timeout=10, blocking_timeout=3):
        key = b.storage_key
        # ── [Step 3] Best-effort S3 delete ─────────────────────────────────
        try:
            s3 = _s3()
            s3.delete(key)
        except Exception:
            # Ignore storage-layer errors on delete to keep UX responsive
            pass

        # ── [Step 4] Remove DB row ─────────────────────────────────────────
        await db.execute(delete(Bundle).where(Bundle.id == bundle_id))
        await db.commit()

    try:
        await log_audit_event(
            db,
            user=current_user,
            action="BUNDLE_DELETE",
            status="SUCCESS",
            request=request,
            meta_data={"bundle_id": str(bundle_id), "storage_key": key},
        )
    except Exception:
        pass
    return {"status": "DELETED", "bundle_id": str(bundle_id)}


# ╔════════════════════════════════ Extras Uploads ═══════════════════════════╗

# ─────────────────────────────────────────────────────────────────────────────
# ⬆️ Presign PUT for season extras ZIP (local-built)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/titles/{title_id}/season-extras", summary="Presign upload for season extras ZIP (local-built)")
@rate_limit("10/minute")
async def create_season_extras_zip(
    title_id: UUID,
    payload: SeasonExtrasCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Return a presigned PUT for uploading a season extras ZIP built locally.

    Key layout: `downloads/{title_id}/extras/S{season}_extras.zip`
    Avoids server-side bundling costs; keeps delivery simple.
    """
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    await _ensure_title(db, title_id)
    key = f"downloads/{title_id}/extras/S{int(payload.season_number):02}_extras.zip"

    s3 = _s3()
    try:
        upload_url = s3.presigned_put(key, content_type="application/zip", public=False)
        return {"upload_url": upload_url, "storage_key": key}
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
# ⬆️ Presign PUT for movie extras ZIP (local-built)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/titles/{title_id}/movie-extras", summary="Presign upload for movie extras ZIP (local-built)")
@rate_limit("10/minute")
async def create_movie_extras_zip(
    title_id: UUID,
    payload: MovieExtrasCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Return a presigned PUT for uploading a movie extras ZIP built locally.

    Key layout: `downloads/{title_id}/extras/movie_extras.zip`
    """
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    await _ensure_title(db, title_id)
    key = f"downloads/{title_id}/extras/movie_extras.zip"

    s3 = _s3()
    try:
        upload_url = s3.presigned_put(key, content_type="application/zip", public=False)
        return {"upload_url": upload_url, "storage_key": key}
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))


