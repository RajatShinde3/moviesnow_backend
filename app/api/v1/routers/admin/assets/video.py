"""
📼 MoviesNow · Admin Video Assets (main features)
=================================================

Security‑hardened FastAPI routes for managing **video assets** (the main movie
or episode files) under `/api/v1/admin`.

Routes (4)
----------
- POST   /api/v1/admin/titles/{title_id}/video     → Create a video asset (presigned PUT)
- GET    /api/v1/admin/titles/{title_id}/video     → List video assets for a title
- PATCH  /api/v1/admin/video/{asset_id}            → Update video asset metadata
- DELETE /api/v1/admin/video/{asset_id}            → Delete a video asset (DB + best‑effort S3)

Security & Operations
---------------------
- **Admin‑only** + **MFA** enforcement
- **SlowAPI** per‑route rate limits
- **Idempotency‑Key** replay for create
- **Redis locks** for mutating routes
- **Sensitive cache** headers on presign/metadata responses (`no-store`)
- **Audit logs** are best‑effort and never block the request path
- Explicit `JSONResponse` returns (to cooperate with SlowAPI header injection)

Adjust imports/paths for your project structure.
"""

# ─────────────────────────────────────────────────────────────────────────────
# 📦 Imports
# ─────────────────────────────────────────────────────────────────────────────
from typing import Optional, Dict, Any, List
from uuid import UUID, uuid4
import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_

from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.core.config import settings
from app.db.session import get_async_db
from app.db.models.user import User
from app.db.models.title import Title
from app.db.models.media_asset import MediaAsset
from app.schemas.enums import MediaAssetKind
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event
from app.utils.aws import S3Client, S3StorageError

# Router with admin prefix
router = APIRouter(prefix="/api/v1/admin", tags=["Admin • Video Assets"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧰 Helpers
# ─────────────────────────────────────────────────────────────────────────────
ALLOWED_VIDEO_MIME = {"video/mp4", "video/mpeg"}
_BCP47_RE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")


def _json(data: Any, status_code: int = 200) -> JSONResponse:
    """Return JSONResponse with strict no‑store headers for admin responses."""
    return JSONResponse(data, status_code=status_code, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


def _ensure_s3() -> S3Client:
    try:
        return S3Client()
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))


def _ext_for_content_type(ct: str) -> str:
    ct = (ct or "").lower()
    return {"video/mp4": "mp4", "video/mpeg": "mpg"}.get(ct, "bin")


def _ensure_allowed_mime(ct: str) -> None:
    if (ct or "").lower() not in ALLOWED_VIDEO_MIME:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Unsupported video content-type")


def _validate_language(tag: Optional[str]) -> Optional[str]:
    if not tag:
        return None
    tag = tag.strip()
    if not _BCP47_RE.match(tag):
        raise HTTPException(status_code=400, detail="Invalid language tag (BCP-47)")
    return tag


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Schemas
# ─────────────────────────────────────────────────────────────────────────────
class VideoCreateIn(BaseModel):
    """Input model for creating a **video** media asset with a presigned PUT.

    Notes
    -----
    - If `is_primary=true`, existing primaries (same title + language) are unset.
    - Returned `upload_url` is a short‑lived, private PUT URL to S3.
    """
    content_type: str = Field(..., description="e.g., video/mp4")
    language: Optional[str] = Field(None, description="BCP-47 tag (e.g., en, en-US)")
    is_primary: bool = False
    label: Optional[str] = Field(None, description="UI label stored in metadata")


class VideoPatchIn(BaseModel):
    language: Optional[str] = None
    is_primary: Optional[bool] = None
    label: Optional[str] = None
    sort_order: Optional[int] = Field(None, ge=0)
    cdn_url: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# ➕ Create video asset (presigned PUT)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/titles/{title_id}/video", summary="Create a video asset (presigned PUT)")
@rate_limit("6/minute")
async def create_video_asset(
    title_id: UUID,
    payload: VideoCreateIn | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Provision a **video** media asset and return a presigned **PUT** URL.

    Steps
    -----
    1) AuthZ/MFA + cache hardening
    2) Validate title, MIME, and optional language
    3) **Idempotency** (replay on matching `Idempotency-Key`)
    4) Presign S3 key and insert DB row (unset other primaries if requested)
    5) Return `{upload_url, storage_key, asset_id}`
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = VideoCreateIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Validate inputs ────────────────────────────────────────────
    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")
    _ensure_allowed_mime(payload.content_type)
    lang = _validate_language(payload.language)

    # ── [Step 3] Idempotency replay ─────────────────────────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:video:create:{title_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return _json(snap)

    # ── [Step 4] Presign + insert DB row ────────────────────────────────────
    s3 = _ensure_s3()
    ext = _ext_for_content_type(payload.content_type) or "mp4"
    key = f"video/title/{title_id}/main_{uuid4().hex}.{ext}"
    url = s3.presigned_put(key, content_type=payload.content_type, public=False)

    # Primary enforcement: unset others for same title/lang before insert
    if payload.is_primary:
        conds = [MediaAsset.title_id == title_id, MediaAsset.kind == MediaAssetKind.VIDEO]
        if lang is not None:
            from sqlalchemy import func
            conds += [func.coalesce(func.lower(MediaAsset.language), "") == str(lang).lower()]
        await db.execute(update(MediaAsset).where(and_(*conds)).values(is_primary=False))

    meta = {}
    if payload.label:
        meta["label"] = payload.label

    m = MediaAsset(
        title_id=title_id,
        kind=MediaAssetKind.VIDEO,
        language=lang,
        storage_key=key,
        mime_type=payload.content_type,
        is_primary=bool(payload.is_primary),
        metadata_json=meta or None,
    )
    db.add(m)
    await db.flush()
    await db.commit()

    body = {"upload_url": url, "storage_key": key, "asset_id": str(m.id)}

    try:
        await log_audit_event(db, user=current_user, action="VIDEO_CREATE", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "asset_id": body["asset_id"]})
    except Exception:
        pass

    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass

    return _json(body)


# ─────────────────────────────────────────────────────────────────────────────
# 📄 List video assets for a title
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/titles/{title_id}/video", summary="List video assets for a title")
@rate_limit("30/minute")
async def list_video_assets(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> JSONResponse:
    """List all **VIDEO** assets attached to the specified title.

    Returns a compact projection suitable for admin tables.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    rows = (
        await db.execute(
            select(MediaAsset)
            .where(MediaAsset.title_id == title_id, MediaAsset.kind == MediaAssetKind.VIDEO)
            .order_by(MediaAsset.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
    ).scalars().all() or []

    items = [{
        "id": str(a.id),
        "language": getattr(a, "language", None),
        "storage_key": getattr(a, "storage_key", None),
        "is_primary": bool(getattr(a, "is_primary", False)),
        "label": (getattr(a, "metadata_json", {}) or {}).get("label"),
        "cdn_url": getattr(a, "cdn_url", None),
        "created_at": getattr(a, "created_at", None),
    } for a in rows]

    return _json(items)


# ─────────────────────────────────────────────────────────────────────────────
# ✏️ Patch video asset metadata
# ─────────────────────────────────────────────────────────────────────────────
@router.patch("/video/{asset_id}", summary="Update video asset metadata")
@rate_limit("20/minute")
async def patch_video_asset(
    asset_id: UUID,
    payload: VideoPatchIn | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Update a video asset's language/primary/label/order/CDN link.

    Concurrency
    -----------
    - Uses a short **Redis lock** and a row‑level `FOR UPDATE` to serialize updates.

    Primary Semantics
    -----------------
    - Setting `is_primary=true` unsets other VIDEO assets for the same
      title/season/episode **and** same language (if present).
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = VideoPatchIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Serialize with lock ────────────────────────────────────────
    async with redis_wrapper.lock(f"lock:admin:video:{asset_id}", timeout=10, blocking_timeout=3):
        m = (
            await db.execute(
                select(MediaAsset)
                .where(MediaAsset.id == asset_id, MediaAsset.kind == MediaAssetKind.VIDEO)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if not m:
            raise HTTPException(status_code=404, detail="Video asset not found")

        updates: Dict[str, Any] = {}
        # Language
        if payload.language is not None:
            updates["language"] = _validate_language(payload.language)

        # Primary flip
        if payload.is_primary is not None:
            want_primary = bool(payload.is_primary)
            if want_primary:
                from sqlalchemy import func
                conds = [MediaAsset.kind == MediaAssetKind.VIDEO]
                if m.title_id:
                    conds += [MediaAsset.title_id == m.title_id]
                if m.season_id:
                    conds += [MediaAsset.season_id == m.season_id]
                if m.episode_id:
                    conds += [MediaAsset.episode_id == m.episode_id]
                lang = updates.get("language", m.language)
                if lang is not None:
                    conds += [func.coalesce(func.lower(MediaAsset.language), "") == str(lang).lower()]
                await db.execute(update(MediaAsset).where(and_(*conds)).values(is_primary=False))
                updates["is_primary"] = True
            else:
                updates["is_primary"] = False

        # Label in metadata_json
        if payload.label is not None:
            md = dict(getattr(m, "metadata_json", {}) or {})
            if payload.label:
                md["label"] = payload.label
            else:
                md.pop("label", None)
            updates["metadata_json"] = md

        # Sort order / CDN URL
        if payload.sort_order is not None:
            updates["sort_order"] = int(payload.sort_order)
        if payload.cdn_url is not None:
            updates["cdn_url"] = (payload.cdn_url or None)

        if updates:
            await db.execute(update(MediaAsset).where(MediaAsset.id == asset_id).values(**updates))
            await db.commit()

    try:
        await log_audit_event(db, user=current_user, action="VIDEO_PATCH", status="SUCCESS", request=request, meta_data={"asset_id": str(asset_id), "fields": list(updates.keys()) if updates else []})
    except Exception:
        pass

    # Fresh read for response projection
    m = (await db.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one_or_none()
    body = {
        "id": str(getattr(m, "id", asset_id)),
        "language": getattr(m, "language", None),
        "is_primary": bool(getattr(m, "is_primary", False)),
        "label": (getattr(m, "metadata_json", {}) or {}).get("label"),
        "sort_order": getattr(m, "sort_order", 0),
        "cdn_url": getattr(m, "cdn_url", None),
    }

    return _json(body)


# ─────────────────────────────────────────────────────────────────────────────
# 🗑️ Delete video asset
# ─────────────────────────────────────────────────────────────────────────────
@router.delete("/video/{asset_id}", summary="Delete a video asset")
@rate_limit("10/minute")
async def delete_video_asset(
    asset_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Hard‑delete a video media asset and best‑effort delete the S3 object.

    Steps
    -----
    1) AuthZ/MFA + cache hardening
    2) Load asset; capture storage_key
    3) Row delete under a short lock
    4) Best‑effort S3 delete (errors ignored)
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    m = (
        await db.execute(select(MediaAsset).where(MediaAsset.id == asset_id, MediaAsset.kind == MediaAssetKind.VIDEO))
    ).scalar_one_or_none()
    if not m:
        raise HTTPException(status_code=404, detail="Video asset not found")
    key = getattr(m, "storage_key", None)

    # ── [Step 3] Delete row under lock ──────────────────────────────────────
    async with redis_wrapper.lock(f"lock:admin:video:delete:{asset_id}", timeout=10, blocking_timeout=3):
        await db.execute(update(MediaAsset).where(MediaAsset.id == asset_id).values(deleted_at=None))  # no-op placeholder if soft delete later
        await db.execute("DELETE FROM media_assets WHERE id = :id", {"id": str(asset_id)})
        await db.commit()

    # ── [Step 4] Best‑effort S3 delete ──────────────────────────────────────
    if key:
        try:
            s3 = _ensure_s3()
            s3.delete(key)
        except Exception:
            pass

    try:
        await log_audit_event(db, user=current_user, action="VIDEO_DELETE", status="SUCCESS", request=request, meta_data={"asset_id": str(asset_id), "storage_key": key})
    except Exception:
        pass

    return _json({"message": "Deleted"})
