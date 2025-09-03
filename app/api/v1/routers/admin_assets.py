"""
🧊 MoviesNow · Admin Assets (Artwork, Trailers, Subtitles, Streams, Uploads, CDN)
==================================================================================

Uploads use S3 presigned PUT URLs. DB rows are provisioned at request-time with
the generated storage key so clients can reference IDs immediately. Deletions
remove the DB row and (best-effort) the S3 object.

Routes (27)
-----------
Artwork (3)
  - POST   /titles/{title_id}/artwork
  - GET    /titles/{title_id}/artwork
  - DELETE /artwork/{artwork_id}

Trailers (3)
  - POST   /titles/{title_id}/trailers
  - GET    /titles/{title_id}/trailers
  - DELETE /trailers/{trailer_id}

Subtitles (4)
  - POST   /titles/{title_id}/subtitles
  - GET    /titles/{title_id}/subtitles
  - PATCH  /subtitles/{subtitle_id}
  - DELETE /subtitles/{subtitle_id}

Streams (4)
  - POST   /titles/{title_id}/streams
  - GET    /titles/{title_id}/streams
  - PATCH  /streams/{stream_id}
  - DELETE /streams/{stream_id}

Uploads (6)
  - POST   /uploads/init
  - POST   /uploads/multipart/create
  - GET    /uploads/multipart/{uploadId}/part-url
  - POST   /uploads/multipart/{uploadId}/complete
  - POST   /uploads/multipart/{uploadId}/abort
  - POST   /uploads/direct-proxy

Bulk (7)
  - POST   /bulk/manifest
  - GET    /bulk/jobs
  - GET    /bulk/jobs/{job_id}
  - POST   /bulk/jobs/{job_id}/cancel
  - GET    /bulk/jobs/{job_id}/items
  - POST   /bulk/jobs/{job_id}/retry
  - DELETE /bulk/jobs/{job_id}

CDN & Delivery (6)
  - POST   /cdn/invalidate
  - GET    /cdn/invalidation/{request_id}
  - POST   /delivery/signed-url
  - POST   /delivery/download-token
  - GET    /delivery/download/{token}
  - POST   /delivery/signed-manifest

Security & Operations
---------------------
- Admin-only and MFA-enforced (checks `mfa_authenticated` in access token)
- Per-route SlowAPI rate limits
- Redis idempotency for create endpoints (Idempotency-Key header)
- Redis distributed locks + DB row-level `FOR UPDATE` for mutations
- Sensitive cache headers on presigned responses (Cache-Control: no-store)
- Thorough audit logs (best-effort; must not block request flow)
"""


from typing import Optional, List, Dict, Literal
from uuid import UUID, uuid4
from datetime import datetime, timezone, timedelta
import base64
import re
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, update, delete, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import rate_limit
from app.core.jwt import decode_token
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.core.config import settings
from app.db.session import get_async_db
from app.db.models.user import User
from app.db.models.title import Title
from app.db.models.artwork import Artwork
from app.db.models.media_asset import MediaAsset
from app.db.models.stream_variant import StreamVariant
from app.db.models.subtitle import Subtitle
from app.schemas.enums import StreamProtocol, Container, StreamTier
from app.schemas.enums import ArtworkKind, MediaAssetKind, SubtitleFormat
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event
from app.dependencies.admin import (
    is_admin as _is_admin,
    ensure_admin as _ensure_admin,
    ensure_mfa as _ensure_mfa,
)
from app.utils.aws import S3Client, S3StorageError
import boto3


router = APIRouter(tags=["Admin Assets"])


# ─────────────────────────────────────────────────────────────────────────────
# 🔐 Access helpers
# ─────────────────────────────────────────────────────────────────────────────

 


# ─────────────────────────────────────────────────────────────────────────────
# 🧰 Utility helpers (validation, S3)
# ─────────────────────────────────────────────────────────────────────────────

ALLOWED_IMAGE_MIME = {"image/jpeg", "image/jpg", "image/png", "image/webp"}
ALLOWED_VIDEO_MIME = {"video/mp4", "video/mpeg"}
ALLOWED_SUBS_MIME  = {"text/vtt", "application/x-subrip"}

MAX_DIRECT_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MiB (proxy uploads)

_BCP47_RE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")  # pragmatic BCP-47-ish


def _ext_for_content_type(ct: str) -> str:
    ct = (ct or "").lower()
    return {
        "image/jpeg": "jpg",
        "image/jpg": "jpg",
        "image/png": "png",
        "image/webp": "webp",
        "video/mp4": "mp4",
        "video/mpeg": "mpg",
        "text/vtt": "vtt",
        "application/x-subrip": "srt",
    }.get(ct, "bin")


def _ensure_allowed_mime(ct: str, allowed: set[str], label: str) -> None:
    if (ct or "").lower() not in allowed:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=f"Unsupported {label} content-type")


def _validate_language(tag: Optional[str]) -> Optional[str]:
    if not tag:
        return None
    tag = tag.strip()
    if not _BCP47_RE.match(tag):
        raise HTTPException(status_code=400, detail="Invalid language tag (BCP-47)")
    return tag


def _sanitize_segment(s: Optional[str], fallback: str) -> str:
    """
    Sanitize a single path segment to avoid traversal or odd characters.
    - Keep letters, numbers, dot, dash, underscore
    - Collapse whitespace to underscore
    """
    s = (s or fallback).strip()
    s = re.sub(r"\s+", "_", s)
    s = re.sub(r"[^A-Za-z0-9._-]", "", s)
    return s or fallback


def _safe_prefix(prefix: Optional[str], default: str) -> str:
    p = (prefix or default).strip("/ ")
    p = re.sub(r"[^\w./-]", "", p)
    return p or default


def _ensure_s3() -> S3Client:
    if not getattr(settings, "AWS_BUCKET_NAME", None):  # type: ignore[attr-defined]
        raise HTTPException(status_code=503, detail="S3 storage not configured")
    try:
        return S3Client()
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
# 📦 Schemas
# ─────────────────────────────────────────────────────────────────────────────

class ArtworkCreateIn(BaseModel):
    """Input model for creating an artwork upload slot (presigned PUT)."""
    kind: ArtworkKind
    content_type: str = Field(..., description="MIME (e.g., image/jpeg)")
    language: Optional[str] = Field(None, description="BCP-47 tag (e.g., en-US)")
    is_primary: bool = False


class TrailerCreateIn(BaseModel):
    """Input model for creating a trailer upload slot (presigned PUT)."""
    content_type: str = Field(..., description="video mime (e.g., video/mp4)")
    language: Optional[str] = None
    is_primary: bool = False


class SubtitleCreateIn(BaseModel):
    """Input model for creating a subtitle + asset (presigned PUT)."""
    language: str = Field(..., min_length=2, max_length=16)
    format: SubtitleFormat = SubtitleFormat.VTT
    content_type: str = Field(..., description="text/vtt or application/x-subrip")
    label: Optional[str] = None
    is_default: bool = False
    is_forced: bool = False
    is_sdh: bool = False


class SubtitlePatchIn(BaseModel):
    language: Optional[str] = None
    label: Optional[str] = None
    is_default: Optional[bool] = None
    is_forced: Optional[bool] = None
    is_sdh: Optional[bool] = None
    active: Optional[bool] = None


class StreamCreateIn(BaseModel):
    """Input model for associating an HLS or MP4 stream variant to a title."""
    type: Literal["hls", "mp4"]
    quality: Literal["480p", "720p", "1080p"]
    url_path: str = Field(..., min_length=3, max_length=1024, description="Relative path to playlist or mp4 file")
    bandwidth_bps: int = Field(..., ge=64_000, le=500_000_000)
    avg_bandwidth_bps: Optional[int] = Field(None, ge=64_000, le=500_000_000)
    audio_language: Optional[str] = Field(None, min_length=2, max_length=16)
    label: Optional[str] = Field(None, max_length=64)
    is_default: bool = False
    asset_id: Optional[UUID] = None


class StreamPatchIn(BaseModel):
    is_streamable: Optional[bool] = None
    is_default: Optional[bool] = None
    is_downloadable: Optional[bool] = None
    stream_tier: Optional[StreamTier] = None


class UploadInitIn(BaseModel):
    content_type: str
    key_prefix: Optional[str] = Field("uploads/title", description="Base path prefix; sanitized")
    filename_hint: Optional[str] = None


class MultipartCreateIn(BaseModel):
    content_type: str
    key_prefix: Optional[str] = "uploads/multipart"
    filename_hint: Optional[str] = None


class MultipartCompleteIn(BaseModel):
    key: str
    parts: List[Dict[str, str]]  # [{ETag:"...", PartNumber:1}, ...]


class MultipartAbortIn(BaseModel):
    key: str


class DirectProxyIn(BaseModel):
    content_type: str
    data_base64: str
    key_prefix: Optional[str] = "uploads/direct"
    filename_hint: Optional[str] = None


class CDNInvalidateIn(BaseModel):
    paths: List[str] = Field(default_factory=list, description="Exact paths (e.g., /videos/a.m3u8)")
    prefixes: List[str] = Field(default_factory=list, description="Prefix patterns; expanded as prefix* for CloudFront")
    distribution_id: Optional[str] = Field(None, description="Override distribution ID (if not in settings)")


class SignedUrlIn(BaseModel):
    storage_key: str
    expires_in: int = Field(300, ge=60, le=3600)
    attachment_filename: Optional[str] = Field(None, description="If set, browsers download as this name")


class DownloadTokenIn(BaseModel):
    storage_key: str
    ttl_seconds: int = Field(3600, ge=60, le=24 * 3600)


class SignedManifestIn(BaseModel):
    """Request body to sign a manifest (HLS/DASH) for short-lived preview.

    The endpoint returns a signed URL for the manifest object itself. Segment
    URLs referenced within are not rewritten; this is intended for ephemeral
    previews where the manifest is privately stored.
    """
    storage_key: str
    expires_in: int = Field(300, ge=60, le=3600)
    format: Optional[Literal["hls", "dash"]] = Field(None, description="Override auto-detect by file extension")


# ─────────────────────────────────────────────────────────────────────────────
# 🖼️ Artwork
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/titles/{title_id}/artwork", summary="Create artwork (presigned PUT)")
@rate_limit("10/minute")
async def create_artwork(
    title_id: UUID,
    payload: ArtworkCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Provision an **artwork** record and return a presigned **PUT** URL.

    Steps:
    1) Enforce ADMIN + MFA; apply `no-store` cache headers.
    2) Validate title exists, MIME is allowed, and language tag if provided.
    3) Generate deterministic S3 key; create DB row.
    4) Return `{upload_url, storage_key, artwork_id}`.
    """
    # [Step 0] AuthZ / AuthN and cache hardening
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)

    # [Step 1] Validate inputs
    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")
    _ensure_allowed_mime(payload.content_type, ALLOWED_IMAGE_MIME, "image")
    lang = _validate_language(payload.language)

    # [Step 2] Idempotent replay (best-effort)
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:artwork:create:{title_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    # [Step 3] Build key + presign
    s3 = _ensure_s3()
    ext = _ext_for_content_type(payload.content_type)
    key = f"artwork/title/{title_id}/{payload.kind.value.lower()}_{uuid4().hex}.{ext}"
    url = s3.presigned_put(key, content_type=payload.content_type, public=False)

    # [Step 4] Create DB row
    art = Artwork(
        title_id=title_id,
        kind=payload.kind,
        language=lang,
        storage_key=key,
        content_type=payload.content_type,
        is_primary=bool(payload.is_primary),
    )
    db.add(art); await db.flush(); await db.commit()

    # [Step 5] Log + snapshot
    body = {"upload_url": url, "storage_key": key, "artwork_id": str(art.id)}
    await log_audit_event(db, user=current_user, action="ARTWORK_CREATE", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "artwork_id": body["artwork_id"]})
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    return body


@router.get("/titles/{title_id}/artwork", summary="List artwork")
@rate_limit("30/minute")
async def list_artwork(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    kind: Optional[ArtworkKind] = Query(None),
    language: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    """
    List artwork for a title with optional filters and pagination.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request)
    stmt = select(Artwork).where(Artwork.title_id == title_id)
    if kind:
        stmt = stmt.where(Artwork.kind == kind)
    if language:
        stmt = stmt.where(func.lower(Artwork.language) == language.strip().lower())
    stmt = stmt.order_by(Artwork.created_at.desc()).offset(offset).limit(limit)
    rows = (await db.execute(stmt)).scalars().all() or []
    return [{
        "id": str(a.id),
        "kind": str(getattr(a, "kind", None)),
        "language": getattr(a, "language", None),
        "storage_key": getattr(a, "storage_key", None),
        "is_primary": bool(getattr(a, "is_primary", False)),
        "created_at": getattr(a, "created_at", None),
    } for a in rows]


class ArtworkPatchIn(BaseModel):
    language: Optional[str] = Field(None, description="BCP-47 tag (e.g., 'en', 'en-US')")
    is_primary: Optional[bool] = None
    region: Optional[str] = Field(None, description="ISO-3166-1 alpha-2 (optional)")
    dominant_color: Optional[str] = None
    focus_x: Optional[float] = Field(None, ge=0.0, le=1.0)
    focus_y: Optional[float] = Field(None, ge=0.0, le=1.0)
    sort_order: Optional[int] = Field(None, ge=0)
    cdn_url: Optional[str] = None


@router.patch("/artwork/{artwork_id}", summary="Update artwork flags/meta")
@rate_limit("20/minute")
async def patch_artwork(
    artwork_id: UUID,
    payload: ArtworkPatchIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)

    async with redis_wrapper.lock(f"lock:admin:artwork:{artwork_id}", timeout=10, blocking_timeout=3):
        art = (await db.execute(select(Artwork).where(Artwork.id == artwork_id).with_for_update())).scalar_one_or_none()
        if not art:
            raise HTTPException(status_code=404, detail="Artwork not found")

        updates: Dict[str, object] = {}
        if payload.language is not None:
            updates["language"] = _validate_language(payload.language)
        if payload.region is not None:
            updates["region"] = (payload.region or None)
        if payload.dominant_color is not None:
            updates["dominant_color"] = (payload.dominant_color or None)
        if payload.focus_x is not None:
            updates["focus_x"] = payload.focus_x
        if payload.focus_y is not None:
            updates["focus_y"] = payload.focus_y
        if payload.sort_order is not None:
            updates["sort_order"] = int(payload.sort_order)
        if payload.cdn_url is not None:
            updates["cdn_url"] = (payload.cdn_url or None)

        if payload.is_primary is not None:
            want_primary = bool(payload.is_primary)
            if want_primary:
                # Unset others for same parent/kind/lang first to avoid unique violations
                lang = updates.get("language", art.language)
                conds = [Artwork.kind == art.kind]
                if art.title_id:
                    conds += [Artwork.title_id == art.title_id]
                if art.season_id:
                    conds += [Artwork.season_id == art.season_id]
                if art.episode_id:
                    conds += [Artwork.episode_id == art.episode_id]
                if lang is not None:
                    conds += [func.coalesce(func.lower(Artwork.language), "") == (str(lang).lower())]
                await db.execute(update(Artwork).where(and_(*conds)).values(is_primary=False))
                updates["is_primary"] = True
            else:
                updates["is_primary"] = False

        if updates:
            await db.execute(update(Artwork).where(Artwork.id == artwork_id).values(**updates))
            await db.commit()

    await log_audit_event(db, user=current_user, action="ARTWORK_PATCH", status="SUCCESS", request=request,
                          meta_data={"artwork_id": str(artwork_id), "fields": list(updates.keys()) if updates else []})
    # Return a small view
    art = (await db.execute(select(Artwork).where(Artwork.id == artwork_id))).scalar_one_or_none()
    return {
        "id": str(getattr(art, "id", artwork_id)),
        "language": getattr(art, "language", None),
        "is_primary": bool(getattr(art, "is_primary", False)),
        "sort_order": getattr(art, "sort_order", 0),
    }


class ReorderArtworkIn(BaseModel):
    order: List[UUID] = Field(..., description="Artwork IDs in desired order (front to back)")


@router.post("/titles/{title_id}/artwork/reorder", summary="Reorder artwork for a title")
@rate_limit("10/minute")
async def reorder_artwork(
    title_id: UUID,
    payload: ReorderArtworkIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)
    ids = [UUID(str(i)) for i in payload.order]
    if not ids:
        raise HTTPException(status_code=400, detail="Provide at least one artwork id")

    async with redis_wrapper.lock(f"lock:admin:artwork:reorder:{title_id}", timeout=15, blocking_timeout=5):
        # Verify all belong to title
        rows = (await db.execute(select(Artwork.id).where(Artwork.title_id == title_id, Artwork.id.in_(ids)))).scalars().all()
        found = set(rows)
        missing = [str(i) for i in ids if i not in found]
        if missing:
            raise HTTPException(status_code=400, detail=f"Artwork not for title or missing: {', '.join(missing)}")
        # Assign sort_order in the given order (0..)
        for idx, aid in enumerate(ids):
            await db.execute(update(Artwork).where(Artwork.id == aid).values(sort_order=idx))
        await db.commit()

    await log_audit_event(db, user=current_user, action="ARTWORK_REORDER", status="SUCCESS", request=request,
                          meta_data={"title_id": str(title_id), "count": len(ids)})
    return {"message": "Reordered", "count": len(ids)}


@router.post("/titles/{title_id}/artwork/{artwork_id}/make-primary", summary="Make this artwork primary")
@rate_limit("10/minute")
async def make_primary_artwork(
    title_id: UUID,
    artwork_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)

    async with redis_wrapper.lock(f"lock:admin:artwork:primary:{title_id}:{artwork_id}", timeout=15, blocking_timeout=5):
        art = (await db.execute(select(Artwork).where(Artwork.id == artwork_id).with_for_update())).scalar_one_or_none()
        if not art or art.title_id != title_id:
            raise HTTPException(status_code=404, detail="Artwork not found for this title")
        lang = art.language
        conds = [Artwork.title_id == title_id, Artwork.kind == art.kind]
        if lang is not None:
            conds += [func.coalesce(func.lower(Artwork.language), "") == str(lang).lower()]
        await db.execute(update(Artwork).where(and_(*conds)).values(is_primary=False))
        await db.execute(update(Artwork).where(Artwork.id == artwork_id).values(is_primary=True))
        await db.commit()

    await log_audit_event(db, user=current_user, action="ARTWORK_MAKE_PRIMARY", status="SUCCESS", request=request,
                          meta_data={"title_id": str(title_id), "artwork_id": str(artwork_id)})
    return {"message": "Primary set"}


class TrailerPatchIn(BaseModel):
    language: Optional[str] = None
    is_primary: Optional[bool] = None
    label: Optional[str] = Field(None, description="UI label stored in metadata")


@router.patch("/trailers/{trailer_id}", summary="Update trailer flags/label")
@rate_limit("20/minute")
async def patch_trailer(
    trailer_id: UUID,
    payload: TrailerPatchIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)

    async with redis_wrapper.lock(f"lock:admin:trailer:{trailer_id}", timeout=10, blocking_timeout=3):
        m = (await db.execute(select(MediaAsset).where(MediaAsset.id == trailer_id, MediaAsset.kind == MediaAssetKind.TRAILER).with_for_update())).scalar_one_or_none()
        if not m:
            raise HTTPException(status_code=404, detail="Trailer not found")

        updates: Dict[str, object] = {}
        if payload.language is not None:
            updates["language"] = _validate_language(payload.language)
        if payload.is_primary is not None:
            if payload.is_primary:
                # Unset others for same scope/lang
                conds = [MediaAsset.kind == MediaAssetKind.TRAILER]
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

        if payload.label is not None:
            md = dict(getattr(m, "metadata_json", {}) or {})
            if payload.label:
                md["label"] = payload.label
            else:
                md.pop("label", None)
            updates["metadata_json"] = md

        if updates:
            await db.execute(update(MediaAsset).where(MediaAsset.id == trailer_id).values(**updates))
            await db.commit()

    await log_audit_event(db, user=current_user, action="TRAILER_PATCH", status="SUCCESS", request=request,
                          meta_data={"trailer_id": str(trailer_id), "fields": list(updates.keys()) if updates else []})
    m = (await db.execute(select(MediaAsset).where(MediaAsset.id == trailer_id))).scalar_one_or_none()
    return {
        "id": str(getattr(m, "id", trailer_id)),
        "language": getattr(m, "language", None),
        "is_primary": bool(getattr(m, "is_primary", False)),
        "label": (getattr(m, "metadata_json", {}) or {}).get("label"),
    }


@router.post("/titles/{title_id}/trailers/{trailer_id}/make-primary", summary="Make this trailer primary")
@rate_limit("10/minute")
async def make_primary_trailer(
    title_id: UUID,
    trailer_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)

    async with redis_wrapper.lock(f"lock:admin:trailer:primary:{title_id}:{trailer_id}", timeout=15, blocking_timeout=5):
        m = (await db.execute(select(MediaAsset).where(MediaAsset.id == trailer_id, MediaAsset.kind == MediaAssetKind.TRAILER).with_for_update())).scalar_one_or_none()
        if not m or m.title_id != title_id:
            raise HTTPException(status_code=404, detail="Trailer not found for this title")
        lang = m.language
        conds = [MediaAsset.title_id == title_id, MediaAsset.kind == MediaAssetKind.TRAILER]
        if lang is not None:
            conds += [func.coalesce(func.lower(MediaAsset.language), "") == str(lang).lower()]
        await db.execute(update(MediaAsset).where(and_(*conds)).values(is_primary=False))
        await db.execute(update(MediaAsset).where(MediaAsset.id == trailer_id).values(is_primary=True))
        await db.commit()

    await log_audit_event(db, user=current_user, action="TRAILER_MAKE_PRIMARY", status="SUCCESS", request=request,
                          meta_data={"title_id": str(title_id), "trailer_id": str(trailer_id)})
    return {"message": "Primary set"}


@router.delete("/artwork/{artwork_id}", summary="Delete artwork + storage")
@rate_limit("10/minute")
async def delete_artwork(
    artwork_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Hard-delete an artwork row and best-effort delete the backing S3 object.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request)
    a = (await db.execute(select(Artwork).where(Artwork.id == artwork_id))).scalar_one_or_none()
    if not a:
        raise HTTPException(status_code=404, detail="Artwork not found")
    key = getattr(a, "storage_key", None)
    await db.execute(delete(Artwork).where(Artwork.id == artwork_id)); await db.commit()
    if key:
        try:
            _ensure_s3().delete(key)
        except HTTPException:
            pass
    await log_audit_event(db, user=current_user, action="ARTWORK_DELETE", status="SUCCESS", request=request, meta_data={"artwork_id": str(artwork_id)})
    return {"message": "Artwork deleted"}


# ─────────────────────────────────────────────────────────────────────────────
# 🎬 Trailers
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/titles/{title_id}/trailers", summary="Create trailer (presigned PUT)")
@rate_limit("10/minute")
async def create_trailer(
    title_id: UUID,
    payload: TrailerCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Provision a **trailer** media asset and return a presigned **PUT** URL.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)
    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")
    _ensure_allowed_mime(payload.content_type, ALLOWED_VIDEO_MIME, "video")
    lang = _validate_language(payload.language)

    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:trailers:create:{title_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    s3 = _ensure_s3()
    ext = _ext_for_content_type(payload.content_type)
    key = f"video/title/{title_id}/trailer_{uuid4().hex}.{ext}"
    url = s3.presigned_put(key, content_type=payload.content_type, public=False)

    asset = MediaAsset(
        title_id=title_id,
        kind=MediaAssetKind.TRAILER,
        language=lang,
        storage_key=key,
        is_primary=bool(payload.is_primary),
    )
    db.add(asset); await db.flush(); await db.commit()

    body = {"upload_url": url, "storage_key": key, "asset_id": str(asset.id)}
    await log_audit_event(db, user=current_user, action="TRAILER_CREATE", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "asset_id": body["asset_id"]})
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    return body


@router.get("/titles/{title_id}/trailers", summary="List trailers")
@rate_limit("30/minute")
async def list_trailers(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    """List trailer assets for a title (most recent first)."""
    await _ensure_admin(current_user); await _ensure_mfa(request)
    stmt = (
        select(MediaAsset)
        .where(MediaAsset.title_id == title_id, MediaAsset.kind == MediaAssetKind.TRAILER)
        .order_by(MediaAsset.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all() or []
    return [{
        "id": str(a.id),
        "language": getattr(a, "language", None),
        "storage_key": getattr(a, "storage_key", None),
        "is_primary": bool(getattr(a, "is_primary", False)),
        "created_at": getattr(a, "created_at", None),
    } for a in rows]


@router.delete("/trailers/{trailer_id}", summary="Delete trailer asset")
@rate_limit("10/minute")
async def delete_trailer(
    trailer_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Hard-delete a trailer media asset and best-effort delete the S3 object."""
    await _ensure_admin(current_user); await _ensure_mfa(request)
    a = (await db.execute(select(MediaAsset).where(MediaAsset.id == trailer_id, MediaAsset.kind == MediaAssetKind.TRAILER))).scalar_one_or_none()
    if not a:
        raise HTTPException(status_code=404, detail="Trailer not found")
    key = getattr(a, "storage_key", None)
    await db.execute(delete(MediaAsset).where(MediaAsset.id == trailer_id)); await db.commit()
    if key:
        try:
            _ensure_s3().delete(key)
        except HTTPException:
            pass
    await log_audit_event(db, user=current_user, action="TRAILER_DELETE", status="SUCCESS", request=request, meta_data={"asset_id": str(trailer_id)})
    return {"message": "Trailer deleted"}


# ─────────────────────────────────────────────────────────────────────────────
# 💬 Subtitles
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/titles/{title_id}/subtitles", summary="Create subtitle (presigned PUT + rows)")
@rate_limit("10/minute")
async def create_subtitle(
    title_id: UUID,
    payload: SubtitleCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Provision a **subtitle** asset + track and return a presigned **PUT** URL.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)

    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")
    _ensure_allowed_mime(payload.content_type, ALLOWED_SUBS_MIME, "subtitle")
    lang = _validate_language(payload.language)

    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:subtitle:create:{title_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    s3 = _ensure_s3()
    ext = _ext_for_content_type(payload.content_type)
    key = f"subs/title/{title_id}/{lang.lower()}_{uuid4().hex}.{ext}"
    url = s3.presigned_put(key, content_type=payload.content_type, public=False)

    asset = MediaAsset(
        title_id=title_id,
        kind=MediaAssetKind.SUBTITLE,
        language=lang,
        storage_key=key,
        uploaded_by_id=getattr(current_user, "id", None),
    )
    db.add(asset); await db.flush()

    track = Subtitle(
        title_id=title_id,
        asset_id=asset.id,
        language=lang,
        format=payload.format,
        label=payload.label,
        is_default=bool(payload.is_default),
        is_forced=bool(payload.is_forced),
        is_sdh=bool(payload.is_sdh),
        created_by_id=getattr(current_user, "id", None),
    )
    db.add(track); await db.flush(); await db.commit()

    body = {"upload_url": url, "storage_key": key, "subtitle_id": str(track.id), "asset_id": str(asset.id)}
    await log_audit_event(db, user=current_user, action="SUBTITLE_CREATE", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "subtitle_id": body["subtitle_id"]})
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    return body


@router.get("/titles/{title_id}/subtitles", summary="List subtitles")
@rate_limit("30/minute")
async def list_subtitles(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    """List subtitle tracks for a title with pagination."""
    await _ensure_admin(current_user); await _ensure_mfa(request)
    rows = (await db.execute(
        select(Subtitle).where(Subtitle.title_id == title_id).order_by(Subtitle.created_at.desc()).offset(offset).limit(limit)
    )).scalars().all() or []
    return [{
        "id": str(s.id),
        "asset_id": str(s.asset_id),
        "language": s.language,
        "format": str(getattr(s, "format", None)),
        "label": s.label,
        "is_default": bool(s.is_default),
        "is_forced": bool(s.is_forced),
        "is_sdh": bool(s.is_sdh),
        "created_at": getattr(s, "created_at", None),
    } for s in rows]


@router.patch("/subtitles/{subtitle_id}", summary="Patch subtitle flags/label")
@rate_limit("10/minute")
async def patch_subtitle(
    subtitle_id: UUID,
    payload: SubtitlePatchIn,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """
    Update a subtitle's flags/label. Enforces a short Redis lock + row lock.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request)
    async with redis_wrapper.lock(f"lock:admin_subtitles:patch:{subtitle_id}", timeout=10, blocking_timeout=3):
        s = (await db.execute(select(Subtitle).where(Subtitle.id == subtitle_id).with_for_update())).scalar_one_or_none()
        if not s:
            raise HTTPException(status_code=404, detail="Subtitle not found")
        updates = payload.model_dump(exclude_unset=True)
        if not updates:
            raise HTTPException(status_code=400, detail="No changes provided")
        for k, v in updates.items():
            if k == "language" and v is not None:
                v = _validate_language(v)
            setattr(s, k, v)
        await db.flush(); await db.commit()
        await log_audit_event(db, user=current_user, action="SUBTITLE_PATCH", status="SUCCESS", request=request, meta_data={"subtitle_id": str(subtitle_id), "fields": list(updates.keys())})
        return {"message": "Updated"}


@router.delete("/subtitles/{subtitle_id}", summary="Delete subtitle + asset")
@rate_limit("10/minute")
async def delete_subtitle(
    subtitle_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Hard-delete a subtitle row and its media asset; delete S3 object best-effort."""
    await _ensure_admin(current_user); await _ensure_mfa(request)
    s = (await db.execute(select(Subtitle).where(Subtitle.id == subtitle_id))).scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Subtitle not found")
    asset_id = getattr(s, "asset_id", None)
    key: Optional[str] = None
    if asset_id:
        a = (await db.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one_or_none()
        key = getattr(a, "storage_key", None)
        await db.execute(delete(MediaAsset).where(MediaAsset.id == asset_id))
    await db.execute(delete(Subtitle).where(Subtitle.id == subtitle_id)); await db.commit()
    if key:
        try:
            _ensure_s3().delete(key)
        except HTTPException:
            pass
    await log_audit_event(db, user=current_user, action="SUBTITLE_DELETE", status="SUCCESS", request=request, meta_data={"subtitle_id": str(subtitle_id)})
    return {"message": "Subtitle deleted"}


# ─────────────────────────────────────────────────────────────────────────────
# 📡 Streams (HLS/MP4)
# ─────────────────────────────────────────────────────────────────────────────

def _tier_for_quality(q: str) -> StreamTier:
    return {"1080p": StreamTier.P1080, "720p": StreamTier.P720, "480p": StreamTier.P480}[q]


def _height_for_quality(q: str) -> int:
    return {"1080p": 1080, "720p": 720, "480p": 480}[q]


def _serialize_stream(v: StreamVariant) -> Dict[str, object]:
    return {
        "id": str(v.id),
        "media_asset_id": str(v.media_asset_id),
        "url_path": v.url_path,
        "protocol": str(getattr(v, "protocol", None)),
        "container": str(getattr(v, "container", None)),
        "height": getattr(v, "height", None),
        "bandwidth_bps": getattr(v, "bandwidth_bps", None),
        "avg_bandwidth_bps": getattr(v, "avg_bandwidth_bps", None),
        "stream_tier": str(getattr(v, "stream_tier", None)),
        "is_streamable": bool(getattr(v, "is_streamable", False)),
        "is_downloadable": bool(getattr(v, "is_downloadable", False)),
        "is_default": bool(getattr(v, "is_default", False)),
        "audio_language": getattr(v, "audio_language", None),
        "label": getattr(v, "label", None),
    }


@router.post("/titles/{title_id}/streams", summary="Create stream variant for title (HLS/MP4)")
@rate_limit("10/minute")
async def create_stream(
    title_id: UUID,
    payload: StreamCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """
    Create a stream variant bound to a (new or provided) media asset.
    - HLS → streamable (not downloadable), requires `stream_tier`
    - MP4 → downloadable (not streamable)
    """
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)

    # [Step 1] Title check
    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")

    # [Step 2] Idempotency replay
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:streams:create:{title_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    # [Step 3] Resolve or create asset holder
    asset_id = payload.asset_id
    if asset_id is None:
        asset = MediaAsset(
            title_id=title_id,
            kind=MediaAssetKind.VIDEO,
            language=_validate_language(payload.audio_language),
            storage_key=f"streams/title/{title_id}/holder_{uuid4().hex}.meta",
        )
        db.add(asset); await db.flush()
        asset_id = asset.id

    # [Step 4] Map quality -> tier/height; derive flags from protocol
    height = _height_for_quality(payload.quality)
    tier = _tier_for_quality(payload.quality)
    if payload.type == "hls":
        protocol = StreamProtocol.HLS; container = Container.FMP4
        is_streamable, is_downloadable = True, False
    else:
        protocol = StreamProtocol.MP4; container = Container.MP4
        is_streamable, is_downloadable = False, True

    # [Step 5] Persist variant
    v = StreamVariant(
        media_asset_id=asset_id,
        url_path=payload.url_path,
        protocol=protocol,
        container=container,
        bandwidth_bps=payload.bandwidth_bps,
        avg_bandwidth_bps=payload.avg_bandwidth_bps,
        width=None,
        height=height,
        is_streamable=is_streamable,
        is_downloadable=is_downloadable,
        stream_tier=tier if is_streamable else None,
        is_default=bool(payload.is_default),
        audio_language=_validate_language(payload.audio_language),
        label=payload.label,
    )
    db.add(v); await db.flush(); await db.commit()

    # [Step 6] Log + idempotent snapshot
    body = _serialize_stream(v)
    await log_audit_event(db, user=current_user, action="STREAM_CREATE", status="SUCCESS", request=request, meta_data={"stream_id": body["id"], "title_id": str(title_id)})
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    return body


@router.get("/titles/{title_id}/streams", summary="List stream variants for title")
@rate_limit("30/minute")
async def list_streams(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    """List all stream variants attached to the given title."""
    await _ensure_admin(current_user); await _ensure_mfa(request)
    stmt = (
        select(StreamVariant)
        .join(MediaAsset, StreamVariant.media_asset_id == MediaAsset.id)
        .where(MediaAsset.title_id == title_id)
        .order_by(StreamVariant.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all() or []
    return [_serialize_stream(v) for v in rows]


@router.patch("/streams/{stream_id}", summary="Update stream flags / tier")
@rate_limit("10/minute")
async def patch_stream(
    stream_id: UUID,
    payload: StreamPatchIn,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """
    Patch streamability flags and/or stream tier.
    Policy: only HLS may be streamable; setting `is_streamable=true` requires a tier.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request)
    async with redis_wrapper.lock(f"lock:admin_streams:patch:{stream_id}", timeout=10, blocking_timeout=3):
        v = (await db.execute(select(StreamVariant).where(StreamVariant.id == stream_id).with_for_update())).scalar_one_or_none()
        if not v:
            raise HTTPException(status_code=404, detail="Stream not found")
        updates = payload.model_dump(exclude_unset=True)
        if not updates:
            raise HTTPException(status_code=400, detail="No changes provided")
        if updates.get("is_streamable"):
            if getattr(v, "protocol", None) != StreamProtocol.HLS:
                raise HTTPException(status_code=400, detail="Only HLS variants can be streamable")
            if not updates.get("stream_tier") and not getattr(v, "stream_tier", None):
                raise HTTPException(status_code=400, detail="stream_tier required when setting streamable")
        for k, val in updates.items():
            setattr(v, k, val)
        await db.flush(); await db.commit()
        await log_audit_event(db, user=current_user, action="STREAM_PATCH", status="SUCCESS", request=request, meta_data={"stream_id": str(stream_id), "fields": list(updates.keys())})
        return _serialize_stream(v)


@router.delete("/streams/{stream_id}", summary="Delete stream variant")
@rate_limit("10/minute")
async def delete_stream(
    stream_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Hard-delete a stream variant row."""
    await _ensure_admin(current_user); await _ensure_mfa(request)
    await db.execute(delete(StreamVariant).where(StreamVariant.id == stream_id)); await db.commit()
    await log_audit_event(db, user=current_user, action="STREAM_DELETE", status="SUCCESS", request=request, meta_data={"stream_id": str(stream_id)})
    return {"message": "Stream deleted"}


# ─────────────────────────────────────────────────────────────────────────────
# ☁️ Generic Uploads (single & multipart)
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/uploads/init", summary="Init single upload (presigned PUT)")
@rate_limit("20/minute")
async def uploads_init(
    payload: UploadInitIn,
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Create a presigned **single-part** PUT URL for arbitrary content.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)

    s3 = _ensure_s3()
    ext = _ext_for_content_type(payload.content_type)
    prefix = _safe_prefix(payload.key_prefix, "uploads")
    name = _sanitize_segment(payload.filename_hint, f"upload_{uuid4().hex}")
    key = f"{prefix}/{name}.{ext}"

    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:uploads:init:{key}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    url = s3.presigned_put(key, content_type=payload.content_type, public=False)
    body = {"upload_url": url, "storage_key": key}
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    return body


@router.post("/uploads/multipart/create", summary="Create multipart upload (returns uploadId)")
@rate_limit("20/minute")
async def multipart_create(
    payload: MultipartCreateIn,
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Initialize a **multipart** upload for large files and return an `uploadId`.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)

    s3 = _ensure_s3()
    ext = _ext_for_content_type(payload.content_type)
    prefix = _safe_prefix(payload.key_prefix, "uploads/multipart")
    name = _sanitize_segment(payload.filename_hint, f"mup_{uuid4().hex}")
    key = f"{prefix}/{name}.{ext}"

    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:uploads:multipart:create:{key}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    try:
        upload = s3.client.create_multipart_upload(
            Bucket=s3.bucket,
            Key=key,
            ContentType=payload.content_type,
            ACL="private",
        )
        upload_id = upload["UploadId"]
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Multipart init failed: {e}")

    body = {"uploadId": upload_id, "storage_key": key}
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=3600)
        except Exception:
            pass
    return body


@router.get("/uploads/multipart/{uploadId}/part-url", summary="Presigned URL for a multipart part")
@rate_limit("60/minute")
async def multipart_part_url(
    uploadId: str,
    key: str,
    partNumber: int = Query(..., ge=1, le=10_000),
    request: Request = None,
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Return a presigned **PUT** URL for a specific multipart `partNumber`.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request)
    s3 = _ensure_s3()
    try:
        url = s3.client.generate_presigned_url(
            ClientMethod="upload_part",
            Params={
                "Bucket": s3.bucket,
                "Key": key,
                "UploadId": uploadId,
                "PartNumber": int(partNumber),
            },
            ExpiresIn=3600,
            HttpMethod="PUT",
        )
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Part URL failed: {e}")
    return {"upload_url": url}


@router.post("/uploads/multipart/{uploadId}/complete", summary="Complete multipart upload")
@rate_limit("20/minute")
async def multipart_complete(
    uploadId: str,
    payload: MultipartCompleteIn,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Complete a multipart upload by supplying `{ETag, PartNumber}` for each part.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request)
    s3 = _ensure_s3()
    try:
        s3.client.complete_multipart_upload(
            Bucket=s3.bucket,
            Key=payload.key,
            UploadId=uploadId,
            MultipartUpload={"Parts": [{"ETag": p["ETag"], "PartNumber": int(p["PartNumber"])} for p in payload.parts]},
        )
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Complete failed: {e}")
    return {"message": "Upload complete", "storage_key": payload.key}


@router.post("/uploads/multipart/{uploadId}/abort", summary="Abort multipart upload")
@rate_limit("20/minute")
async def multipart_abort(
    uploadId: str,
    payload: MultipartAbortIn,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Abort a multipart upload."""
    await _ensure_admin(current_user); await _ensure_mfa(request)
    s3 = _ensure_s3()
    try:
        s3.client.abort_multipart_upload(Bucket=s3.bucket, Key=payload.key, UploadId=uploadId)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Abort failed: {e}")
    return {"message": "Upload aborted"}


@router.post("/uploads/direct-proxy", summary="Direct proxy upload (small files)")
@rate_limit("20/minute")
async def direct_proxy_upload(
    payload: DirectProxyIn,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Directly proxy small files (≤ 10 MiB) into S3 by base64 payload.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request)
    data = base64.b64decode(payload.data_base64, validate=True)
    if len(data) > MAX_DIRECT_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large")
    s3 = _ensure_s3()
    ext = _ext_for_content_type(payload.content_type)
    prefix = _safe_prefix(payload.key_prefix, "uploads/direct")
    name = _sanitize_segment(payload.filename_hint, f"direct_{uuid4().hex}")
    key = f"{prefix}/{name}.{ext}"
    try:
        s3.put_bytes(key, data, content_type=payload.content_type, public=False)
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return {"storage_key": key}


# ─────────────────────────────────────────────────────────────────────────────
# 📥 Bulk ingestion jobs (Redis-backed scaffold)
# ─────────────────────────────────────────────────────────────────────────────

class BulkManifestIn(BaseModel):
    manifest_url: Optional[str] = None
    items: Optional[List[Dict[str, object]]] = None


@router.post("/bulk/manifest", status_code=202, summary="Submit bulk manifest (JSON/CSV)")
@rate_limit("10/minute")
async def bulk_manifest(
    payload: BulkManifestIn,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Submit a bulk manifest by URL or inline items; returns a queued job id.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request)
    job_id = uuid4().hex
    job_key = f"bulk:job:{job_id}"
    try:
        await redis_wrapper.json_set(job_key, {
            "id": job_id,
            "status": "QUEUED",
            "submitted_at": getattr(request, "state", object()).__dict__.get("request_start_time", None),
            "submitted_by": str(getattr(current_user, "id", "")),
            "manifest_url": payload.manifest_url,
            "items_count": len(payload.items) if payload.items else None,
        }, ttl_seconds=24 * 3600)
        await redis_wrapper.client.sadd("bulk:jobs", job_id)  # type: ignore
    except Exception:
        raise HTTPException(status_code=503, detail="Could not enqueue job")
    return {"job_id": job_id, "status": "QUEUED"}


@router.get("/bulk/jobs", summary="List bulk jobs (recent)")
@rate_limit("30/minute")
async def bulk_jobs(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, object]]:
    """List recent bulk jobs recorded in Redis."""
    await _ensure_admin(current_user); await _ensure_mfa(request)
    out: List[Dict[str, object]] = []
    try:
        ids = await redis_wrapper.client.smembers("bulk:jobs")  # type: ignore
        for jid in ids or []:
            try:
                data = await redis_wrapper.json_get(f"bulk:job:{jid}")
                if data:
                    out.append(data)  # type: ignore[arg-type]
            except Exception:
                continue
    except Exception:
        out = []
    return out


@router.get("/bulk/jobs/{job_id}", summary="Get bulk job status")
@rate_limit("60/minute")
async def bulk_job_get(
    job_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """Get a specific bulk job's status payload."""
    await _ensure_admin(current_user); await _ensure_mfa(request)
    data = await redis_wrapper.json_get(f"bulk:job:{job_id}")
    if not data:
        raise HTTPException(status_code=404, detail="Job not found")
    return data  # type: ignore[return-value]


@router.post("/bulk/jobs/{job_id}/cancel", summary="Request cancel for a bulk job")
@rate_limit("10/minute")
async def bulk_job_cancel(
    job_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Request cancellation for a queued/running bulk job (best-effort)."""
    await _ensure_admin(current_user); await _ensure_mfa(request)
    key = f"bulk:job:{job_id}"
    data = await redis_wrapper.json_get(key) or {}
    if not data:
        raise HTTPException(status_code=404, detail="Job not found")
    data["status"] = "CANCEL_REQUESTED"
    try:
        await redis_wrapper.json_set(key, data, ttl_seconds=24 * 3600)
    except Exception:
        raise HTTPException(status_code=503, detail="Could not update job")
    return {"status": "CANCEL_REQUESTED"}


# ----------------------------------------------------------------------------------
# Bulk job QoL: inspect items/errors, retry failed, purge job records
# ----------------------------------------------------------------------------------


@router.get("/bulk/jobs/{job_id}/items", summary="Inspect bulk job items and errors")
@rate_limit("60/minute")
async def bulk_job_items(
    job_id: str,
    request: Request,
    status_filter: Literal["all", "failed", "succeeded", "pending", "error"] = Query(
        "all", alias="status", description="Filter items by status"
    ),
    only_errors: bool = Query(False, description="Return only error entries if available"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=1000, description="Pagination limit"),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """Return a slice of recorded items and errors for a bulk job.

    Data Model (Redis)
    ------------------
    - Job envelope: `bulk:job:{job_id}` (JSON)
    - Items array:  `bulk:job:{job_id}:items` (JSON list; optional)
    - Errors array: `bulk:job:{job_id}:errors` (JSON list; optional)

    Notes
    -----
    - If a worker does not populate items/errors, this returns empty arrays.
    - Supports simple pagination and status filtering on the in-memory list.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request)

    job_key = f"bulk:job:{job_id}"
    job = await redis_wrapper.json_get(job_key)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    items_key = f"bulk:job:{job_id}:items"
    errs_key = f"bulk:job:{job_id}:errors"
    items = await redis_wrapper.json_get(items_key, default=[]) or []
    errors = await redis_wrapper.json_get(errs_key, default=[]) or []

    # Defensive normalization: ensure lists of dicts
    try:
        items = [i for i in items if isinstance(i, dict)]
    except Exception:
        items = []
    try:
        errors = [e for e in errors if isinstance(e, dict)]
    except Exception:
        errors = []

    # Optional filter by status
    sf = str(status_filter or "all").lower()
    if sf != "all":
        def _match(it: Dict[str, object]) -> bool:
            st = str(it.get("status", "")).lower()
            if sf == "failed":
                return st in {"failed", "error"}
            if sf == "succeeded":
                return st in {"success", "succeeded", "done"}
            if sf == "pending":
                return st in {"queued", "pending", "running"}
            if sf == "error":
                return st == "error"
            return True
        items = [it for it in items if _match(it)]

    total = len(items)
    start = int(offset)
    end = min(start + int(limit), total)
    page = items[start:end]

    return {
        "job": {"id": job.get("id"), "status": job.get("status")},
        "items": page,
        "items_total": total,
        "next_offset": end if end < total else None,
        "errors": errors if only_errors else None,
        "errors_total": len(errors) if errors else 0,
    }


class BulkRetryIn(BaseModel):
    """Retry request payload for a bulk job.

    - `only_failed`: when true, only items with status FAILED/ERROR are re-queued.
    - `include_pending`: include PENDING/QUEUED items in retry set.
    """
    only_failed: bool = True
    include_pending: bool = False


@router.post("/bulk/jobs/{job_id}/retry", status_code=202, summary="Re-queue a failed/partial bulk job")
@rate_limit("10/minute")
async def bulk_job_retry(
    job_id: str,
    payload: BulkRetryIn,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """Create a new queued job from failed/pending items of an existing job.

    Behavior
    --------
    - Reads `bulk:job:{job_id}` and its `:items` list, if present.
    - Filters items according to `only_failed` and `include_pending`.
    - Creates a new job id and enqueues it with copied items.
    - Marks source job with `retries` count and `last_retry_job_id`.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request)

    src_job_key = f"bulk:job:{job_id}"
    src_job = await redis_wrapper.json_get(src_job_key)
    if not src_job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Load items to retry (may be empty if not recorded by worker)
    items_key = f"bulk:job:{job_id}:items"
    items = await redis_wrapper.json_get(items_key, default=[]) or []
    if not isinstance(items, list):
        items = []

    def _is_failed(it: Dict[str, object]) -> bool:
        st = str(it.get("status", "")).lower()
        return st in {"failed", "error"}

    def _is_pending(it: Dict[str, object]) -> bool:
        st = str(it.get("status", "")).lower()
        return st in {"queued", "pending", "running"}

    retry_pool: List[Dict[str, object]] = []
    for it in (items if isinstance(items, list) else []):
        if not isinstance(it, dict):
            continue
        if payload.only_failed and not _is_failed(it):
            if payload.include_pending and _is_pending(it):
                retry_pool.append(it)
            continue
        else:
            # If only_failed=False -> include all items, or include_failed path
            if payload.only_failed:
                retry_pool.append(it) if _is_failed(it) else None
            else:
                retry_pool.append(it)

    # If we have no recorded items, still allow a blind retry by cloning manifest_url
    if not retry_pool and not items:
        retry_pool = []  # empty -> worker can interpret manifest_url

    new_job_id = uuid4().hex
    new_job_key = f"bulk:job:{new_job_id}"
    ttl = 24 * 3600
    try:
        await redis_wrapper.json_set(new_job_key, {
            "id": new_job_id,
            "status": "QUEUED",
            "submitted_at": getattr(request, "state", object()).__dict__.get("request_start_time", None),
            "submitted_by": str(getattr(current_user, "id", "")),
            "manifest_url": src_job.get("manifest_url"),
            "items_count": len(retry_pool) if retry_pool else src_job.get("items_count"),
            "retry_of": job_id,
        }, ttl_seconds=ttl)
        await redis_wrapper.client.sadd("bulk:jobs", new_job_id)  # type: ignore

        # Copy selected items into the new job's items list
        if retry_pool:
            await redis_wrapper.json_set(f"bulk:job:{new_job_id}:items", retry_pool, ttl_seconds=ttl)

        # Update source job with retry bookkeeping
        src_job["retries"] = int(src_job.get("retries", 0) or 0) + 1
        src_job["last_retry_job_id"] = new_job_id
        src_job["status"] = src_job.get("status") or "RETRY_QUEUED"
        await redis_wrapper.json_set(src_job_key, src_job, ttl_seconds=ttl)
    except Exception:
        raise HTTPException(status_code=503, detail="Could not enqueue retry job")

    try:
        await log_audit_event(
            db=db,
            user=current_user,
            action="BULK_JOB_RETRY",
            status="QUEUED",
            request=request,
            meta_data={
                "source_job_id": job_id,
                "new_job_id": new_job_id,
                "requeued_items": len(retry_pool),
                "only_failed": payload.only_failed,
                "include_pending": payload.include_pending,
            },
        )
    except Exception:
        pass

    return {"job_id": new_job_id, "status": "QUEUED", "requeued_items": len(retry_pool)}


@router.delete("/bulk/jobs/{job_id}", status_code=200, summary="Purge a bulk job record")
@rate_limit("10/minute")
async def bulk_job_purge(
    job_id: str,
    request: Request,
    force: bool = Query(False, description="Force purge regardless of status"),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Delete a bulk job envelope and its associated items/errors from Redis.

    Safety
    ------
    - By default only purges jobs in a terminal state: COMPLETED/FAILED/CANCELLED/ABORTED.
    - Set `force=true` to override (not recommended during active processing).
    """
    await _ensure_admin(current_user); await _ensure_mfa(request)

    key = f"bulk:job:{job_id}"
    job = await redis_wrapper.json_get(key)
    if not job:
        # Remove from index set if present anyway
        try:
            await redis_wrapper.client.srem("bulk:jobs", job_id)  # type: ignore
        except Exception:
            pass
        raise HTTPException(status_code=404, detail="Job not found")

    status_str = str(job.get("status", "")).upper()
    terminal = {"COMPLETED", "FAILED", "CANCELLED", "ABORTED"}
    if not force and status_str not in terminal:
        raise HTTPException(status_code=409, detail="Job not in terminal state; set force=true to purge")

    try:
        await redis_wrapper.client.delete(key)  # type: ignore
        await redis_wrapper.client.delete(f"bulk:job:{job_id}:items")  # type: ignore
        await redis_wrapper.client.delete(f"bulk:job:{job_id}:errors")  # type: ignore
        await redis_wrapper.client.srem("bulk:jobs", job_id)  # type: ignore
    except Exception:
        raise HTTPException(status_code=503, detail="Could not purge job")
    try:
        await log_audit_event(
            db=db,
            user=current_user,
            action="BULK_JOB_PURGE",
            status="SUCCESS",
            request=request,
            meta_data={"job_id": job_id, "forced": force},
        )
    except Exception:
        pass

    return {"status": "PURGED", "job_id": job_id}

# ─────────────────────────────────────────────────────────────────────────────
# 🚀 CDN & Delivery
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/cdn/invalidate", summary="Invalidate CDN paths/prefixes")
@rate_limit("6/minute")
async def cdn_invalidate(
    payload: CDNInvalidateIn,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """
    Invalidate CDN cache paths or prefix patterns.
    - If CloudFront is configured, submit an invalidation.
    - Otherwise, queue paths to Redis for an async worker.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request)

    paths = list({p.strip() for p in (payload.paths or []) if p and p.strip()})
    for pre in payload.prefixes or []:
        pre = pre.strip()
        if pre:
            if not pre.endswith("*"):
                pre = pre + "*"
            if not pre.startswith("/"):
                pre = "/" + pre
            paths.append(pre)
    if not paths:
        raise HTTPException(status_code=400, detail="Provide at least one path or prefix")

    dist_id = payload.distribution_id or getattr(settings, "CLOUDFRONT_DISTRIBUTION_ID", None)
    request_id = uuid4().hex
    caller_ref = f"inv-{request_id}"

    if dist_id:
        try:
            cf = boto3.client(
                "cloudfront",
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY.get_secret_value(),
                region_name=settings.AWS_REGION,
            )
            resp = cf.create_invalidation(
                DistributionId=dist_id,
                InvalidationBatch={"Paths": {"Quantity": len(paths), "Items": paths}, "CallerReference": caller_ref},
            )
            inv_id = None
            try:
                inv_id = (resp or {}).get("Invalidation", {}).get("Id")  # type: ignore[assignment]
            except Exception:
                inv_id = None

            # Persist status for later polling
            state = {
                "request_id": request_id,
                "provider": "cloudfront",
                "distribution_id": dist_id,
                "invalidation_id": inv_id,
                "paths": paths,
                "status": "SUBMITTED",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "caller_reference": caller_ref,
            }
            try:
                await redis_wrapper.json_set(f"cdn:inv:{request_id}", state, ttl_seconds=24 * 3600)
            except Exception:
                pass
            await log_audit_event(
                db=db,
                user=current_user,
                action="CDN_INVALIDATE",
                status="SUBMITTED",
                request=request,
                meta_data={"distribution": dist_id, "paths": paths[:10], "count": len(paths), "request_id": request_id, "invalidation_id": inv_id},
            )
            return {"status": "SUBMITTED", "distribution_id": dist_id, "paths": paths, "request_id": request_id, "invalidation_id": inv_id}
        except Exception:
            # Fall through to queue
            pass

    try:
        await redis_wrapper.client.rpush("cdn:invalidate:queue", *paths)  # type: ignore
        # Persist queued request for status polling
        state = {
            "request_id": request_id,
            "provider": "queue",
            "paths": paths,
            "status": "QUEUED",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            await redis_wrapper.json_set(f"cdn:inv:{request_id}", state, ttl_seconds=24 * 3600)
        except Exception:
            pass
        await log_audit_event(
            db=db,
            user=current_user,
            action="CDN_INVALIDATE",
            status="QUEUED",
            request=request,
            meta_data={"paths": paths[:10], "count": len(paths), "request_id": request_id},
        )
        return {"status": "QUEUED", "paths": paths, "request_id": request_id}
    except Exception:
        raise HTTPException(status_code=503, detail="Could not queue invalidation")


@router.post("/delivery/signed-url", summary="Short-lived preview (signed URL)")
@rate_limit("60/minute")
async def delivery_signed_url(
    payload: SignedUrlIn,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Return a short-lived presigned GET URL (optionally as attachment)."""
    await _ensure_admin(current_user); await _ensure_mfa(request)
    s3 = _ensure_s3()
    disp = f'attachment; filename="{payload.attachment_filename}"' if payload.attachment_filename else None
    try:
        url = s3.presigned_get(payload.storage_key, expires_in=payload.expires_in, response_content_disposition=disp)
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return {"url": url}


@router.post("/delivery/download-token", summary="One-time download token for premium assets")
@rate_limit("30/minute")
async def delivery_download_token(
    payload: DownloadTokenIn,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """
    Issue a one-time, short-lived download token (stored in Redis).
    """
    await _ensure_admin(current_user); await _ensure_mfa(request)
    token = uuid4().hex
    key = f"download:token:{token}"
    exp_at = datetime.now(timezone.utc) + timedelta(seconds=payload.ttl_seconds)
    data = {
        "storage_key": payload.storage_key,
        "one_time": True,
        "issued_by": str(getattr(current_user, "id", "")),
        "expires_at": exp_at.isoformat(),
    }
    try:
        await redis_wrapper.json_set(key, data, ttl_seconds=payload.ttl_seconds)
    except Exception:
        raise HTTPException(status_code=503, detail="Could not store token")
    return {"token": token, "expires_at": data["expires_at"]}


@router.get("/delivery/download/{token}", summary="Redeem one-time download token")
@rate_limit("60/minute")
async def delivery_download_redeem(
    token: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    redirect: bool = Query(True, description="If true, 307 redirect to signed URL; else return JSON"),
    filename: Optional[str] = Query(None, description="Optional attachment filename for Content-Disposition"),
    expires_in: int = Query(300, ge=60, le=3600, description="Signed URL TTL in seconds"),
) -> Dict[str, str] | RedirectResponse:
    """Redeem a one-time token and return/redirect to a signed URL.

    Semantics
    ---------
    - Tokens are stored at `download:token:{token}` with TTL and one_time flag.
    - Redemption acquires a short lock and deletes the token to prevent reuse.
    - This endpoint does not require authentication; the token itself authorizes access.
    """
    set_sensitive_cache(response)
    # Serialize redemption via a distributed lock to ensure one-time usage
    async with redis_wrapper.lock(f"lock:download:token:{token}", timeout=5, blocking_timeout=2):
        key = f"download:token:{token}"
        data = await redis_wrapper.json_get(key)
        if not data:
            raise HTTPException(status_code=404, detail="Token not found or expired")
        # One-time semantics: best-effort delete
        try:
            await redis_wrapper.client.delete(key)  # type: ignore
        except Exception:
            pass

    storage_key = data.get("storage_key") if isinstance(data, dict) else None
    if not storage_key:
        raise HTTPException(status_code=400, detail="Token missing storage_key")
 
    try:
        s3 = _ensure_s3()
        disp = f'attachment; filename="{filename}"' if filename else None
        url = s3.presigned_get(str(storage_key), expires_in=int(expires_in), response_content_disposition=disp)
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))

    # Return redirect or JSON, based on caller preference
    if redirect:
        headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
        try:
            await log_audit_event(
                db=db,
                user=None,
                action="DELIVERY_DOWNLOAD_REDEEM",
                status="SUCCESS",
                request=request,
                meta_data={"token": token, "redirect": True},
            )
        except Exception:
            pass
        return RedirectResponse(url=url, status_code=307, headers=headers)
    try:
        await log_audit_event(
            db=db,
            user=None,
            action="DELIVERY_DOWNLOAD_REDEEM",
            status="SUCCESS",
            request=request,
            meta_data={"token": token, "redirect": False},
        )
    except Exception:
        pass
    return {"url": url}


@router.get("/cdn/invalidation/{request_id}", summary="Fetch CDN invalidation status")
@rate_limit("60/minute")
async def cdn_invalidation_status(
    request_id: str,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """Return the status of a previously submitted CDN invalidation.

    Looks up state from Redis at `cdn:inv:{request_id}`. When CloudFront
    information is present, attempts to refresh status via `GetInvalidation`.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request)
    key = f"cdn:inv:{request_id}"
    state = await redis_wrapper.json_get(key)
    if not state:
        raise HTTPException(status_code=404, detail="Invalidation request not found")

    provider = state.get("provider") if isinstance(state, dict) else None
    if provider == "cloudfront":
        dist_id = state.get("distribution_id")
        inv_id = state.get("invalidation_id")
        if dist_id and inv_id:
            try:
                cf = boto3.client(
                    "cloudfront",
                    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY.get_secret_value(),
                    region_name=settings.AWS_REGION,
                )
                resp = cf.get_invalidation(DistributionId=dist_id, Id=inv_id)
                status = (resp or {}).get("Invalidation", {}).get("Status", state.get("status"))
                # Update cached state
                state.update({
                    "status": status,
                    "last_checked_at": datetime.now(timezone.utc).isoformat(),
                })
                try:
                    await redis_wrapper.json_set(key, state, ttl_seconds=24 * 3600)
                except Exception:
                    pass
            except Exception:
                # Ignore refresh failures; return cached state
                pass

    try:
        await log_audit_event(
            db=db,
            user=current_user,
            action="CDN_INVALIDATE_STATUS",
            status=str(state.get("status") if isinstance(state, dict) else "UNKNOWN"),
            request=request,
            meta_data={"request_id": request_id},
        )
    except Exception:
        pass

    return state  # type: ignore[return-value]


@router.post("/delivery/signed-manifest", summary="Sign a HLS/DASH manifest for preview")
@rate_limit("60/minute")
async def delivery_signed_manifest(
    payload: SignedManifestIn,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Return a short-lived signed URL for the manifest object.

    This does not rewrite segment URLs; use a private storage layout for
    previews where the manifest suffices.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request)
    s3 = _ensure_s3()
    # Decide content-type by format or extension
    fmt = (payload.format or "").lower()
    ctype = None
    key_lower = payload.storage_key.lower()
    if fmt == "hls" or key_lower.endswith(".m3u8"):
        ctype = "application/vnd.apple.mpegurl"
    elif fmt == "dash" or key_lower.endswith(".mpd"):
        ctype = "application/dash+xml"
    try:
        url = s3.presigned_get(payload.storage_key, expires_in=payload.expires_in, response_content_type=ctype)
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))
    try:
        await log_audit_event(
            db=db,
            user=current_user,
            action="DELIVERY_SIGNED_MANIFEST",
            status="SUCCESS",
            request=request,
            meta_data={"storage_key": payload.storage_key, "format": fmt or ("hls" if key_lower.endswith(".m3u8") else "dash" if key_lower.endswith(".mpd") else None)},
        )
    except Exception:
        pass
    return {"url": url, "content_type": ctype or "application/octet-stream"}


# ----------------------------------------------------------------------------
# Video assets (main features)
# ----------------------------------------------------------------------------

class VideoCreateIn(BaseModel):
    content_type: str = Field(..., description="e.g., video/mp4")
    language: Optional[str] = Field(None, description="BCP-47 tag")
    is_primary: bool = False
    label: Optional[str] = Field(None, description="UI label stored in metadata")


@router.post("/titles/{title_id}/video", summary="Create a video asset (presigned PUT)")
@rate_limit("6/minute")
async def create_video_asset(
    title_id: UUID,
    payload: VideoCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)

    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")
    _ensure_allowed_mime(payload.content_type, ALLOWED_VIDEO_MIME, "video")
    lang = _validate_language(payload.language)

    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:video:create:{title_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    s3 = _ensure_s3()
    ext = _ext_for_content_type(payload.content_type) or "mp4"
    key = f"video/title/{title_id}/main_{uuid4().hex}.{ext}"
    url = s3.presigned_put(key, content_type=payload.content_type, public=False)

    meta = {}
    if payload.label:
        meta["label"] = payload.label

    if payload.is_primary:
        conds = [MediaAsset.title_id == title_id, MediaAsset.kind == MediaAssetKind.VIDEO]
        if lang is not None:
            conds += [func.coalesce(func.lower(MediaAsset.language), "") == str(lang).lower()]
        await db.execute(update(MediaAsset).where(and_(*conds)).values(is_primary=False))

    m = MediaAsset(
        title_id=title_id,
        kind=MediaAssetKind.VIDEO,
        language=lang,
        storage_key=key,
        mime_type=payload.content_type,
        is_primary=bool(payload.is_primary),
        metadata_json=meta or None,
    )
    db.add(m); await db.flush(); await db.commit()

    body = {"upload_url": url, "storage_key": key, "asset_id": str(m.id)}
    await log_audit_event(db, user=current_user, action="VIDEO_CREATE", status="SUCCESS", request=request,
                          meta_data={"title_id": str(title_id), "asset_id": body["asset_id"]})
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    return body


class VideoPatchIn(BaseModel):
    language: Optional[str] = None
    is_primary: Optional[bool] = None
    label: Optional[str] = None
    sort_order: Optional[int] = Field(None, ge=0)
    cdn_url: Optional[str] = None


@router.patch("/video/{asset_id}", summary="Update video asset metadata")
@rate_limit("20/minute")
async def patch_video_asset(
    asset_id: UUID,
    payload: VideoPatchIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)

    async with redis_wrapper.lock(f"lock:admin:video:{asset_id}", timeout=10, blocking_timeout=3):
        m = (await db.execute(select(MediaAsset).where(MediaAsset.id == asset_id, MediaAsset.kind == MediaAssetKind.VIDEO).with_for_update())).scalar_one_or_none()
        if not m:
            raise HTTPException(status_code=404, detail="Video asset not found")
        updates: Dict[str, object] = {}
        if payload.language is not None:
            updates["language"] = _validate_language(payload.language)
        if payload.is_primary is not None:
            if payload.is_primary:
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
        if payload.label is not None:
            md = dict(getattr(m, "metadata_json", {}) or {})
            if payload.label:
                md["label"] = payload.label
            else:
                md.pop("label", None)
            updates["metadata_json"] = md
        if payload.sort_order is not None:
            updates["sort_order"] = int(payload.sort_order)
        if payload.cdn_url is not None:
            updates["cdn_url"] = (payload.cdn_url or None)
        if updates:
            await db.execute(update(MediaAsset).where(MediaAsset.id == asset_id).values(**updates))
            await db.commit()

    await log_audit_event(db, user=current_user, action="VIDEO_PATCH", status="SUCCESS", request=request,
                          meta_data={"asset_id": str(asset_id), "fields": list(updates.keys()) if updates else []})
    m = (await db.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one_or_none()
    return {
        "id": str(getattr(m, "id", asset_id)),
        "language": getattr(m, "language", None),
        "is_primary": bool(getattr(m, "is_primary", False)),
        "label": (getattr(m, "metadata_json", {}) or {}).get("label"),
        "sort_order": getattr(m, "sort_order", 0),
    }


@router.delete("/video/{asset_id}", summary="Delete a video asset")
@rate_limit("10/minute")
async def delete_video_asset(
    asset_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)

    m = (await db.execute(select(MediaAsset).where(MediaAsset.id == asset_id, MediaAsset.kind == MediaAssetKind.VIDEO))).scalar_one_or_none()
    if not m:
        raise HTTPException(status_code=404, detail="Video asset not found")
    key = getattr(m, "storage_key", None)

    async with redis_wrapper.lock(f"lock:admin:video:delete:{asset_id}", timeout=10, blocking_timeout=3):
        await db.execute(delete(MediaAsset).where(MediaAsset.id == asset_id))
        await db.commit()
    if key:
        try:
            s3 = _ensure_s3()
            s3.delete_object(key)
        except Exception:
            pass

    await log_audit_event(db, user=current_user, action="VIDEO_DELETE", status="SUCCESS", request=request,
                          meta_data={"asset_id": str(asset_id), "storage_key": key})
    return {"message": "Deleted"}


# ============================================================
# Assets: HEAD metadata and checksum
# ============================================================

class ChecksumIn(BaseModel):
    sha256: Optional[str] = Field(None, description="Client-provided SHA-256 hex (optional if server computes)")
    force: bool = Field(False, description="If true, overwrite existing checksum")


@router.get("/assets/{asset_id}/head", summary="Fetch S3 HEAD metadata and cache in DB")
@rate_limit("60/minute")
async def assets_head(
    asset_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)
    m = (await db.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one_or_none()
    if not m:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not m.storage_key:
        raise HTTPException(status_code=400, detail="Asset missing storage_key")

    s3 = _ensure_s3()
    try:
        head = s3.client.head_object(Bucket=s3.bucket, Key=m.storage_key)  # type: ignore[attr-defined]
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"HEAD failed: {e}")

    size = int(head.get("ContentLength", 0))
    ctype = head.get("ContentType")
    etag = (head.get("ETag") or "").strip('"')

    # Update DB cache
    await db.execute(
        update(MediaAsset)
        .where(MediaAsset.id == asset_id)
        .values(bytes_size=size or None, mime_type=ctype or None)
    )
    await db.commit()

    return {"size_bytes": size, "content_type": ctype, "etag": etag, "storage_key": m.storage_key}


@router.post("/assets/{asset_id}/checksum", summary="Store/verify asset SHA-256")
@rate_limit("30/minute")
async def assets_checksum(
    asset_id: UUID,
    payload: ChecksumIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)
    m = (await db.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one_or_none()
    if not m:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not m.storage_key:
        raise HTTPException(status_code=400, detail="Asset missing storage_key")

    sha = (payload.sha256 or "").strip().lower()
    if not sha:
        # Best-effort server-side compute if reasonably small
        max_bytes = 10 * 1024 * 1024  # 10MB
        size = int(getattr(m, "bytes_size", 0) or 0)
        if size <= 0:
            # Try head to discover size
            try:
                s3 = _ensure_s3()
                head = s3.client.head_object(Bucket=s3.bucket, Key=m.storage_key)  # type: ignore[attr-defined]
                size = int(head.get("ContentLength", 0))
            except Exception:
                size = 0
        if size and size <= max_bytes:
            try:
                s3 = _ensure_s3()
                obj = s3.client.get_object(Bucket=s3.bucket, Key=m.storage_key)  # type: ignore[attr-defined]
                data = obj["Body"].read()
                sha = hashlib.sha256(data).hexdigest()
            except Exception as e:
                raise HTTPException(status_code=503, detail=f"Checksum compute failed: {e}")
        else:
            raise HTTPException(status_code=400, detail="Provide sha256 for large assets (>10MB)")

    # Store if empty or force
    if m.checksum_sha256 and not payload.force:
        return {"sha256": m.checksum_sha256, "status": "UNCHANGED"}

    await db.execute(
        update(MediaAsset)
        .where(MediaAsset.id == asset_id)
        .values(checksum_sha256=sha)
    )
    await db.commit()
    return {"sha256": sha, "status": "UPDATED"}


class FinalizeAssetIn(BaseModel):
    size_bytes: Optional[int] = None
    content_type: Optional[str] = None
    sha256: Optional[str] = None
    force: bool = False


@router.post("/assets/{asset_id}/finalize", summary="Finalize asset metadata after upload")
@rate_limit("30/minute")
async def assets_finalize(
    asset_id: UUID,
    payload: FinalizeAssetIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)
    m = (await db.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one_or_none()
    if not m:
        raise HTTPException(status_code=404, detail="Asset not found")
    updates = {}
    if payload.size_bytes is not None:
        if payload.size_bytes < 0:
            raise HTTPException(status_code=400, detail="size_bytes must be >= 0")
        updates["bytes_size"] = int(payload.size_bytes)
    if payload.content_type is not None:
        updates["mime_type"] = payload.content_type
    if payload.sha256:
        if m.checksum_sha256 and not payload.force:
            # Do not overwrite unless forced
            pass
        else:
            updates["checksum_sha256"] = payload.sha256.strip().lower()
    if updates:
        await db.execute(update(MediaAsset).where(MediaAsset.id == asset_id).values(**updates))
        await db.commit()
    return {"id": str(asset_id), **updates}


@router.get("/titles/{title_id}/validate-media", summary="Validate media policy for a title")
@rate_limit("30/minute")
async def validate_media_policy(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """Run non-destructive checks against streaming and download policy.

    Checks
    - Exactly 3 streamable HLS tiers (480/720/1080) with one per tier.
    - No audio-only rows marked as streamable.
    - Download assets have `size_bytes` and `checksum_sha256`.
    - Subtitle defaults do not conflict per language per scope.
    """
    await _ensure_admin(current_user); await _ensure_mfa(request); set_sensitive_cache(response)
    from app.db.models.stream_variant import StreamVariant
    from app.schemas.enums import StreamProtocol, StreamTier
    issues: list[dict] = []

    # Stream variants
    rows = (await db.execute(select(StreamVariant).where(StreamVariant.media_asset.has(MediaAsset.title_id == title_id)))).scalars().all()
    # Filter streamable
    streamable = [r for r in rows if getattr(r, "is_streamable", False)]
    tiers = {}
    # Count by (asset, tier) to ensure one per asset/tier
    per_asset_tier: dict[tuple[str, str], int] = {}
    for r in streamable:
        t = getattr(r, "stream_tier", None)
        if t is None:
            issues.append({"severity": "error", "code": "STREAMABLE_NO_TIER", "id": str(r.id)})
            continue
        t_key = str(t.value if hasattr(t, 'value') else t)
        tiers.setdefault(t_key, []).append(r.id)
        key = (str(getattr(r, 'media_asset_id', '')), t_key)
        per_asset_tier[key] = per_asset_tier.get(key, 0) + 1
        if getattr(r, "is_audio_only", False):
            issues.append({"severity": "error", "code": "STREAMABLE_AUDIO_ONLY", "id": str(r.id)})
        if getattr(r, "protocol", None) and getattr(r, "protocol") != StreamProtocol.HLS:
            issues.append({"severity": "warning", "code": "STREAMABLE_NOT_HLS", "id": str(r.id)})
    # Expect exactly one per tier across P480/P720/P1080
    for required in ("P480", "P720", "P1080"):
        if required not in tiers:
            issues.append({"severity": "error", "code": "MISSING_TIER", "tier": required})
        elif len(tiers[required]) != 1:
            issues.append({"severity": "error", "code": "MULTI_TIER", "tier": required, "count": len(tiers[required])})

    # Per-asset per-tier uniqueness
    for (asset_id, tier), count in per_asset_tier.items():
        if count > 1:
            issues.append({"severity": "error", "code": "DUP_STREAMABLE_PER_ASSET_TIER", "asset_id": asset_id, "tier": tier, "count": count})

    # Download assets completeness
    d_assets = (await db.execute(select(MediaAsset).where(MediaAsset.title_id == title_id, MediaAsset.kind.in_([MediaAssetKind.DOWNLOAD, MediaAssetKind.ORIGINAL, MediaAssetKind.VIDEO])))).scalars().all()
    for a in d_assets:
        if a.bytes_size is None:
            issues.append({"severity": "warning", "code": "DOWNLOAD_SIZE_MISSING", "asset_id": str(a.id)})
        if (a.checksum_sha256 or "").strip() == "":
            issues.append({"severity": "warning", "code": "DOWNLOAD_SHA_MISSING", "asset_id": str(a.id)})

    # Subtitle defaults per language
    subs = (await db.execute(select(Subtitle).where(Subtitle.title_id == title_id, Subtitle.active == True))).scalars().all()
    from collections import defaultdict
    def_by_lang: dict[str, int] = defaultdict(int)
    forced_by_lang: dict[str, int] = defaultdict(int)
    for s in subs:
        if s.is_default:
            def_by_lang[s.language] += 1
        if s.is_forced:
            forced_by_lang[s.language] += 1
    for lang, c in def_by_lang.items():
        if c > 1:
            issues.append({"severity": "error", "code": "SUBTITLE_MULTI_DEFAULT", "language": lang, "count": c})
    for lang, c in forced_by_lang.items():
        if c > 1:
            issues.append({"severity": "error", "code": "SUBTITLE_MULTI_FORCED", "language": lang, "count": c})

    return {"issues": issues}


class BatchTokenItem(BaseModel):
    storage_key: str
    ttl_seconds: int = Field(3600, ge=60, le=24*3600)


class BatchTokensIn(BaseModel):
    items: list[BatchTokenItem]


@router.post("/delivery/download-tokens/batch", summary="Create multiple one-time download tokens")
@rate_limit("20/minute")
async def batch_download_tokens(
    payload: BatchTokensIn,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user); await _ensure_mfa(request)
    max_items = 100
    if not payload.items or len(payload.items) == 0:
        raise HTTPException(status_code=400, detail="No items provided")
    if len(payload.items) > max_items:
        raise HTTPException(status_code=400, detail=f"Too many items (max {max_items})")
    results: list[dict] = []
    for it in payload.items:
        token = uuid4().hex
        key = f"download:token:{token}"
        exp_at = datetime.now(timezone.utc) + timedelta(seconds=it.ttl_seconds)
        data = {"storage_key": it.storage_key, "one_time": True, "issued_by": str(getattr(current_user, "id", "")), "expires_at": exp_at.isoformat()}
        try:
            await redis_wrapper.json_set(key, data, ttl_seconds=it.ttl_seconds)
            results.append({"token": token, "expires_at": data["expires_at"], "storage_key": it.storage_key})
        except Exception as e:
            results.append({"error": str(e), "storage_key": it.storage_key})
    return {"results": results}
