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

Bulk (4)
  - POST   /bulk/manifest
  - GET    /bulk/jobs
  - GET    /bulk/jobs/{job_id}
  - POST   /bulk/jobs/{job_id}/cancel

CDN & Delivery (3)
  - POST   /cdn/invalidate
  - POST   /delivery/signed-url
  - POST   /delivery/download-token

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

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, delete, func
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
from app.utils.aws import S3Client, S3StorageError
import boto3


router = APIRouter(tags=["Admin Assets"])


# ─────────────────────────────────────────────────────────────────────────────
# 🔐 Access helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_admin(user: User) -> bool:
    """Return True if user is ADMIN or SUPERUSER (portable across schemas)."""
    try:
        from app.schemas.enums import OrgRole
        return getattr(user, "role", None) in {OrgRole.ADMIN, OrgRole.SUPERUSER}
    except Exception:
        return bool(getattr(user, "is_superuser", False))


async def _ensure_admin(user: User) -> None:
    if not _is_admin(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")


async def _ensure_mfa(request: Request) -> None:
    """Require a valid access token with `mfa_authenticated=True`."""
    try:
        token = (request.headers.get("Authorization", "") or "").split(" ")[-1]
        claims = await decode_token(token, expected_types=["access"], verify_revocation=True)
        if not bool(claims.get("mfa_authenticated")):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MFA required")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token")


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
    caller_ref = f"inv-{uuid4().hex}"

    if dist_id:
        try:
            cf = boto3.client(
                "cloudfront",
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY.get_secret_value(),
                region_name=settings.AWS_REGION,
            )
            cf.create_invalidation(
                DistributionId=dist_id,
                InvalidationBatch={"Paths": {"Quantity": len(paths), "Items": paths}, "CallerReference": caller_ref},
            )
            await log_audit_event(
                db=db,
                user=current_user,
                action="CDN_INVALIDATE",
                status="SUBMITTED",
                request=request,
                meta_data={"distribution": dist_id, "paths": paths[:10], "count": len(paths)},
            )
            return {"status": "SUBMITTED", "distribution_id": dist_id, "paths": paths}
        except Exception:
            # Fall through to queue
            pass

    try:
        await redis_wrapper.client.rpush("cdn:invalidate:queue", *paths)  # type: ignore
        await log_audit_event(
            db=db,
            user=current_user,
            action="CDN_INVALIDATE",
            status="QUEUED",
            request=request,
            meta_data={"paths": paths[:10], "count": len(paths)},
        )
        return {"status": "QUEUED", "paths": paths}
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
