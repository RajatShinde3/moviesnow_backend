"""
💬 MoviesNow · Admin Subtitles API (presigned uploads, listing, patching, deletion)
==============================================================================

Production‑grade, security‑hardened FastAPI routes for **subtitles** under
`/api/v1/admin`. Implements S3 presigned uploads, idempotency, Redis locks,
MFA‑enforced admin access, rate limiting, cache hardening, robust validation,
and best‑effort storage lifecycle.

Routes (4)
----------
- POST   /api/v1/admin/titles/{title_id}/subtitles      → Create subtitle slot (presigned PUT + rows)
- GET    /api/v1/admin/titles/{title_id}/subtitles      → List subtitles for a title
- PATCH  /api/v1/admin/subtitles/{subtitle_id}          → Patch subtitle flags/label/language
- DELETE /api/v1/admin/subtitles/{subtitle_id}          → Hard delete subtitle (DB + S3 best‑effort)

Security & Operations
---------------------
- **Admin‑only** + **MFA** on every route.
- **SlowAPI** rate limits with proper `Response` injection.
- **Idempotency** on create via `Idempotency-Key` (Redis snapshot).
- **Distributed locks** (Redis) + **row locks** for safe mutations.
- **Sensitive cache headers** (`Cache‑Control: no‑store`) for admin responses.
- **Audit logs** are best‑effort and never block the request path.

Replace or align imports to match your app's package layout if needed.
"""
from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# 📦 Imports
# ─────────────────────────────────────────────────────────────────────────────
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update, delete, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

# Project‑specific dependencies (adjust to your app)
from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event

# Domain models / enums (adjust to your app)
from app.db.models.user import User
from app.db.models.title import Title
from app.db.models.media_asset import MediaAsset
from app.db.models.subtitle import Subtitle
from app.schemas.enums import MediaAssetKind, SubtitleFormat

# Storage abstraction (must provide `presigned_put`, `delete`)
from app.utils.aws import S3Client, S3StorageError

router = APIRouter(tags=["Admin • Subtitles"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧰 Constants & Utilities
# ─────────────────────────────────────────────────────────────────────────────
ALLOWED_SUBS_MIME = {"text/vtt", "application/x-subrip"}
_BCP47_RE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")  # pragmatic BCP‑47‑ish


def _ensure_s3() -> S3Client:
    """Return a configured S3 client or raise 503 if unavailable."""
    try:
        return S3Client()
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))


def _ext_for_mime(ct: str) -> str:
    ct = (ct or "").lower()
    return {"text/vtt": "vtt", "application/x-subrip": "srt"}.get(ct, "bin")


def _validate_language(tag: Optional[str]) -> Optional[str]:
    if tag is None or str(tag).strip() == "":
        return None
    tag = str(tag).strip()
    if not _BCP47_RE.match(tag):
        raise HTTPException(status_code=400, detail="Invalid language tag (BCP‑47)")
    return tag


async def _ensure_title_exists(db: AsyncSession, title_id: UUID) -> None:
    exists = (await db.execute(select(Title.id).where(Title.id == title_id))).scalar_one_or_none()
    if not exists:
        raise HTTPException(status_code=404, detail="Title not found")


def _build_subtitle_key(*, title_id: UUID, subtitle_id: UUID, content_type: str, language: str) -> str:
    """Construct a stable hierarchical storage key for subtitle assets.

    Example::
        subs/title/{title_id}/en-US/{subtitle_id}.vtt
    """
    lang = (language or "und").replace("/", "-")
    return f"subs/title/{title_id}/{lang}/{subtitle_id}.{_ext_for_mime(content_type)}"


def _ensure_mime_matches_format(content_type: str, fmt: SubtitleFormat) -> None:
    ct = (content_type or "").lower()
    if ct not in ALLOWED_SUBS_MIME:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Unsupported subtitle content‑type")
    if fmt == SubtitleFormat.VTT and ct != "text/vtt":
        raise HTTPException(status_code=400, detail="For VTT format, content_type must be text/vtt")
    if fmt == SubtitleFormat.SRT and ct != "application/x-subrip":
        raise HTTPException(status_code=400, detail="For SRT format, content_type must be application/x-subrip")


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Schemas
# ─────────────────────────────────────────────────────────────────────────────
class SubtitleCreateIn(BaseModel):
    """Request model for creating a subtitle upload slot (presigned PUT).

    Creates both a **MediaAsset(kind=SUBTITLE)** and a **Subtitle** track row.
    """

    language: str = Field(..., min_length=2, max_length=16, description="BCP‑47 language (e.g., 'en' or 'en‑US')")
    format: SubtitleFormat = SubtitleFormat.VTT
    content_type: str = Field(..., description="text/vtt or application/x-subrip")
    label: Optional[str] = Field(None, description="Optional UI label")
    is_default: bool = False
    is_forced: bool = False
    is_sdh: bool = False


class SubtitleOut(BaseModel):
    id: UUID
    asset_id: UUID
    title_id: UUID
    language: str
    format: SubtitleFormat
    label: Optional[str] = None
    is_default: bool
    is_forced: bool
    is_sdh: bool
    active: Optional[bool] = True


class SubtitlePatchIn(BaseModel):
    """Patch mutable attributes of a Subtitle track row."""

    language: Optional[str] = None
    label: Optional[str] = None
    is_default: Optional[bool] = None
    is_forced: Optional[bool] = None
    is_sdh: Optional[bool] = None
    active: Optional[bool] = None


# ─────────────────────────────────────────────────────────────────────────────
# ✍️ Create Subtitle
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/titles/{title_id}/subtitles", summary="Create subtitle (presigned PUT + rows)")
@rate_limit("10/minute")
async def create_subtitle(
    title_id: UUID,
    payload: SubtitleCreateIn | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Provision a **subtitle** asset + track and return a presigned **PUT** URL.

    Steps
    -----
    1. **AuthZ + MFA** → Admin gate; apply no‑store cache policy.
    2. **Validate** → Title exists, MIME/format match, language (BCP‑47).
    3. **Idempotency** → If `Idempotency-Key` present and snapshot exists, replay.
    4. **Persist** → Insert MediaAsset(kind=SUBTITLE) and Subtitle track; commit.
    5. **Presign** → Build storage key and issue S3 presigned PUT URL.
    6. **Respond** → Contract `{asset_id, subtitle_id, upload_url, storage_key}`.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # Normalize body (allow dicts for convenience/testing)
    if isinstance(payload, dict):
        payload = SubtitleCreateIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Validate inputs ────────────────────────────────────────────
    await _ensure_title_exists(db, title_id)
    lang = _validate_language(payload.language) or payload.language
    _ensure_mime_matches_format(payload.content_type, payload.format)

    # ── [Step 3] Idempotent replay ──────────────────────────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:subtitles:create:{title_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    # ── [Step 4] Persist DB rows ────────────────────────────────────────────
    asset = MediaAsset(
        title_id=title_id,
        kind=MediaAssetKind.SUBTITLE,
        language=lang,
        mime_type=payload.content_type,
        metadata_json=( {"label": payload.label} if payload.label else None ),
    )
    db.add(asset)
    await db.flush()  # assign asset.id

    track = Subtitle(
        title_id=title_id,
        asset_id=asset.id,
        language=lang,
        format=payload.format,
        label=payload.label,
        is_default=bool(payload.is_default),
        is_forced=bool(payload.is_forced),
        is_sdh=bool(payload.is_sdh),
        active=True,
    )
    db.add(track)
    await db.flush()  # assign track.id

    # If default requested, demote any other defaults for same language scope
    if payload.is_default:
        await db.execute(
            update(Subtitle)
            .where(
                Subtitle.title_id == title_id,
                func.lower(Subtitle.language) == lang.lower(),
                Subtitle.id != track.id,
            )
            .values(is_default=False)
        )

    # ── [Step 5] Presign storage key ────────────────────────────────────────
    key = _build_subtitle_key(title_id=title_id, subtitle_id=track.id, content_type=payload.content_type, language=lang)
    try:
        setattr(asset, "storage_key", key)
    except Exception:
        pass
    await db.commit()

    s3 = _ensure_s3()
    upload_url = s3.presigned_put(key, content_type=payload.content_type, public=False)

    body = {"asset_id": str(asset.id), "subtitle_id": str(track.id), "upload_url": upload_url, "storage_key": key}

    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    try:
        await log_audit_event(db, user=current_user, action="SUBTITLE_CREATE", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "subtitle_id": str(track.id)})
    except Exception:
        pass

    return body


# ─────────────────────────────────────────────────────────────────────────────
# 📋 List Subtitles
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/titles/{title_id}/subtitles", response_model=List[SubtitleOut], summary="List subtitles for a title")
@rate_limit("30/minute")
async def list_subtitles(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    language: Optional[str] = Query(None, description="Filter by BCP‑47 language"),
    active_only: bool = Query(False, description="Return only active subtitles"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> List[SubtitleOut]:
    """Return subtitle tracks for the given title, newest first, with optional filters."""
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Validate + build query ─────────────────────────────────────
    await _ensure_title_exists(db, title_id)
    stmt = select(Subtitle).where(Subtitle.title_id == title_id)
    if language:
        stmt = stmt.where(func.lower(Subtitle.language) == _validate_language(language).lower())
    if active_only:
        stmt = stmt.where(Subtitle.active == True)  # noqa: E712
    stmt = stmt.order_by(Subtitle.created_at.desc()).offset(offset).limit(limit)

    rows = (await db.execute(stmt)).scalars().all() or []
    return [
        SubtitleOut(
            id=r.id,
            asset_id=r.asset_id,
            title_id=r.title_id,
            language=r.language,
            format=getattr(r, "format", None),
            label=getattr(r, "label", None),
            is_default=bool(getattr(r, "is_default", False)),
            is_forced=bool(getattr(r, "is_forced", False)),
            is_sdh=bool(getattr(r, "is_sdh", False)),
            active=getattr(r, "active", True),
        )
        for r in rows
    ]


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Patch Subtitle
# ─────────────────────────────────────────────────────────────────────────────
@router.patch("/subtitles/{subtitle_id}", summary="Update subtitle flags/label/language")
@rate_limit("10/minute")
async def patch_subtitle(
    subtitle_id: UUID,
    payload: SubtitlePatchIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Update a subtitle's language/default/forced/SDH/active/label.

    Concurrency
    -----------
    Short **Redis** lock + **row‑level** SQL lock avoid racey defaults and
    edits when multiple admins operate simultaneously.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Locked update ──────────────────────────────────────────────
    async with redis_wrapper.lock(f"lock:admin:subtitles:patch:{subtitle_id}", timeout=10, blocking_timeout=3):
        s = (await db.execute(select(Subtitle).where(Subtitle.id == subtitle_id).with_for_update())).scalar_one_or_none()
        if not s:
            raise HTTPException(status_code=404, detail="Subtitle not found")

        updates: Dict[str, Any] = {}
        new_lang = None
        if payload.language is not None:
            new_lang = _validate_language(payload.language)
            updates["language"] = new_lang
        if payload.label is not None:
            updates["label"] = payload.label or None
        if payload.is_default is not None:
            updates["is_default"] = bool(payload.is_default)
        if payload.is_forced is not None:
            updates["is_forced"] = bool(payload.is_forced)
        if payload.is_sdh is not None:
            updates["is_sdh"] = bool(payload.is_sdh)
        if payload.active is not None:
            updates["active"] = bool(payload.active)

        if not updates:
            raise HTTPException(status_code=400, detail="No changes provided")

        # Apply updates
        await db.execute(update(Subtitle).where(Subtitle.id == subtitle_id).values(**updates))

        # Enforce single default per language scope if requested
        # Determine effective language after patch
        eff_lang = new_lang if new_lang is not None else s.language
        if updates.get("is_default"):
            await db.execute(
                update(Subtitle)
                .where(
                    Subtitle.title_id == s.title_id,
                    func.lower(Subtitle.language) == func.lower(eff_lang),
                    Subtitle.id != s.id,
                )
                .values(is_default=False)
            )

        await db.commit()

    try:
        await log_audit_event(
            db, user=current_user, action="SUBTITLE_PATCH", status="SUCCESS", request=request,
            meta_data={"subtitle_id": str(subtitle_id), "fields": list(updates.keys())}
        )
    except Exception:
        pass

    s2 = (await db.execute(select(Subtitle).where(Subtitle.id == subtitle_id))).scalar_one_or_none()
    return {
        "id": str(getattr(s2, "id", subtitle_id)),
        "language": getattr(s2, "language", None),
        "is_default": bool(getattr(s2, "is_default", False)),
        "is_forced": bool(getattr(s2, "is_forced", False)),
        "is_sdh": bool(getattr(s2, "is_sdh", False)),
        "active": bool(getattr(s2, "active", True)),
        "label": getattr(s2, "label", None),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 🗑️ Delete Subtitle
# ─────────────────────────────────────────────────────────────────────────────
@router.delete("/subtitles/{subtitle_id}", summary="Delete subtitle (DB + S3 best‑effort)")
@rate_limit("10/minute")
async def delete_subtitle(
    subtitle_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Hard‑delete a subtitle row and its media asset; purge S3 best‑effort.

    Semantics
    ---------
    - First delete returns **200 OK**.
    - Subsequent attempts may return **404 Not Found**.
    - Storage deletion failures are swallowed; DB is the source of truth.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Lookup & cascade delete ────────────────────────────────────
    s = (await db.execute(select(Subtitle).where(Subtitle.id == subtitle_id))).scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Subtitle not found")

    asset_id = getattr(s, "asset_id", None)
    storage_key: Optional[str] = None
    if asset_id:
        a = (await db.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one_or_none()
        storage_key = getattr(a, "storage_key", None)
        await db.execute(delete(MediaAsset).where(MediaAsset.id == asset_id))

    await db.execute(delete(Subtitle).where(Subtitle.id == subtitle_id))
    await db.commit()

    # ── [Step 3] Best‑effort storage purge ──────────────────────────────────
    if storage_key:
        try:
            _ensure_s3().delete(storage_key)
        except Exception:
            pass

    try:
        await log_audit_event(db, user=current_user, action="SUBTITLE_DELETE", status="SUCCESS", request=request, meta_data={"subtitle_id": str(subtitle_id)})
    except Exception:
        pass

    return {"message": "Subtitle deleted"}
