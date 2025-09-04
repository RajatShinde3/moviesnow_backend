"""
🎬 MoviesNow · Admin Trailers API (presigned uploads, listing, patching, primaries, deletion)
=============================================================================================

Production‑grade, security‑hardened FastAPI routes for **trailer** management under
`/api/v1/admin`. Implements S3 presigned uploads, idempotency, Redis locks,
MFA‑enforced admin access, rate limiting, cache hardening, robust validation,
and best‑effort storage lifecycle.

Routes (5)
----------
- POST   /api/v1/admin/titles/{title_id}/trailers                     → Create trailer slot (presigned PUT)
- GET    /api/v1/admin/titles/{title_id}/trailers                     → List trailers for a title
- PATCH  /api/v1/admin/trailers/{trailer_id}                          → Patch trailer flags/label
- POST   /api/v1/admin/titles/{title_id}/trailers/{trailer_id}/make-primary → Mark trailer as primary
- DELETE /api/v1/admin/trailers/{trailer_id}                          → Hard delete trailer (DB + S3 best‑effort)

Security & Operations
---------------------
- **Admin‑only** + **MFA** on every route.
- **SlowAPI** rate limits with proper `Response` injection.
- **Idempotency** on create via `Idempotency-Key` (Redis snapshot).
- **Distributed locks** (Redis) + **row locks** to avoid racey writes.
- **Sensitive cache headers** (`Cache‑Control: no‑store`) for admin responses.
- **Audit logs** are best‑effort and never block the request path.

Replace or align imports to match your app's package layout if needed.
"""

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

# Project‑specific dependencies (adjust these to your app)
from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.security_headers import set_sensitive_cache
import app.services.audit_log_service as audit_log_service

# Domain models / enums (adjust imports to your app)
from app.db.models.user import User
from app.db.models.title import Title
from app.db.models.media_asset import MediaAsset
from app.schemas.enums import MediaAssetKind

# Storage abstraction (must provide `presigned_put`, `presigned_get`, `delete`)
from app.utils.aws import S3Client, S3StorageError

router = APIRouter(tags=["Admin • Trailers"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧰 Constants & Utilities
# ─────────────────────────────────────────────────────────────────────────────
ALLOWED_VIDEO_MIME = {"video/mp4", "video/mpeg", "video/webm", "video/quicktime"}
_BCP47_RE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")  # pragmatic BCP‑47‑ish


def _ensure_s3() -> S3Client:
    """Return a configured S3 client or raise 503 if unavailable."""
    try:
        return S3Client()
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))


def _ext_for_mime(ct: str) -> str:
    ct = (ct or "").lower()
    return {
        "video/mp4": "mp4",
        "video/mpeg": "mpg",
        "video/webm": "webm",
        "video/quicktime": "mov",
    }.get(ct, "bin")


def _validate_language(tag: Optional[str]) -> Optional[str]:
    if tag is None or str(tag).strip() == "":
        return None
    tag = str(tag).strip()
    if not _BCP47_RE.match(tag):
        raise HTTPException(status_code=400, detail="Invalid language tag (BCP‑47)")
    return tag


def _ensure_title_exists(db: AsyncSession, title_id: UUID) -> None:
    """Raise 404 if the title does not exist."""
    # NOTE: Intentionally synchronous signature; used as `await _ensure_title_exists(...)` for clarity.
    # This function performs an async DB query and raises on absence.
    return  # will be monkey‑patched by the async variant below


async def _ensure_title_exists(db: AsyncSession, title_id: UUID) -> None:  # type: ignore[no-redef]
    exists = (await db.execute(select(Title.id).where(Title.id == title_id))).scalar_one_or_none()
    if not exists:
        raise HTTPException(status_code=404, detail="Title not found")


def _build_trailer_key(*, title_id: UUID, trailer_id: UUID, content_type: str, language: Optional[str]) -> str:
    """Construct a stable hierarchical storage key for trailer assets.

    Example::
        video/title/{title_id}/trailers/en-US/{trailer_id}.mp4
    """
    lang = (language or "und").replace("/", "-")
    return f"video/title/{title_id}/trailers/{lang}/{trailer_id}.{_ext_for_mime(content_type)}"


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Schemas
# ─────────────────────────────────────────────────────────────────────────────
class TrailerCreateIn(BaseModel):
    """Request model for creating a trailer upload slot (presigned PUT)."""

    content_type: str = Field(..., description="Video MIME type (e.g., video/mp4)")
    language: Optional[str] = Field(None, description="BCP‑47 tag (e.g., en‑US)")
    is_primary: bool = False
    label: Optional[str] = Field(None, description="Optional UI label stored in metadata")


class TrailerOut(BaseModel):
    id: UUID
    title_id: UUID
    language: Optional[str] = None
    content_type: Optional[str] = None
    is_primary: Optional[bool] = None
    label: Optional[str] = None


class TrailerPatchIn(BaseModel):
    """Patch mutable attributes of a Trailer media asset."""

    language: Optional[str] = None
    is_primary: Optional[bool] = None
    label: Optional[str] = Field(None, description="UI label stored in metadata")


# ─────────────────────────────────────────────────────────────────────────────
# 🎬 Create Trailer
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/titles/{title_id}/trailers", summary="Create trailer (presigned PUT)")
@rate_limit("10/minute")
async def create_trailer(
    title_id: UUID,
    payload: TrailerCreateIn | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Provision a **trailer** media asset and return a presigned **PUT** URL.

    Steps
    -----
    1. **AuthZ + MFA** → Admin gate; apply no‑store cache policy.
    2. **Validate** → Title exists, MIME allowed, language (BCP‑47).
    3. **Idempotency** → If `Idempotency-Key` present and snapshot exists, replay.
    4. **Persist** → Insert MediaAsset row (kind=TRAILER) and commit to obtain ID.
    5. **Presign** → Build storage key and issue S3 presigned PUT URL.
    6. **Respond** → Contract `{asset_id, upload_url, storage_key}`.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # Normalize body (allow dicts for convenience/testing)
    if isinstance(payload, dict):
        payload = TrailerCreateIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Validate inputs ────────────────────────────────────────────
    await _ensure_title_exists(db, title_id)
    ct = (payload.content_type or "").lower()
    if ct not in ALLOWED_VIDEO_MIME:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Unsupported video content‑type")
    lang = _validate_language(payload.language)

    # ── [Step 3] Idempotent replay ──────────────────────────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:trailers:create:{title_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    # ── [Step 4] Persist DB row ─────────────────────────────────────────────
    meta = {"label": payload.label} if payload.label else None
    asset = MediaAsset(
        title_id=title_id,
        kind=MediaAssetKind.TRAILER,
        language=lang,
        mime_type=ct,
        is_primary=bool(payload.is_primary),
        metadata_json=meta,
    )
    db.add(asset)
    await db.flush()  # get asset.id

    # ── [Step 5] Presign storage key ────────────────────────────────────────
    key = _build_trailer_key(title_id=title_id, trailer_id=asset.id, content_type=ct, language=lang)
    try:
        setattr(asset, "storage_key", key)
    except Exception:
        pass
    await db.commit()

    s3 = _ensure_s3()
    upload_url = s3.presigned_put(key, content_type=ct, public=False)

    body = {"asset_id": str(asset.id), "upload_url": upload_url, "storage_key": key}

    # Idempotent snapshot & audit (best‑effort)
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    try:
        await audit_log_service.log_audit_event(db, user=current_user, action="TRAILER_CREATE", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "asset_id": str(asset.id)})
    except Exception:
        pass

    return body


# ─────────────────────────────────────────────────────────────────────────────
# 📋 List Trailers
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/titles/{title_id}/trailers", response_model=List[TrailerOut], summary="List trailers for a title")
@rate_limit("30/minute")
async def list_trailers(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    language: Optional[str] = Query(None, description="Filter by BCP‑47 language"),
    only_primary: bool = Query(False, description="Return only primary trailers for the language scope"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> List[TrailerOut]:
    """Return trailer assets for the given title, newest first, with optional filters."""
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Validate + build query ─────────────────────────────────────
    await _ensure_title_exists(db, title_id)
    stmt = select(MediaAsset).where(MediaAsset.title_id == title_id, MediaAsset.kind == MediaAssetKind.TRAILER)
    if language:
        stmt = stmt.where(func.lower(MediaAsset.language) == _validate_language(language).lower())
    if only_primary:
        stmt = stmt.where(MediaAsset.is_primary == True)  # noqa: E712
    stmt = stmt.order_by(MediaAsset.created_at.desc()).offset(offset).limit(limit)

    rows = (await db.execute(stmt)).scalars().all() or []
    return [
        TrailerOut(
            id=r.id,
            title_id=r.title_id,
            language=getattr(r, "language", None),
            content_type=getattr(r, "mime_type", None) or getattr(r, "content_type", None),
            is_primary=bool(getattr(r, "is_primary", False)),
            label=(getattr(r, "metadata_json", {}) or {}).get("label"),
        )
        for r in rows
    ]


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Patch Trailer
# ─────────────────────────────────────────────────────────────────────────────
@router.patch("/trailers/{trailer_id}", summary="Update trailer flags/label")
@rate_limit("20/minute")
async def patch_trailer(
    trailer_id: UUID,
    payload: TrailerPatchIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Update a trailer's language / primary flag / label.

    Concurrency
    -----------
    Short **Redis** lock + **row‑level** SQL lock avoid racey primaries/edits.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Locked update ──────────────────────────────────────────────
    async with redis_wrapper.lock(f"lock:admin:trailer:{trailer_id}", timeout=10, blocking_timeout=3):
        m = (await db.execute(select(MediaAsset).where(MediaAsset.id == trailer_id, MediaAsset.kind == MediaAssetKind.TRAILER).with_for_update())).scalar_one_or_none()
        if not m:
            raise HTTPException(status_code=404, detail="Trailer not found")

        updates: Dict[str, Any] = {}
        if payload.language is not None:
            updates["language"] = _validate_language(payload.language)
        if payload.is_primary is not None:
            if payload.is_primary:
                # Demote siblings (same scope/lang)
                conds = [MediaAsset.kind == MediaAssetKind.TRAILER]
                if m.title_id:
                    conds.append(MediaAsset.title_id == m.title_id)
                if getattr(m, "season_id", None):
                    conds.append(MediaAsset.season_id == m.season_id)
                if getattr(m, "episode_id", None):
                    conds.append(MediaAsset.episode_id == m.episode_id)
                lang = updates.get("language", m.language)
                if lang is not None:
                    conds.append(func.coalesce(func.lower(MediaAsset.language), "") == str(lang).lower())
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

    try:
        await audit_log_service.log_audit_event(db, user=current_user, action="TRAILER_PATCH", status="SUCCESS", request=request, meta_data={"trailer_id": str(trailer_id), "fields": list(updates.keys()) if updates else []})
    except Exception:
        pass

    m = (await db.execute(select(MediaAsset).where(MediaAsset.id == trailer_id))).scalar_one_or_none()
    return {
        "id": str(getattr(m, "id", trailer_id)),
        "language": getattr(m, "language", None),
        "is_primary": bool(getattr(m, "is_primary", False)),
        "label": (getattr(m, "metadata_json", {}) or {}).get("label"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# ⭐ Make Primary Trailer
# ─────────────────────────────────────────────────────────────────────────────
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
    """Set the given trailer as **primary** within its scope (language).

    Demotes other trailer rows for the same `(title_id, language)`.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    async with redis_wrapper.lock(f"lock:admin:trailer:primary:{title_id}:{trailer_id}", timeout=15, blocking_timeout=5):
        m = (await db.execute(select(MediaAsset).where(MediaAsset.id == trailer_id, MediaAsset.kind == MediaAssetKind.TRAILER).with_for_update())).scalar_one_or_none()
        if not m or m.title_id != title_id:
            raise HTTPException(status_code=404, detail="Trailer not found for this title")
        lang = m.language
        conds = [MediaAsset.title_id == title_id, MediaAsset.kind == MediaAssetKind.TRAILER]
        if lang is not None:
            conds.append(func.coalesce(func.lower(MediaAsset.language), "") == str(lang).lower())
        await db.execute(update(MediaAsset).where(and_(*conds)).values(is_primary=False))
        await db.execute(update(MediaAsset).where(MediaAsset.id == trailer_id).values(is_primary=True))
        await db.commit()

    try:
        await audit_log_service.log_audit_event(db, user=current_user, action="TRAILER_MAKE_PRIMARY", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "trailer_id": str(trailer_id)})
    except Exception:
        pass

    return {"message": "Primary set"}


# ─────────────────────────────────────────────────────────────────────────────
# 🗑️ Delete Trailer
# ─────────────────────────────────────────────────────────────────────────────
@router.delete("/trailers/{trailer_id}", summary="Delete trailer (DB + S3 best‑effort)")
@rate_limit("10/minute")
async def delete_trailer(
    trailer_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Hard‑delete a trailer media asset and (best‑effort) purge the S3 object.

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

    # ── [Step 2] Lookup & delete row ────────────────────────────────────────
    row = (await db.execute(select(MediaAsset).where(MediaAsset.id == trailer_id, MediaAsset.kind == MediaAssetKind.TRAILER))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Trailer not found")

    storage_key = getattr(row, "storage_key", None)
    await db.execute(delete(MediaAsset).where(MediaAsset.id == trailer_id))
    await db.commit()

    # ── [Step 3] Best‑effort storage purge ──────────────────────────────────
    if storage_key:
        try:
            _ensure_s3().delete(storage_key)
        except Exception:
            pass

    try:
        await audit_log_service.log_audit_event(db, user=current_user, action="TRAILER_DELETE", status="SUCCESS", request=request, meta_data={"asset_id": str(trailer_id)})
    except Exception:
        pass

    return {"message": "Trailer deleted"}
