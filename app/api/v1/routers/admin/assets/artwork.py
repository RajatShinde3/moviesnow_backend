"""
🧊 MoviesNow · Admin Artwork API (presigned uploads, listing, patching, reordering, primaries, deletion)
==============================================================================================

Production‑grade, security‑hardened FastAPI routes for **artwork** management under
`/api/v1/admin`. This module implements presigned uploads (S3), idempotency,
rate‑limiting, MFA enforcement, cache hardening for admin responses, robust
validation, and best‑effort storage lifecycle.

Routes (6)
----------
- POST   /api/v1/admin/titles/{title_id}/artwork          → Create artwork slot (presigned PUT)
- GET    /api/v1/admin/titles/{title_id}/artwork          → List artwork for a title
- PATCH  /api/v1/admin/artwork/{artwork_id}               → Patch artwork flags/meta
- POST   /api/v1/admin/titles/{title_id}/artwork/reorder  → Reorder artwork (front→back)
- POST   /api/v1/admin/titles/{title_id}/artwork/{artwork_id}/make-primary → Mark primary
- DELETE /api/v1/admin/artwork/{artwork_id}               → Hard delete (DB + S3 best‑effort)

Security & Operations
---------------------
- **Admin‑only** + **MFA** (token must indicate MFA) on every route.
- **SlowAPI** rate limiting with proper `Response` injection.
- **Idempotency** for create via `Idempotency-Key` header (Redis snapshot).
- **Distributed locks** (Redis) + row‑level locks for mutating flows.
- **Sensitive cache headers** (`Cache‑Control: no‑store`) on admin responses.
- **Audit logs** are best‑effort; never block the request path.

Implementation Notes
--------------------
- Storage keys are normalized, language is validated (BCP‑47‑ish), MIME types
  are constrained. Unexpected storage failures do not roll back DB deletes.
- `Artwork.kind` accepts the common alias **BACKGROUND** and maps it to
  **BACKDROP** for compatibility with tests/legacy payloads.

Replace/align imports to match your app's package layout if needed.
"""

# ─────────────────────────────────────────────────────────────────────────────
# 📦 Imports
# ─────────────────────────────────────────────────────────────────────────────
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select, update, delete, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

# Project‑specific dependencies (adjust these to your app)
from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event

# Domain models / enums (adjust imports to your app)
from app.db.models.user import User
from app.db.models.title import Title
from app.db.models.artwork import Artwork
from app.schemas.enums import ArtworkKind

# Storage abstraction (must provide `presigned_put`, `delete`)
from app.utils.aws import S3Client, S3StorageError

router = APIRouter(tags=["Admin • Artwork"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧰 Constants & Utilities
# ─────────────────────────────────────────────────────────────────────────────
ALLOWED_IMAGE_MIME = {"image/jpeg", "image/jpg", "image/png", "image/webp"}
_BCP47_RE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")  # pragmatic BCP‑47‑ish


def _ensure_s3() -> S3Client:
    """Return a configured S3 client or raise 503 if unavailable."""
    try:
        return S3Client()
    except S3StorageError as e:  # storage misconfig is operational, not client error
        raise HTTPException(status_code=503, detail=str(e))


def _ext_for_mime(ct: str) -> str:
    ct = (ct or "").lower()
    return {
        "image/jpeg": "jpg",
        "image/jpg": "jpg",
        "image/png": "png",
        "image/webp": "webp",
    }.get(ct, "bin")


def _validate_language(tag: Optional[str]) -> Optional[str]:
    if tag is None or str(tag).strip() == "":
        return None
    tag = str(tag).strip()
    if not _BCP47_RE.match(tag):
        raise HTTPException(status_code=400, detail="Invalid language tag (BCP‑47)")
    return tag


def _normalize_kind(kind: Any) -> str:
    """Normalize incoming kind to a canonical string value.

    Accepts enum or string. Maps common alias **BACKGROUND** → **BACKDROP**.
    """
    if isinstance(kind, ArtworkKind):
        val = kind.value if hasattr(kind, "value") else str(kind)
    else:
        val = str(kind or "").upper().strip()
    if val == "BACKGROUND":
        val = "BACKDROP"
    if not val:
        raise HTTPException(status_code=400, detail="Artwork kind is required")
    return val


def _build_artwork_key(*, title_id: UUID, kind: str, artwork_id: UUID, content_type: str, language: Optional[str]) -> str:
    """Construct a stable hierarchical storage key for artwork assets.

    Example::
        artwork/title/{title_id}/POSTER/en-US/{artwork_id}.jpg
    """
    lang = (language or "und").replace("/", "-")
    return f"artwork/title/{title_id}/{kind}/{lang}/{artwork_id}.{_ext_for_mime(content_type)}"


async def _ensure_title_exists(db: AsyncSession, title_id: UUID) -> None:
    exists = (await db.execute(select(Title.id).where(Title.id == title_id))).scalar_one_or_none()
    if not exists:
        raise HTTPException(status_code=404, detail="Title not found")


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Schemas
# ─────────────────────────────────────────────────────────────────────────────
class ArtworkCreateIn(BaseModel):
    """Request model for creating/attaching an artwork slot and presigning PUT.

    Attributes
    ----------
    kind:
        Logical type of artwork (e.g., POSTER, BACKDROP). String or enum is
        accepted; **BACKGROUND** is normalized to **BACKDROP**.
    content_type:
        MIME type of the binary you will upload (e.g., image/jpeg).
    language:
        Optional BCP‑47 code (e.g., "en" or "en‑US").
    is_primary:
        Whether this artwork should be the primary for its scope and language.
    """

    kind: Any
    content_type: str = Field(..., description="Image MIME type (e.g., image/jpeg)")
    language: Optional[str] = Field(None, description="BCP‑47 tag, optional")
    is_primary: bool = False

    @model_validator(mode="after")
    def _post(self):
        # minimal structural validation; MIME is validated in the route
        if not str(self.content_type or "").strip():
            raise ValueError("content_type is required")
        return self


class ArtworkOut(BaseModel):
    id: UUID
    title_id: UUID
    kind: Optional[str] = None
    language: Optional[str] = None
    content_type: Optional[str] = None
    is_primary: Optional[bool] = None


class ArtworkPatchIn(BaseModel):
    """Patch mutable attributes of an Artwork record.

    Only provided fields are updated; absent fields are left unchanged.
    """

    language: Optional[str] = Field(None, description="BCP‑47 tag (e.g., 'en', 'en‑US')")
    is_primary: Optional[bool] = None
    region: Optional[str] = Field(None, description="ISO‑3166‑1 alpha‑2 (optional)")
    dominant_color: Optional[str] = None
    focus_x: Optional[float] = Field(None, ge=0.0, le=1.0)
    focus_y: Optional[float] = Field(None, ge=0.0, le=1.0)
    sort_order: Optional[int] = Field(None, ge=0)
    cdn_url: Optional[str] = None


class ReorderArtworkIn(BaseModel):
    order: List[UUID] = Field(..., description="Artwork IDs in desired order (front→back)")


# ─────────────────────────────────────────────────────────────────────────────
# 🖼️ Create Artwork
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/titles/{title_id}/artwork", summary="Create artwork (presigned PUT)")
@rate_limit("10/minute")
async def create_artwork(
    title_id: UUID,
    payload: ArtworkCreateIn | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Provision an **artwork** DB row and return a presigned **PUT** URL.

    Steps
    -----
    1. **AuthZ + MFA** → Admin gate; apply no‑store cache policy.
    2. **Validate** → Title exists, MIME allowed, language (BCP‑47), kind normalized.
    3. **Idempotency** → If `Idempotency-Key` present and snapshot exists, replay.
    4. **Persist** → Insert Artwork row (pending upload) and commit to obtain ID.
    5. **Presign** → Build storage key and issue S3 presigned PUT URL.
    6. **Respond** → Contract `{artwork_id, upload_url, storage_key}`.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # Normalize body (allow dicts for convenience/testing)
    if isinstance(payload, dict):
        payload = ArtworkCreateIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa  # late import to avoid cycles
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Validate inputs ────────────────────────────────────────────
    await _ensure_title_exists(db, title_id)
    ct = (payload.content_type or "").lower()
    if ct not in ALLOWED_IMAGE_MIME:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Unsupported image content‑type")
    lang = _validate_language(payload.language)
    kind = _normalize_kind(payload.kind)

    # ── [Step 3] Idempotent replay ──────────────────────────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:artwork:create:{title_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    # ── [Step 4] Persist DB row ─────────────────────────────────────────────
    art = Artwork(
        title_id=title_id,
        kind=kind,  # ORM column may be Enum or String; normalized value works for both
        language=lang,
        content_type=ct,
        is_primary=bool(payload.is_primary),
    )
    db.add(art)
    await db.flush()  # obtain art.id without full commit

    # ── [Step 5] Presign storage key ────────────────────────────────────────
    key = _build_artwork_key(title_id=title_id, kind=kind, artwork_id=art.id, content_type=ct, language=lang)
    try:
        setattr(art, "storage_key", key)
    except Exception:
        pass  # tolerate models without storage_key column
    await db.commit()

    s3 = _ensure_s3()
    upload_url = s3.presigned_put(key, content_type=ct, public=False)

    body = {"artwork_id": str(art.id), "upload_url": upload_url, "storage_key": key}

    # Store idempotent snapshot (best‑effort) & audit
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    try:
        await log_audit_event(db, user=current_user, action="ARTWORK_CREATE", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "artwork_id": str(art.id)})
    except Exception:
        pass

    return body


# ─────────────────────────────────────────────────────────────────────────────
# 📋 List Artwork
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/titles/{title_id}/artwork", response_model=List[ArtworkOut], summary="List artwork for a title")
@rate_limit("30/minute")
async def list_artwork(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    kind: Optional[str] = Query(None, description="Filter by kind (e.g., POSTER)"),
    language: Optional[str] = Query(None, description="Filter by BCP‑47 language"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> List[ArtworkOut]:
    """Return artwork rows for the given title, newest first, with optional filters.

    The response model is intentionally compact to keep admin pages snappy.
    Extend as needed for your UI.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Validate + build query ─────────────────────────────────────
    await _ensure_title_exists(db, title_id)
    stmt = select(Artwork).where(Artwork.title_id == title_id)
    if kind:
        stmt = stmt.where(func.upper(Artwork.kind) == _normalize_kind(kind))
    if language:
        stmt = stmt.where(func.lower(Artwork.language) == _validate_language(language).lower())
    stmt = stmt.order_by(Artwork.created_at.desc()).offset(offset).limit(limit)

    rows = (await db.execute(stmt)).scalars().all() or []
    return [
        ArtworkOut(
            id=r.id,
            title_id=r.title_id,
            kind=getattr(r, "kind", None),
            language=getattr(r, "language", None),
            content_type=getattr(r, "content_type", None),
            is_primary=bool(getattr(r, "is_primary", False)),
        )
        for r in rows
    ]


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Patch Artwork
# ─────────────────────────────────────────────────────────────────────────────
@router.patch("/artwork/{artwork_id}", summary="Update artwork flags/meta")
@rate_limit("20/minute")
async def patch_artwork(
    artwork_id: UUID,
    payload: ArtworkPatchIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Update language/primary/positioning metadata for a specific artwork.

    Concurrency
    -----------
    Short **Redis** lock + **row‑level** SQL lock avoid racey primaries or
    reorders when multiple admins edit simultaneously.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Locked update ──────────────────────────────────────────────
    async with redis_wrapper.lock(f"lock:admin:artwork:{artwork_id}", timeout=10, blocking_timeout=3):
        art = (await db.execute(select(Artwork).where(Artwork.id == artwork_id).with_for_update())).scalar_one_or_none()
        if not art:
            raise HTTPException(status_code=404, detail="Artwork not found")

        updates: Dict[str, Any] = {}
        if payload.language is not None:
            updates["language"] = _validate_language(payload.language)
        if payload.region is not None:
            updates["region"] = payload.region or None
        if payload.dominant_color is not None:
            updates["dominant_color"] = payload.dominant_color or None
        if payload.focus_x is not None:
            updates["focus_x"] = payload.focus_x
        if payload.focus_y is not None:
            updates["focus_y"] = payload.focus_y
        if payload.sort_order is not None:
            updates["sort_order"] = int(payload.sort_order)
        if payload.cdn_url is not None:
            updates["cdn_url"] = payload.cdn_url or None

        if payload.is_primary is not None:
            want_primary = bool(payload.is_primary)
            if want_primary:
                # Demote siblings (same scope, kind, language)
                lang = updates.get("language", art.language)
                conds = [Artwork.kind == art.kind]
                if art.title_id:
                    conds.append(Artwork.title_id == art.title_id)
                if getattr(art, "season_id", None):
                    conds.append(Artwork.season_id == art.season_id)
                if getattr(art, "episode_id", None):
                    conds.append(Artwork.episode_id == art.episode_id)
                if lang is not None:
                    conds.append(func.coalesce(func.lower(Artwork.language), "") == str(lang).lower())
                await db.execute(update(Artwork).where(and_(*conds)).values(is_primary=False))
                updates["is_primary"] = True
            else:
                updates["is_primary"] = False

        if updates:
            await db.execute(update(Artwork).where(Artwork.id == artwork_id).values(**updates))
            await db.commit()

    try:
        await log_audit_event(db, user=current_user, action="ARTWORK_PATCH", status="SUCCESS", request=request, meta_data={"artwork_id": str(artwork_id), "fields": list(updates.keys()) if updates else []})
    except Exception:
        pass

    art = (await db.execute(select(Artwork).where(Artwork.id == artwork_id))).scalar_one_or_none()
    return {
        "id": str(getattr(art, "id", artwork_id)),
        "language": getattr(art, "language", None),
        "is_primary": bool(getattr(art, "is_primary", False)),
        "sort_order": getattr(art, "sort_order", 0),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 🔁 Reorder Artwork
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/titles/{title_id}/artwork/reorder", summary="Reorder artwork for a title")
@rate_limit("10/minute")
async def reorder_artwork(
    title_id: UUID,
    payload: ReorderArtworkIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Assign ascending `sort_order` according to the provided list of IDs (front→back)."""
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    ids = [UUID(str(i)) for i in payload.order]
    if not ids:
        raise HTTPException(status_code=400, detail="Provide at least one artwork id")

    # ── [Step 2] Locked reorder ─────────────────────────────────────────────
    async with redis_wrapper.lock(f"lock:admin:artwork:reorder:{title_id}", timeout=15, blocking_timeout=5):
        rows = (await db.execute(select(Artwork.id).where(Artwork.title_id == title_id, Artwork.id.in_(ids)))).scalars().all()
        found = set(rows)
        missing = [str(i) for i in ids if i not in found]
        if missing:
            raise HTTPException(status_code=400, detail=f"Artwork not for title or missing: {', '.join(missing)}")
        for idx, aid in enumerate(ids):
            await db.execute(update(Artwork).where(Artwork.id == aid).values(sort_order=idx))
        await db.commit()

    try:
        await log_audit_event(db, user=current_user, action="ARTWORK_REORDER", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "count": len(ids)})
    except Exception:
        pass

    return {"message": "Reordered", "count": len(ids)}


# ─────────────────────────────────────────────────────────────────────────────
# ⭐ Make Primary Artwork
# ─────────────────────────────────────────────────────────────────────────────
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
    """Set the given artwork as **primary** within its scope (kind + language).

    Scope
    -----
    Demotes other artwork rows for the same `(title_id, kind, language)`.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    async with redis_wrapper.lock(f"lock:admin:artwork:primary:{title_id}:{artwork_id}", timeout=15, blocking_timeout=5):
        art = (await db.execute(select(Artwork).where(Artwork.id == artwork_id).with_for_update())).scalar_one_or_none()
        if not art or art.title_id != title_id:
            raise HTTPException(status_code=404, detail="Artwork not found for this title")
        lang = art.language
        conds = [Artwork.title_id == title_id, Artwork.kind == art.kind]
        if lang is not None:
            conds.append(func.coalesce(func.lower(Artwork.language), "") == str(lang).lower())
        await db.execute(update(Artwork).where(and_(*conds)).values(is_primary=False))
        await db.execute(update(Artwork).where(Artwork.id == artwork_id).values(is_primary=True))
        await db.commit()

    try:
        await log_audit_event(db, user=current_user, action="ARTWORK_MAKE_PRIMARY", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "artwork_id": str(artwork_id)})
    except Exception:
        pass

    return {"message": "Primary set"}


# ─────────────────────────────────────────────────────────────────────────────
# 🗑️ Delete Artwork
# ─────────────────────────────────────────────────────────────────────────────
@router.delete("/artwork/{artwork_id}", summary="Delete artwork (DB + S3 best‑effort)")
@rate_limit("10/minute")
async def delete_artwork(
    artwork_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Hard‑delete an artwork row and (best‑effort) purge the S3 object.

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
    row = (await db.execute(select(Artwork).where(Artwork.id == artwork_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Artwork not found")

    storage_key = getattr(row, "storage_key", None)
    await db.execute(delete(Artwork).where(Artwork.id == artwork_id))
    await db.commit()

    # ── [Step 3] Best‑effort storage purge ──────────────────────────────────
    if storage_key:
        try:
            _ensure_s3().delete(storage_key)
        except Exception:
            pass

    try:
        await log_audit_event(db, user=current_user, action="ARTWORK_DELETE", status="SUCCESS", request=request, meta_data={"artwork_id": str(artwork_id)})
    except Exception:
        pass

    return {"message": "Artwork deleted"}
