"""
📡 MoviesNow · Admin Streams API (HLS/MP4 variants)
==================================================

Production‑grade, security‑hardened FastAPI routes for **stream variants** under
`/api/v1/admin`. Implements creation of HLS/MP4 variants, safe patching, listing,
and deletion with **Admin+MFA** enforcement, **SlowAPI** rate limits,
**idempotency** on create, **Redis locks** for concurrency, and **audit logs**.

Routes (4)
----------
- POST   /api/v1/admin/titles/{title_id}/streams   → Create stream variant (HLS/MP4)
- GET    /api/v1/admin/titles/{title_id}/streams   → List variants for a title
- PATCH  /api/v1/admin/streams/{stream_id}         → Patch flags / tier / default / labels
- DELETE /api/v1/admin/streams/{stream_id}         → Hard delete a variant

Security & Operations
---------------------
- **Admin‑only** + **MFA** on every route.
- **SlowAPI** rate limits with Response‑aware returns (JSONResponse) so headers inject cleanly.
- **Idempotency** on create via `Idempotency-Key` (Redis snapshot, 10min TTL).
- **Distributed locks** (Redis) & **row locks** to prevent race conditions.
- **Sensitive cache** headers on returned responses (no‑store/no‑cache).
- **Audit logs** are best‑effort and never block the request path.

Adjust import paths if your project layout differs.
"""

# ─────────────────────────────────────────────────────────────────────────────
# 📦 Imports
# ─────────────────────────────────────────────────────────────────────────────
from typing import Optional, Dict, Any, List, Literal
from uuid import UUID, uuid4
import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status, Body
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select, update, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

# Project‑specific deps (align to your app)
from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.security_headers import set_sensitive_cache
# Import the module rather than the function so tests can monkeypatch it reliably
import app.services.audit_log_service as audit_log_service

# Domain models / enums (align to your app)
from app.db.models.user import User
from app.db.models.title import Title
from app.db.models.media_asset import MediaAsset
from app.db.models.stream_variant import StreamVariant
from app.schemas.enums import StreamProtocol, Container, StreamTier, MediaAssetKind

router = APIRouter(tags=["Admin • Streams"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧰 Helpers & Constants
# ─────────────────────────────────────────────────────────────────────────────
_BCP47_RE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")  # pragmatic BCP‑47‑ish


def _json(data: Dict[str, Any], status_code: int = 200) -> JSONResponse:
    """
    JSONResponse wrapper that:
      - serializes non-JSON-native types (datetime, UUID, Enum)
      - ensures sensitive responses are not cached
    """
    return JSONResponse(
        jsonable_encoder(data),
        status_code=status_code,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _validate_language(tag: Optional[str]) -> Optional[str]:
    if tag is None:
        return None
    tag = str(tag).strip()
    if not tag:
        return None
    if not _BCP47_RE.match(tag):
        raise HTTPException(status_code=400, detail="Invalid language tag (BCP-47)")
    return tag


async def _ensure_title_exists(db: AsyncSession, title_id: UUID) -> None:
    if not (await db.execute(select(Title.id).where(Title.id == title_id))).scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Title not found")


def _tier_for_quality(q: str) -> StreamTier:
    q = q.lower()
    mapping = {"1080p": StreamTier.P1080, "720p": StreamTier.P720, "480p": StreamTier.P480}
    if q not in mapping:
        raise HTTPException(status_code=400, detail="Unsupported quality; use 480p/720p/1080p")
    return mapping[q]


def _height_for_quality(q: str) -> int:
    q = q.lower()
    mapping = {"1080p": 1080, "720p": 720, "480p": 480}
    if q not in mapping:
        raise HTTPException(status_code=400, detail="Unsupported quality; use 480p/720p/1080p")
    return mapping[q]


def _serialize_stream(v: StreamVariant) -> Dict[str, Any]:
    def _str_or_none(val):
        return str(val) if val is not None else None

    return {
        "id": str(v.id),
        "media_asset_id": str(v.media_asset_id),
        "url_path": v.url_path,
        "protocol": _str_or_none(getattr(v, "protocol", None)),
        "container": _str_or_none(getattr(v, "container", None)),
        "height": getattr(v, "height", None),
        "bandwidth_bps": getattr(v, "bandwidth_bps", None),
        "avg_bandwidth_bps": getattr(v, "avg_bandwidth_bps", None),
        "stream_tier": _str_or_none(getattr(v, "stream_tier", None)),
        "is_streamable": bool(getattr(v, "is_streamable", False)),
        "is_downloadable": bool(getattr(v, "is_downloadable", False)),
        "is_default": bool(getattr(v, "is_default", False)),
        "audio_language": getattr(v, "audio_language", None),
        "label": getattr(v, "label", None),
        "created_at": getattr(v, "created_at", None),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Schemas
# ─────────────────────────────────────────────────────────────────────────────
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
    is_downloadable: Optional[bool] = None
    is_default: Optional[bool] = None
    stream_tier: Optional[StreamTier] = None
    label: Optional[str] = Field(None, max_length=64)
    audio_language: Optional[str] = Field(None, min_length=2, max_length=16)


# ─────────────────────────────────────────────────────────────────────────────
# ➕ Create Stream Variant
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/titles/{title_id}/streams", summary="Create stream variant (HLS/MP4)")
@rate_limit("10/minute")
async def create_stream(
    title_id: UUID,
    request: Request,
    response: Response,
    payload: StreamCreateIn | Dict[str, Any] = Body(..., description="Stream creation payload"),
    db: AsyncSession = Depends(get_async_db),
    current_user: "User" = Depends(get_current_user),
) -> JSONResponse:
    """
    Create a **stream variant** (HLS or MP4) for a title.

    ## Behavior
    - **HLS** variants are *streamable* (not downloadable) and must include a derived `stream_tier`
      based on quality (e.g., 480p → SD, 720p → HD, 1080p → FHD).
    - **MP4** variants are *downloadable* (not streamable).
    - If `asset_id` is not provided, a placeholder **MediaAsset(kind=VIDEO)** holder is created and
      the variant is bound to that new asset.

    ## Idempotency
    If you provide an `Idempotency-Key` header, the endpoint will:
    - On first successful call, store a snapshot of the response for 10 minutes.
    - On subsequent calls with the same key and title, immediately replay the stored snapshot.

    ## Security
    - Requires admin privileges + MFA.
    - Returns `404` if the title or asset (when provided) do not match.
    - Returns `400/422` on validation issues.

    ## Parameters
    - `title_id`: The ID of the Title the stream belongs to.
    - `payload`: Either a validated `StreamCreateIn` model or a raw dict (validated here).

    ## Returns
    - JSON describing the created stream variant (JSON-safe: datetimes, UUIDs, enums serialized).

    ## Errors
    - `404 Not Found` – title/asset mismatch.
    - `400 Bad Request` – invalid asset reference or domain-specific validation errors.
    - `422 Unprocessable Entity` – schema validation errors (when raw dict payload is invalid).
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Normalize & validate body (schema) ─────────────────────────
    # FastAPI will already validate if the parameter type is StreamCreateIn.
    # We additionally support dict payloads for flexibility (tests, internal calls).
    if isinstance(payload, dict):
        try:
            payload = StreamCreateIn.model_validate(payload)
        except ValidationError as ve:
            # Surface the same error shape FastAPI uses (422 with 'detail')
            raise RequestValidationError(ve.errors())

    # ── [Step 2] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import (
        ensure_admin as _ensure_admin,
        ensure_mfa as _ensure_mfa,
    )
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 3] Upfront invariants (title + domain validation) ─────────────
    # Ensure the title exists (404 if not).
    await _ensure_title_exists(db, title_id)

    # Validate quality early; raises on invalid values.
    _ = _height_for_quality(payload.quality)
    _ = _tier_for_quality(payload.quality)

    # Normalize/validate language once.
    lang = _validate_language(payload.audio_language)

    # ── [Step 4] Idempotent replay (if header present) ──────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:streams:create:{title_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            # Replay snapshot as-is (already JSON-safe when stored)
            return _json(snap)

    # ── [Step 5] Resolve/create asset holder in a transaction ───────────────
    # Use a DB transaction for consistency across the asset+variant write.
    # Use a SAVEPOINT so this plays nicely if a transaction is already begun.
    async with db.begin_nested():  # commits on success, rolls back on exception
        asset_id = payload.asset_id
        asset_ref = None

        if asset_id is None:
            # Create a minimal VIDEO asset holder for the variant to bind to.
            asset = MediaAsset(
                title_id=title_id,
                kind=MediaAssetKind.VIDEO,
                language=lang,
                storage_key=f"streams/title/{title_id}/holder_{uuid4().hex}.meta",
            )
            db.add(asset)
            await db.flush()  # get asset.id
            asset_id = asset.id
            asset_ref = asset
        else:
            # Asset must exist, belong to the same title, and be suitable for video stream variants.
            a = (
                await db.execute(select(MediaAsset).where(MediaAsset.id == asset_id))
            ).scalar_one_or_none()
            if not a or a.title_id != title_id:
                raise HTTPException(
                    status_code=400, detail="asset_id not found for this title"
                )
            if a.kind != MediaAssetKind.VIDEO:
                raise HTTPException(
                    status_code=400, detail="asset_id is not a VIDEO asset"
                )
            asset_ref = a

        # Map quality → (height, tier) and derive flags.
        height = _height_for_quality(payload.quality)
        tier = _tier_for_quality(payload.quality)

        if payload.type == "hls":
            protocol = StreamProtocol.HLS
            container = Container.FMP4
            is_streamable, is_downloadable = True, False
        else:  # "mp4"
            protocol = StreamProtocol.MP4
            container = Container.MP4
            is_streamable, is_downloadable = False, True

        # Persist the variant.
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
            audio_language=lang,
            label=payload.label,
        )
        db.add(v)
        await db.flush()  # ensure `v.id` is populated
        try:
            if asset_ref is not None:
                await db.refresh(asset_ref)
        except Exception:
            pass

    # ── [Step 6] Serialize view model (JSON-safe) ───────────────────────────
    body = _serialize_stream(v)

    # ── [Step 7] Audit (best-effort) + idempotent snapshot ──────────────────
    try:
        await audit_log_service.log_audit_event(
            db,
            user=current_user,
            action="STREAM_CREATE",
            status="SUCCESS",
            request=request,
            meta_data={"stream_id": body["id"], "title_id": str(title_id)},
            commit=False,
        )
    except Exception:
        # Deliberately swallow audit failures so they don't affect the API result.
        pass

    if idem_key:
        try:
            # Store a JSON-safe snapshot for quick replay.
            await redis_wrapper.idempotency_set(
                idem_key, jsonable_encoder(body), ttl_seconds=600
            )
        except Exception:
            # Idempotency cache is best-effort; ignore storage errors.
            pass

    # ── [Step 8] Respond ────────────────────────────────────────────────────
    return _json(body)

# ─────────────────────────────────────────────────────────────────────────────
# 📋 List Stream Variants
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/titles/{title_id}/streams", summary="List variants for a title")
@rate_limit("30/minute")
async def list_streams(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    protocol: Optional[StreamProtocol] = Query(None, description="Filter by protocol (HLS/MP4)"),
    tier: Optional[StreamTier] = Query(None, description="Filter by stream tier (P480/P720/P1080)"),
    language: Optional[str] = Query(None, description="Filter by BCP‑47 audio language"),
    streamable: Optional[bool] = Query(None, description="Filter by streamable flag"),
    downloadable: Optional[bool] = Query(None, description="Filter by downloadable flag"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> JSONResponse:
    """List all stream variants attached to the given title (newest first)."""
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Build query ────────────────────────────────────────────────
    await _ensure_title_exists(db, title_id)
    stmt = (
        select(StreamVariant)
        .join(MediaAsset, StreamVariant.media_asset_id == MediaAsset.id)
        .where(MediaAsset.title_id == title_id)
        .order_by(StreamVariant.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    if protocol is not None:
        stmt = stmt.where(StreamVariant.protocol == protocol)
    if tier is not None:
        stmt = stmt.where(StreamVariant.stream_tier == tier)
    if language:
        stmt = stmt.where(func.lower(StreamVariant.audio_language) == _validate_language(language).lower())
    if streamable is not None:
        stmt = stmt.where(StreamVariant.is_streamable == bool(streamable))
    if downloadable is not None:
        stmt = stmt.where(StreamVariant.is_downloadable == bool(downloadable))

    rows = (await db.execute(stmt)).scalars().all() or []
    return _json([_serialize_stream(v) for v in rows])


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Patch Stream Variant
# ─────────────────────────────────────────────────────────────────────────────
@router.patch("/streams/{stream_id}", summary="Update stream flags / tier / labels")
@rate_limit("10/minute")
async def patch_stream(
    stream_id: UUID,
    payload: StreamPatchIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Patch streamability flags, tier, default flag, label, and audio language.

    Policy
    ------
    - Only **HLS** variants may be `is_streamable=True`.
    - When setting `is_streamable=True`, a `stream_tier` must be present (either
      in payload or already on the row).
    - Audio language must be a valid BCP‑47 tag when provided.

    Concurrency
    -----------
    Short **Redis** lock + **row‑level** SQL lock for safe updates.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Locked update ──────────────────────────────────────────────
    async with redis_wrapper.lock(f"lock:admin_streams:patch:{stream_id}", timeout=10, blocking_timeout=3):
        v = (await db.execute(select(StreamVariant).where(StreamVariant.id == stream_id).with_for_update())).scalar_one_or_none()
        if not v:
            raise HTTPException(status_code=404, detail="Stream not found")

        updates: Dict[str, Any] = {}
        if payload.is_streamable is not None:
            if payload.is_streamable and getattr(v, "protocol", None) != StreamProtocol.HLS:
                raise HTTPException(status_code=400, detail="Only HLS variants can be streamable")
            updates["is_streamable"] = bool(payload.is_streamable)
        if payload.is_downloadable is not None:
            updates["is_downloadable"] = bool(payload.is_downloadable)
        if payload.is_default is not None:
            updates["is_default"] = bool(payload.is_default)
        if payload.stream_tier is not None:
            updates["stream_tier"] = payload.stream_tier
        if payload.label is not None:
            updates["label"] = payload.label or None
        if payload.audio_language is not None:
            updates["audio_language"] = _validate_language(payload.audio_language)

        if updates.get("is_streamable"):
            # Ensure a tier exists when marking as streamable
            if not updates.get("stream_tier") and not getattr(v, "stream_tier", None):
                raise HTTPException(status_code=400, detail="stream_tier required when setting streamable")

        if not updates:
            raise HTTPException(status_code=400, detail="No changes provided")

        await db.execute(update(StreamVariant).where(StreamVariant.id == stream_id).values(**updates))
        await db.commit()

    try:
        await audit_log_service.log_audit_event(db, user=current_user, action="STREAM_PATCH", status="SUCCESS", request=request, meta_data={"stream_id": str(stream_id), "fields": list(updates.keys())})
    except Exception:
        pass

    v2 = (await db.execute(select(StreamVariant).where(StreamVariant.id == stream_id))).scalar_one_or_none()
    return _json(_serialize_stream(v2 or v))


# ─────────────────────────────────────────────────────────────────────────────
# 🗑️ Delete Stream Variant
# ─────────────────────────────────────────────────────────────────────────────
@router.delete("/streams/{stream_id}", summary="Delete a stream variant")
@rate_limit("10/minute")
async def delete_stream(
    stream_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Hard‑delete a stream variant row.

    Semantics
    ---------
    - First delete returns **200 OK**.
    - Subsequent attempts may return **404 Not Found**.
    - No storage deletion is necessary; variants reference external playlists/files.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Delete ─────────────────────────────────────────────────────
    found = (await db.execute(select(StreamVariant.id).where(StreamVariant.id == stream_id))).scalar_one_or_none()
    if not found:
        raise HTTPException(status_code=404, detail="Stream not found")

    await db.execute(delete(StreamVariant).where(StreamVariant.id == stream_id))
    await db.commit()

    try:
        await audit_log_service.log_audit_event(db, user=current_user, action="STREAM_DELETE", status="SUCCESS", request=request, meta_data={"stream_id": str(stream_id)})
    except Exception:
        pass

    return _json({"message": "Stream deleted"})
