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
from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# 📦 Imports
# ─────────────────────────────────────────────────────────────────────────────
from typing import Optional, Dict, Any, List, Literal
from uuid import UUID, uuid4
import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, update, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

# Project‑specific deps (align to your app)
from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event

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


def _json(data: Any, status_code: int = 200) -> JSONResponse:
    """Return JSONResponse with strict no‑store headers for admin responses."""
    return JSONResponse(
        data,
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
    payload: StreamCreateIn | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Create a stream variant bound to a (new or provided) media asset.

    Rules
    -----
    - **HLS** → streamable (not downloadable), requires `stream_tier` (derived from quality).
    - **MP4** → downloadable (not streamable).
    - If `asset_id` omitted, a holder **MediaAsset(kind=VIDEO)** is created.

    Steps
    -----
    1. AuthZ/MFA + cache hardening
    2. Validate title and inputs (quality, url_path, language)
    3. Idempotency replay if provided
    4. Resolve/create asset
    5. Map quality → height/tier; derive flags from type
    6. Persist variant and commit
    7. Audit + idempotent snapshot
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # Normalize body
    if isinstance(payload, dict):
        payload = StreamCreateIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Validate inputs ────────────────────────────────────────────
    await _ensure_title_exists(db, title_id)
    _ = _height_for_quality(payload.quality)  # validates
    _ = _tier_for_quality(payload.quality)    # validates
    lang = _validate_language(payload.audio_language)

    # ── [Step 3] Idempotent replay ──────────────────────────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:streams:create:{title_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return _json(snap)

    # ── [Step 4] Resolve or create asset holder ─────────────────────────────
    asset_id = payload.asset_id
    if asset_id is None:
        asset = MediaAsset(
            title_id=title_id,
            kind=MediaAssetKind.VIDEO,
            language=lang,
            storage_key=f"streams/title/{title_id}/holder_{uuid4().hex}.meta",
        )
        db.add(asset)
        await db.flush()
        asset_id = asset.id
    else:
        # Validate that asset belongs to title and is of a compatible kind
        a = (await db.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one_or_none()
        if not a or a.title_id != title_id:
            raise HTTPException(status_code=400, detail="asset_id not found for this title")

    # ── [Step 5] Map quality → tier/height; derive flags from type ──────────
    height = _height_for_quality(payload.quality)
    tier = _tier_for_quality(payload.quality)

    if payload.type == "hls":
        protocol = StreamProtocol.HLS
        container = Container.FMP4
        is_streamable, is_downloadable = True, False
    else:  # mp4
        protocol = StreamProtocol.MP4
        container = Container.MP4
        is_streamable, is_downloadable = False, True

    # ── [Step 6] Persist variant ────────────────────────────────────────────
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
    await db.flush()
    await db.commit()

    body = _serialize_stream(v)

    # ── [Step 7] Audit + idempotent snapshot ────────────────────────────────
    try:
        await log_audit_event(db, user=current_user, action="STREAM_CREATE", status="SUCCESS", request=request, meta_data={"stream_id": body["id"], "title_id": str(title_id)})
    except Exception:
        pass
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass

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
        await log_audit_event(db, user=current_user, action="STREAM_PATCH", status="SUCCESS", request=request, meta_data={"stream_id": str(stream_id), "fields": list(updates.keys())})
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
        await log_audit_event(db, user=current_user, action="STREAM_DELETE", status="SUCCESS", request=request, meta_data={"stream_id": str(stream_id)})
    except Exception:
        pass

    return _json({"message": "Stream deleted"})
