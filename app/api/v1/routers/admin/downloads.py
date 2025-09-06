# app/api/v1/routers/admin_downloads.py
#
#  🛠️📥 MoviesNow · Admin Downloads
#
#  Purpose: Curate downloadable MP4 variants and reconcile S3 inventory.
#
#  Endpoints (admin-only; MFA; rate-limited; no-store):
#   - POST  /titles/{title_id}/downloads/register           → Upsert Title
#   - POST  /titles/{title_id}/episodes/{episode_id}/...    → Upsert Ep
#   - PATCH /streams/{variant_id}/toggle-downloadable       → Toggle flag
#   - GET   /titles/{title_id}/downloads/inventory          → S3 vs DB
#
#  Policy
#  - All registered assets **must** live under `downloads/` namespace.
#  - Only progressive MP4 (or similar) should be flagged downloadable.
#  - Registration is **idempotent**: existing variants are updated.
#
#  Security & Ops
#  - Requires Admin + MFA; per-route rate limits.
#  - `Cache-Control: no-store` for admin responses.
#  - Neutral errors; no sensitive storage internals leaked.
#

from __future__ import annotations

from typing import Optional, Dict, Any, List, Tuple
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Response,
    Path,
    Query,
    status,
)
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import rate_limit
from app.db.session import get_async_db
from app.db.models.title import Title
from app.db.models.episode import Episode
from app.db.models.media_asset import MediaAsset
from app.db.models.stream_variant import StreamVariant
from app.schemas.enums import StreamProtocol, Container, VideoCodec, AudioCodec
from app.security_headers import set_sensitive_cache
from app.utils.aws import S3Client
from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa

router = APIRouter(tags=["Admin · Downloads"])

__all__ = ["router"]

# ─────────────────────────────────────────────────────────────────────────────
# 📚 Pydantic models (request/response)
# ─────────────────────────────────────────────────────────────────────────────

class RegisterDownloadIn(BaseModel):
    storage_key: str = Field(
        ...,
        description="Object key under downloads/ namespace (e.g., downloads/{title_id}/.../file.mp4)",
    )
    width: Optional[int] = Field(None, ge=1)
    height: Optional[int] = Field(None, ge=1)
    bandwidth_bps: Optional[int] = Field(None, ge=1, description="Approx bitrate in bits per second.")
    container: Optional[Container] = Field(None, description="MP4 recommended.")
    video_codec: Optional[VideoCodec] = Field(None, description="H264 recommended.")
    audio_codec: Optional[AudioCodec] = Field(None, description="AAC recommended.")
    audio_language: Optional[str] = Field(None, description="IETF BCP 47 (e.g., 'en', 'hi').")
    label: Optional[str] = Field(None, description="Curator label (e.g., 'Director Cut').")
    sha256: Optional[str] = Field(None, description="Optional hex SHA-256 checksum for integrity.")


class RegisterDownloadOut(BaseModel):
    message: str
    variant_id: str
    storage_key: str
    created: bool = Field(..., description="True if a new variant was created, False if updated.")
    s3_exists: Optional[bool] = Field(None, description="Whether the object exists in storage (best-effort HEAD).")


class ToggleDownloadableOut(BaseModel):
    message: str
    variant_id: str
    is_downloadable: bool


class InventoryMatchOut(BaseModel):
    key: str
    variant_id: str
    height: Optional[int] = None
    width: Optional[int] = None


class InventoryS3OnlyOut(BaseModel):
    key: str
    size_bytes: int
    last_modified: Optional[str] = None
    etag: Optional[str] = None


class InventoryDBOnlyOut(BaseModel):
    variant_id: str
    url_path: str
    height: Optional[int] = None
    width: Optional[int] = None


class TitleDownloadsInventoryOut(BaseModel):
    title_id: str
    prefix: str
    counts: Dict[str, int]
    matches: List[InventoryMatchOut]
    s3_only: List[InventoryS3OnlyOut]
    db_only: List[InventoryDBOnlyOut]
    next_token: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# ⚙️ Helpers & validation
# ─────────────────────────────────────────────────────────────────────────────

_ALLOWED_DOWNLOAD_EXTS = (".mp4", ".m4v", ".mov", ".webm", ".zip")


def _allowed_download_ext(key: str) -> bool:
    k = key.lower()
    return any(k.endswith(ext) for ext in _ALLOWED_DOWNLOAD_EXTS)


def _ensure_downloads_key(key: str) -> str:
    """
    Validate and normalize a downloads/ storage key.
    - Must start with 'downloads/'
    - Must not contain path traversal ('..')
    - Must use an allowed extension (to reduce noise)
    """
    k = (key or "").strip().lstrip("/")
    if not k.startswith("downloads/"):
        raise HTTPException(status_code=400, detail="storage_key must be under downloads/")
    if ".." in k.split("/"):
        raise HTTPException(status_code=400, detail="storage_key may not contain parent directory segments")
    if not _allowed_download_ext(k):
        raise HTTPException(status_code=400, detail=f"storage_key must end with one of: {', '.join(_ALLOWED_DOWNLOAD_EXTS)}")
    return k


async def _get_or_create_asset_for_title(db: AsyncSession, title_id: UUID, storage_key: str) -> MediaAsset:
    exists = (
        await db.execute(
            select(MediaAsset).where(MediaAsset.title_id == title_id, MediaAsset.storage_key == storage_key)
        )
    ).scalars().first()
    if exists:
        return exists
    asset = MediaAsset(title_id=title_id)
    setattr(asset, "storage_key", storage_key)
    db.add(asset)
    await db.flush()
    return asset


async def _get_or_create_asset_for_episode(db: AsyncSession, episode: Episode, storage_key: str) -> MediaAsset:
    exists = (
        await db.execute(
            select(MediaAsset).where(
                MediaAsset.title_id == episode.title_id,
                MediaAsset.season_id == episode.season_id,
                MediaAsset.episode_id == episode.id,
                MediaAsset.storage_key == storage_key,
            )
        )
    ).scalars().first()
    if exists:
        return exists
    asset = MediaAsset(title_id=episode.title_id, season_id=episode.season_id, episode_id=episode.id)
    setattr(asset, "storage_key", storage_key)
    db.add(asset)
    await db.flush()
    return asset


def _apply_variant_fields(v: StreamVariant, payload: RegisterDownloadIn) -> None:
    """Apply/refresh user-supplied technical metadata on a variant."""
    v.protocol = StreamProtocol.MP4
    v.url_path = payload.storage_key.lstrip("/")
    v.container = payload.container or Container.MP4
    v.video_codec = payload.video_codec or VideoCodec.H264
    v.audio_codec = payload.audio_codec or AudioCodec.AAC
    v.width = payload.width
    v.height = payload.height
    v.bandwidth_bps = payload.bandwidth_bps
    v.label = payload.label
    if hasattr(v, "is_downloadable"):
        setattr(v, "is_downloadable", True)


def _is_hex_sha256(s: Optional[str]) -> bool:
    s = (s or "").strip().lower()
    if len(s) != 64:
        return False
    try:
        int(s, 16)
        return True
    except Exception:
        return False


async def _upsert_variant(
    db: AsyncSession,
    asset: MediaAsset,
    payload: RegisterDownloadIn,
) -> Tuple[StreamVariant, bool]:
    """
    Create or update a StreamVariant for the given asset and url_path.
    Returns (variant, created).
    """
    existing = (
        await db.execute(
            select(StreamVariant).where(
                StreamVariant.media_asset_id == asset.id,
                StreamVariant.url_path == payload.storage_key.lstrip("/"),
                StreamVariant.protocol == StreamProtocol.MP4,
            )
        )
    ).scalars().first()

    if existing:
        _apply_variant_fields(existing, payload)
        created = False
        v = existing
    else:
        v = StreamVariant(media_asset_id=asset.id)
        _apply_variant_fields(v, payload)
        db.add(v)
        created = True

    await db.flush()
    return v, created


def _best_effort_s3_head(key: str) -> Optional[bool]:
    """Return True/False if exists check succeeds, or None if the HEAD fails for operational reasons."""
    try:
        s3 = S3Client()
        s3.client.head_object(Bucket=s3.bucket, Key=key)  # type: ignore[attr-defined]
        return True
    except Exception:
        # Intentionally swallow to avoid leaking internals
        return None


# ╔════════════════════════════════ Route: Register Title Download ═══════════╗
# ║ 🧱🧩  POST /titles/{title_id}/downloads/register                           ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
@router.post(
    "/titles/{title_id}/downloads/register",
    summary="Register (upsert) a title-level downloadable file",
    response_model=RegisterDownloadOut,
    responses={
        201: {"description": "Created"},
        200: {"description": "Updated"},
        400: {"description": "Validation error"},
        401: {"description": "Unauthorized (admin/MFA)"},
        403: {"description": "Forbidden"},
        404: {"description": "Title not found"},
        503: {"description": "S3 error (neutral)"},
    },
)
@rate_limit("20/minute")
async def register_title_download(
    title_id: UUID = Path(..., description="Title ID (UUID)."),
    payload: RegisterDownloadIn = ...,
    request: Request = ...,
    response: Response = ...,
    db: AsyncSession = Depends(get_async_db),
    _adm=Depends(_ensure_admin),
    _mfa=Depends(_ensure_mfa),
) -> RegisterDownloadOut:
    """
    Upsert a **downloadable** progressive file for a *title* scope.

    Semantics
    ---------
    * Ensures key is under `downloads/` with an allowed extension.
    * If a variant with the same `url_path` exists, it's **updated** in place.
    * Sets `is_downloadable=True` when supported by the model.

    Notes
    -----
    * Performs best-effort HEAD to check object existence (no failure on miss).
    """
    set_sensitive_cache(response)  # no-store

    key = _ensure_downloads_key(payload.storage_key)

    t = (await db.execute(select(Title).where(Title.id == title_id))).scalars().first()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")

    s3_exists = _best_effort_s3_head(key)

    asset = await _get_or_create_asset_for_title(db, title_id, key)
    # Optionally persist checksum on the asset for integrity tracking
    if payload.sha256:
        sha = payload.sha256.strip().lower()
        if not _is_hex_sha256(sha):
            raise HTTPException(status_code=400, detail="Invalid sha256 hex")
        try:
            # Only set if empty to avoid unintended overwrites
            if not getattr(asset, "checksum_sha256", None):
                setattr(asset, "checksum_sha256", sha)
        except Exception:
            # Defensive: don't block registration on attribute assignment in odd ORM configs
            pass

    v, created = await _upsert_variant(db, asset, payload)
    await db.commit()

    # Dynamic 201 on creation; 200 on update
    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK

    return RegisterDownloadOut(
        message="registered" if created else "updated",
        variant_id=str(getattr(v, "id", "")),
        storage_key=key,
        created=created,
        s3_exists=s3_exists,
    )


# ╔═══════════════════════════════ Route: Register Episode Download ══════════╗
# ║ 🧱🎬  POST /titles/{title_id}/episodes/{episode_id}/downloads/register     ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
@router.post(
    "/titles/{title_id}/episodes/{episode_id}/downloads/register",
    summary="Register (upsert) an episode-level downloadable file",
    response_model=RegisterDownloadOut,
    responses={
        201: {"description": "Created"},
        200: {"description": "Updated"},
        400: {"description": "Validation error"},
        401: {"description": "Unauthorized (admin/MFA)"},
        403: {"description": "Forbidden"},
        404: {"description": "Episode not found"},
        503: {"description": "S3 error (neutral)"},
    },
)
@rate_limit("20/minute")
async def register_episode_download(
    title_id: UUID = Path(..., description="Title ID (UUID)."),
    episode_id: UUID = Path(..., description="Episode ID (UUID)."),
    payload: RegisterDownloadIn = ...,
    request: Request = ...,
    response: Response = ...,
    db: AsyncSession = Depends(get_async_db),
    _adm=Depends(_ensure_admin),
    _mfa=Depends(_ensure_mfa),
) -> RegisterDownloadOut:
    """
    Upsert a **downloadable** progressive file for an *episode* scope.

    Behavior
    --------
    * Asset is created under the episode lineage (title/season/episode).
    * Existing variant with same `url_path` is updated (idempotent).

    Safety
    ------
    * Validates `downloads/` namespace and allowed file types.
    * Best-effort HEAD to probe existence (optional).
    """
    set_sensitive_cache(response)  # no-store

    key = _ensure_downloads_key(payload.storage_key)

    ep = (
        await db.execute(select(Episode).where(Episode.id == episode_id, Episode.title_id == title_id))
    ).scalars().first()
    if not ep:
        raise HTTPException(status_code=404, detail="Episode not found")

    s3_exists = _best_effort_s3_head(key)

    asset = await _get_or_create_asset_for_episode(db, ep, key)
    # Optionally persist checksum on the asset for integrity tracking
    if payload.sha256:
        sha = payload.sha256.strip().lower()
        if not _is_hex_sha256(sha):
            raise HTTPException(status_code=400, detail="Invalid sha256 hex")
        try:
            if not getattr(asset, "checksum_sha256", None):
                setattr(asset, "checksum_sha256", sha)
        except Exception:
            pass

    v, created = await _upsert_variant(db, asset, payload)
    await db.commit()

    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK

    return RegisterDownloadOut(
        message="registered" if created else "updated",
        variant_id=str(getattr(v, "id", "")),
        storage_key=key,
        created=created,
        s3_exists=s3_exists,
    )


# ╔══════════════════════════════ Route: Toggle Downloadable Flag ════════════╗
# ║ 🎛️🔐  PATCH /streams/{variant_id}/toggle-downloadable                      ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
@router.patch(
    "/streams/{variant_id}/toggle-downloadable",
    summary="Toggle is_downloadable on a stream variant",
    response_model=ToggleDownloadableOut,
    responses={
        200: {"description": "OK"},
        400: {"description": "Variant does not support downloadable flag"},
        401: {"description": "Unauthorized (admin/MFA)"},
        403: {"description": "Forbidden"},
        404: {"description": "Variant not found"},
    },
)
@rate_limit("30/minute")
async def toggle_downloadable(
    variant_id: UUID = Path(..., description="StreamVariant ID (UUID)."),
    request: Request = ...,
    response: Response = ...,
    db: AsyncSession = Depends(get_async_db),
    _adm=Depends(_ensure_admin),
    _mfa=Depends(_ensure_mfa),
) -> ToggleDownloadableOut:
    """
    Flip the `is_downloadable` flag on a variant (when supported by the model).

    Notes
    -----
    * No validation of container/codec here; registration enforces those.
    * Returns the new flag state after persistence.
    """
    set_sensitive_cache(response)  # no-store

    v = (await db.execute(select(StreamVariant).where(StreamVariant.id == variant_id))).scalars().first()
    if not v:
        raise HTTPException(status_code=404, detail="Variant not found")
    if not hasattr(v, "is_downloadable"):
        raise HTTPException(status_code=400, detail="Variant does not support downloadable flag")

    setattr(v, "is_downloadable", not bool(getattr(v, "is_downloadable")))
    await db.commit()
    return ToggleDownloadableOut(
        message="ok",
        variant_id=str(variant_id),
        is_downloadable=bool(getattr(v, "is_downloadable")),
    )


# ╔══════════════════════════════ Route: Title Downloads Inventory ═══════════╗
# ║ 🧭📦  GET /titles/{title_id}/downloads/inventory                           ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
@router.get(
    "/titles/{title_id}/downloads/inventory",
    summary="Reconcile S3 downloads/ keys with DB variants (title scope)",
    response_model=TitleDownloadsInventoryOut,
    responses={
        200: {"description": "OK"},
        400: {"description": "Bad prefix"},
        401: {"description": "Unauthorized (admin/MFA)"},
        403: {"description": "Forbidden"},
        503: {"description": "S3 error (neutral)"},
    },
)
@rate_limit("10/minute")
async def title_downloads_inventory(
    title_id: UUID = Path(..., description="Title ID (UUID)."),
    request: Request = ...,
    response: Response = ...,
    prefix: Optional[str] = Query(
        None,
        description="Override prefix; defaults to downloads/{title_id}/",
    ),
    limit: int = Query(1000, ge=1, le=1000, description="Max objects per page."),
    continuation_token: Optional[str] = Query(None, description="S3 pagination token."),
    db: AsyncSession = Depends(get_async_db),
    _adm=Depends(_ensure_admin),
    _mfa=Depends(_ensure_mfa),
) -> TitleDownloadsInventoryOut:
    """
    List objects under `downloads/{title_id}/...` in S3 and compare against DB
    `StreamVariant` rows (`protocol=MP4`, `url_path` starts with the prefix).

    Output
    ------
    * `matches`: Objects that correspond to a DB variant (by exact `url_path`).
    * `s3_only`: Objects present in S3 without a matching DB variant.
    * `db_only`: Variants in DB that have no corresponding S3 object.

    Notes
    -----
    * Only allowed file extensions are considered (to reduce noise).
    * S3 errors are surfaced as HTTP 503 with a neutral message.
    """
    set_sensitive_cache(response)  # no-store

    pfx_default = f"downloads/{title_id}/"
    pfx = (prefix or pfx_default).lstrip("/")
    if not pfx.startswith(pfx_default):
        raise HTTPException(status_code=400, detail="prefix must start with downloads/{title_id}/")

    # S3 listing (paginated)
    s3 = S3Client()
    client = s3.client
    s3_keys: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {"Bucket": s3.bucket, "Prefix": pfx, "MaxKeys": limit}
    if continuation_token:
        kwargs["ContinuationToken"] = continuation_token
    try:
        resp = client.list_objects_v2(**kwargs)  # type: ignore[attr-defined]
    except Exception:
        raise HTTPException(status_code=503, detail="S3 list error")

    for obj in (resp.get("Contents") or []):
        key = obj.get("Key")
        if not key or not key.startswith(pfx):
            continue
        if not _allowed_download_ext(key):
            continue
        s3_keys.append(
            {
                "key": key,
                "size_bytes": int(obj.get("Size") or 0),
                "last_modified": obj.get("LastModified").isoformat() if obj.get("LastModified") else None,
                "etag": obj.get("ETag"),
            }
        )

    next_token = resp.get("NextContinuationToken")

    # DB variants scoped by prefix
    db_rows = (
        await db.execute(
            select(StreamVariant).where(
                StreamVariant.protocol == StreamProtocol.MP4,
                StreamVariant.url_path.like(pfx + "%"),
            )
        )
    ).scalars().all()

    db_index = {getattr(v, "url_path") or "": v for v in db_rows}
    s3_index = {item["key"]: item for item in s3_keys}

    matches: List[InventoryMatchOut] = []
    s3_only: List[InventoryS3OnlyOut] = []
    db_only: List[InventoryDBOnlyOut] = []

    for key, item in s3_index.items():
        v = db_index.get(key)
        if v is not None:
            matches.append(
                InventoryMatchOut(
                    key=key,
                    variant_id=str(getattr(v, "id", "")),
                    height=getattr(v, "height", None),
                    width=getattr(v, "width", None),
                )
            )
        else:
            s3_only.append(
                InventoryS3OnlyOut(
                    key=item["key"],
                    size_bytes=item["size_bytes"],
                    last_modified=item["last_modified"],
                    etag=item["etag"],
                )
            )

    for url_path, v in db_index.items():
        if url_path not in s3_index:
            db_only.append(
                InventoryDBOnlyOut(
                    variant_id=str(getattr(v, "id", "")),
                    url_path=url_path,
                    height=getattr(v, "height", None),
                    width=getattr(v, "width", None),
                )
            )

    return TitleDownloadsInventoryOut(
        title_id=str(title_id),
        prefix=pfx,
        counts={"s3": len(s3_keys), "db": len(db_rows), "matches": len(matches)},
        matches=matches,
        s3_only=s3_only,
        db_only=db_only,
        next_token=next_token,
    )
