"""
🧩 MoviesNow · Admin Assets: HEAD metadata & checksum
====================================================

Production‑grade, security‑hardened FastAPI routes to **inspect** and **finalize**
asset metadata stored in S3 and cached in DB.

Routes (3)
----------
- GET  /api/v1/admin/assets/{asset_id}/head      → HEAD S3 object; return size/content‑type/etag and cache in DB
- POST /api/v1/admin/assets/{asset_id}/checksum  → Store/verify asset SHA‑256 (server computes if small)
- POST /api/v1/admin/assets/{asset_id}/finalize  → Finalize metadata (size/content‑type/checksum) after upload

Security & Operations
---------------------
- **Admin‑only** + **MFA** enforced on all endpoints.
- **SlowAPI** per‑route rate limits.
- **Sensitive cache headers** on responses.
- **Redis lock** around checksum writes to avoid concurrent updates.
- **Audit logs** are best‑effort and never block the request path.
- Explicit `JSONResponse` returns to cooperate with SlowAPI header injection.

Adjust imports/paths for your project.
"""
from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# 📦 Imports
# ─────────────────────────────────────────────────────────────────────────────
from typing import Optional, Any, Dict
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.db.models.user import User
from app.db.models.media_asset import MediaAsset
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event
from app.utils.aws import S3Client, S3StorageError

router = APIRouter(tags=["Admin • Assets"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧰 Helpers
# ─────────────────────────────────────────────────────────────────────────────
SMALL_COMPUTE_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB


def _json(data: Any, status_code: int = 200) -> JSONResponse:
    """Return JSONResponse with strict no‑store headers for admin responses."""
    return JSONResponse(data, status_code=status_code, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


def _ensure_s3() -> S3Client:
    try:
        return S3Client()
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))


def _is_hex_sha256(s: str) -> bool:
    s = (s or "").strip().lower()
    if len(s) != 64:
        return False
    try:
        int(s, 16)
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Schemas
# ─────────────────────────────────────────────────────────────────────────────
class ChecksumIn(BaseModel):
    sha256: Optional[str] = Field(None, description="Client‑provided SHA‑256 hex (optional if server computes)")
    force: bool = Field(False, description="If true, overwrite existing checksum")


class FinalizeAssetIn(BaseModel):
    size_bytes: Optional[int] = Field(None, ge=0)
    content_type: Optional[str] = None
    sha256: Optional[str] = None
    force: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# 🔎 Assets: HEAD metadata (size, content‑type, etag)
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/assets/{asset_id}/head", summary="Fetch S3 HEAD metadata and cache in DB")
@rate_limit("60/minute")
async def assets_head(
    asset_id: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """HEAD the underlying S3 object and cache key metadata in DB.

    Returns
    -------
    JSON with: `size_bytes`, `content_type`, `etag`, and `storage_key`.

    Steps
    -----
    1) AuthZ/MFA + cache hardening
    2) Fetch asset; validate presence of `storage_key`
    3) S3 **HeadObject**; extract `ContentLength`, `ContentType`, `ETag`
    4) Persist `bytes_size`/`mime_type` cache to DB (best‑effort)
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Load asset ─────────────────────────────────────────────────
    m = (await db.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one_or_none()
    if not m:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not m.storage_key:
        raise HTTPException(status_code=400, detail="Asset missing storage_key")

    # ── [Step 3] S3 HEAD ────────────────────────────────────────────────────
    s3 = _ensure_s3()
    try:
        head = s3.client.head_object(Bucket=s3.bucket, Key=m.storage_key)  # type: ignore[attr-defined]
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"HEAD failed: {e}")

    size = int(head.get("ContentLength", 0))
    ctype = head.get("ContentType")
    etag = (head.get("ETag") or "").strip('"')

    # ── [Step 4] Cache in DB ────────────────────────────────────────────────
    try:
        await db.execute(
            update(MediaAsset)
            .where(MediaAsset.id == asset_id)
            .values(bytes_size=size or None, mime_type=ctype or None)
        )
        await db.commit()
    except Exception:
        # Non‑fatal — return live data regardless
        pass

    body = {"size_bytes": size, "content_type": ctype, "etag": etag, "storage_key": m.storage_key}

    try:
        await log_audit_event(db, user=current_user, action="ASSET_HEAD", status="SUCCESS", request=request, meta_data={"asset_id": str(asset_id)})
    except Exception:
        pass

    return _json(body)


# ─────────────────────────────────────────────────────────────────────────────
# ✅ Assets: checksum (store/verify)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/assets/{asset_id}/checksum", summary="Store/verify asset SHA‑256")
@rate_limit("30/minute")
async def assets_checksum(
    asset_id: str,
    payload: ChecksumIn | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Store or verify an asset's **SHA‑256**.

    Behavior
    --------
    - If `sha256` is **absent**, the server will compute it **only** for small
      objects (≤ 10 MiB). Larger objects must provide the checksum.
    - When a checksum already exists, it is **not** overwritten unless `force=true`.

    Returns `{"sha256": ..., "status": "UPDATED"|"UNCHANGED"}`.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = ChecksumIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Load asset ─────────────────────────────────────────────────
    m = (await db.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one_or_none()
    if not m:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not m.storage_key:
        raise HTTPException(status_code=400, detail="Asset missing storage_key")

    # ── [Step 3] Optional server‑side compute ────────────────────────────────
    sha = (payload.sha256 or "").strip().lower()

    if not sha:
        # Discover size (prefer DB cache, else HEAD)
        size = int(getattr(m, "bytes_size", 0) or 0)
        if size <= 0:
            try:
                s3 = _ensure_s3()
                head = s3.client.head_object(Bucket=s3.bucket, Key=m.storage_key)  # type: ignore[attr-defined]
                size = int(head.get("ContentLength", 0))
            except Exception:
                size = 0
        if not size or size > SMALL_COMPUTE_MAX_BYTES:
            raise HTTPException(status_code=400, detail="Provide sha256 for large assets (>10MB)")
        # Compute by downloading
        try:
            s3 = _ensure_s3()
            obj = s3.client.get_object(Bucket=s3.bucket, Key=m.storage_key)  # type: ignore[attr-defined]
            data = obj["Body"].read()
            sha = hashlib.sha256(data).hexdigest()
        except Exception as e:
            raise HTTPException(status_code=503, detail=f"Checksum compute failed: {e}")

    if not _is_hex_sha256(sha):
        raise HTTPException(status_code=400, detail="Invalid sha256 hex")

    # ── [Step 4] Persist (with short lock) ───────────────────────────────────
    async with redis_wrapper.lock(f"lock:asset:checksum:{asset_id}", timeout=10, blocking_timeout=3):
        fresh = (await db.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one_or_none()
        if fresh and getattr(fresh, "checksum_sha256", None) and not payload.force:
            return _json({"sha256": fresh.checksum_sha256, "status": "UNCHANGED"})
        await db.execute(
            update(MediaAsset).where(MediaAsset.id == asset_id).values(checksum_sha256=sha)
        )
        await db.commit()

    try:
        await log_audit_event(db, user=current_user, action="ASSET_CHECKSUM", status="UPDATED", request=request, meta_data={"asset_id": str(asset_id)})
    except Exception:
        pass

    return _json({"sha256": sha, "status": "UPDATED"})


# ─────────────────────────────────────────────────────────────────────────────
# 🧮 Assets: finalize metadata (size/type/checksum)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/assets/{asset_id}/finalize", summary="Finalize asset metadata after upload")
@rate_limit("30/minute")
async def assets_finalize(
    asset_id: str,
    payload: FinalizeAssetIn | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Finalize metadata after upload.

    Fields
    ------
    - `size_bytes` ≥ 0 (optional)
    - `content_type` (optional)
    - `sha256` (optional; respects `force` like the checksum endpoint)

    Steps
    -----
    1) AuthZ/MFA + cache hardening
    2) Validate/update fields; do **not** overwrite checksum unless `force=true`
    3) Commit and return the updated projection
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = FinalizeAssetIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Prepare updates ────────────────────────────────────────────
    updates: Dict[str, Any] = {}
    if payload.size_bytes is not None:
        if payload.size_bytes < 0:
            raise HTTPException(status_code=400, detail="size_bytes must be >= 0")
        updates["bytes_size"] = int(payload.size_bytes)
    if payload.content_type is not None:
        updates["mime_type"] = payload.content_type
    if payload.sha256:
        if not _is_hex_sha256(payload.sha256):
            raise HTTPException(status_code=400, detail="Invalid sha256 hex")
        # Only overwrite when empty or forced
        current = (await db.execute(select(MediaAsset.checksum_sha256).where(MediaAsset.id == asset_id))).scalar_one_or_none()
        if not current or payload.force:
            updates["checksum_sha256"] = payload.sha256.strip().lower()

    if updates:
        await db.execute(update(MediaAsset).where(MediaAsset.id == asset_id).values(**updates))
        await db.commit()

    try:
        await log_audit_event(db, user=current_user, action="ASSET_FINALIZE", status="SUCCESS", request=request, meta_data={"asset_id": str(asset_id), "fields": list(updates.keys())})
    except Exception:
        pass

    return _json({"id": str(asset_id), **updates})
