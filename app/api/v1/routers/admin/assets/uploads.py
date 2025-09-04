"""
☁️ MoviesNow · Admin Uploads API (single & multipart, direct proxy)
===================================================================

Production‑grade, security‑hardened FastAPI routes for **admin uploads** under
`/api/v1/admin`. Supports S3 presigned single‑part uploads, multipart uploads,
and a small‑file direct proxy. Implements **MFA‑enforced admin** access,
**SlowAPI** rate limits, **idempotency** on create flows, **sensitive cache**
headers, and **audit logs** that never block the critical path.

Routes (6)
----------
- POST /api/v1/admin/uploads/init                      → Presigned PUT for single‑part upload
- POST /api/v1/admin/uploads/multipart/create          → Create multipart upload (returns uploadId + key)
- GET  /api/v1/admin/uploads/multipart/{uploadId}/part-url   → Presigned URL for a multipart part
- POST /api/v1/admin/uploads/multipart/{uploadId}/complete → Complete multipart upload
- POST /api/v1/admin/uploads/multipart/{uploadId}/abort    → Abort multipart upload
- POST /api/v1/admin/uploads/direct-proxy              → Direct proxy small files (≤ 10 MiB)

Security & Operations
---------------------
- **Admin‑only** + **MFA** checks on every route.
- **SlowAPI** per‑route rate limits; responses are `JSONResponse` for clean header injection.
- **Idempotency** via `Idempotency-Key` with Redis snapshot and deterministic keys.
- **Cache hardening** on presign responses (`Cache‑Control: no-store`).
- **Audit logs** emitted best‑effort; failures are swallowed.

Adjust imports/paths to match your project layout.
"""

# ─────────────────────────────────────────────────────────────────────────────
# 📦 Imports
# ─────────────────────────────────────────────────────────────────────────────
from typing import Optional, Dict, Any, List
from uuid import uuid4
import base64
import hashlib
import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.security_headers import set_sensitive_cache
import app.services.audit_log_service as audit_log_service

from app.db.models.user import User
from app.utils.aws import S3Client, S3StorageError

router = APIRouter(tags=["Admin • Uploads"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧰 Helpers & Constants
# ─────────────────────────────────────────────────────────────────────────────
MAX_DIRECT_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MiB

# Common MIME→ext mapping (extend as needed)
_EXT_MAP = {
    # images
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    # video
    "video/mp4": "mp4",
    "video/mpeg": "mpg",
    "video/webm": "webm",
    "video/quicktime": "mov",
    # text/docs
    "text/plain": "txt",
    "application/pdf": "pdf",
    "text/vtt": "vtt",
    "application/x-subrip": "srt",
}

_SAFE_SEG_RE = re.compile(r"[^A-Za-z0-9._-]")


def _json(data: Any, status_code: int = 200) -> JSONResponse:
    """Return JSONResponse with strict no‑store headers for admin responses."""
    return JSONResponse(data, status_code=status_code, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


def _ensure_s3() -> S3Client:
    try:
        return S3Client()
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))


def _ext_for_content_type(ct: str) -> str:
    return _EXT_MAP.get((ct or "").lower(), "bin")


def _sanitize_segment(s: Optional[str], fallback: str) -> str:
    """Single path segment sanitizer (letters/digits/._- only; spaces→underscore)."""
    s = (s or fallback).strip()
    s = re.sub(r"\s+", "_", s)
    s = _SAFE_SEG_RE.sub("", s)
    return s or fallback


def _safe_prefix(prefix: Optional[str], default: str) -> str:
    p = (prefix or default).strip("/ ")
    p = re.sub(r"[^\w./-]", "", p)
    return p or default


def _short_hash(value: str, *, length: int = 8) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:length]


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Schemas
# ─────────────────────────────────────────────────────────────────────────────
class UploadInitIn(BaseModel):
    content_type: str
    key_prefix: Optional[str] = Field("uploads/title", description="Base path prefix; sanitized")
    filename_hint: Optional[str] = None


class MultipartCreateIn(BaseModel):
    content_type: str
    key_prefix: Optional[str] = Field("uploads/multipart", description="Base path prefix; sanitized")
    filename_hint: Optional[str] = None


class MultipartCompleteIn(BaseModel):
    key: str
    parts: List[Dict[str, str]]  # [{ETag:"...", PartNumber:1}, ...]


class MultipartAbortIn(BaseModel):
    key: str


class DirectProxyIn(BaseModel):
    content_type: str
    data_base64: str
    key_prefix: Optional[str] = Field("uploads/direct", description="Base path prefix; sanitized")
    filename_hint: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# 🔗 Single‑part Presigned Upload
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/uploads/init", summary="Init single upload (presigned PUT)")
@rate_limit("20/minute")
async def uploads_init(
    payload: UploadInitIn | Dict[str, Any],
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Create a presigned **single‑part** PUT URL for arbitrary content.

    Steps
    -----
    1. AuthZ/MFA + cache hardening
    2. Build deterministic storage key (idempotency‑aware)
    3. Return presigned PUT URL
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # Normalize body
    if isinstance(payload, dict):
        payload = UploadInitIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Build deterministic key (idempotent) ───────────────────────
    s3 = _ensure_s3()
    ext = _ext_for_content_type(payload.content_type)
    prefix = _safe_prefix(payload.key_prefix, "uploads")

    idem_hdr = request.headers.get("Idempotency-Key") or uuid4().hex
    stem_hint = _sanitize_segment(payload.filename_hint, f"upload_{_short_hash(idem_hdr)}")
    key = f"{prefix}/{stem_hint}.{ext}"

    # Idempotent replay contract
    idem_key = f"idemp:admin:uploads:init:{key}:{idem_hdr}"
    snap = await redis_wrapper.idempotency_get(idem_key)
    if snap:
        return _json(snap)

    # ── [Step 3] Issue presigned URL ────────────────────────────────────────
    url = s3.presigned_put(key, content_type=payload.content_type, public=False)
    body = {"upload_url": url, "storage_key": key}

    try:
        await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
    except Exception:
        pass
    try:
        await audit_log_service.log_audit_event(None, user=current_user, action="UPLOAD_INIT", status="SUCCESS", request=request, meta_data={"storage_key": key})
    except Exception:
        pass

    return _json(body)


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Multipart: Create
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/uploads/multipart/create", summary="Create multipart upload (returns uploadId)")
@rate_limit("20/minute")
async def multipart_create(
    payload: MultipartCreateIn | Dict[str, Any],
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Initialize a **multipart** upload for large files and return an `uploadId` + `storage_key`.

    Deterministic key (when `Idempotency-Key` present) ensures replayability.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = MultipartCreateIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    s3 = _ensure_s3()
    ext = _ext_for_content_type(payload.content_type)
    prefix = _safe_prefix(payload.key_prefix, "uploads/multipart")

    idem_hdr = request.headers.get("Idempotency-Key") or uuid4().hex
    stem_hint = _sanitize_segment(payload.filename_hint, f"mup_{_short_hash(idem_hdr)}")
    key = f"{prefix}/{stem_hint}.{ext}"

    # Idempotency replay
    idem_key = f"idemp:admin:uploads:multipart:create:{key}:{idem_hdr}"
    snap = await redis_wrapper.idempotency_get(idem_key)
    if snap:
        return _json(snap)

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

    try:
        await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=3600)
    except Exception:
        pass
    try:
        await audit_log_service.log_audit_event(None, user=current_user, action="MULTIPART_CREATE", status="SUCCESS", request=request, meta_data={"storage_key": key, "upload_id": upload_id})
    except Exception:
        pass

    return _json(body)


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Multipart: Part URL
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/uploads/multipart/{uploadId}/part-url", summary="Presigned URL for a multipart part")
@rate_limit("60/minute")
async def multipart_part_url(
    uploadId: str,
    key: str,
    partNumber: int = Query(..., ge=1, le=10_000),
    request: Request = None,
    response: Response = None,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Return a presigned **PUT** URL for a specific multipart `partNumber`."""
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    if response is not None:
        set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    s3 = _ensure_s3()
    try:
        url = s3.client.generate_presigned_url(
            ClientMethod="upload_part",
            Params={"Bucket": s3.bucket, "Key": key, "UploadId": uploadId, "PartNumber": int(partNumber)},
            ExpiresIn=3600,
            HttpMethod="PUT",
        )
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Part URL failed: {e}")

    return _json({"upload_url": url})


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Multipart: Complete
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/uploads/multipart/{uploadId}/complete", summary="Complete multipart upload")
@rate_limit("20/minute")
async def multipart_complete(
    uploadId: str,
    payload: MultipartCompleteIn | Dict[str, Any],
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Complete a multipart upload by supplying `{ETag, PartNumber}` for each part."""
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = MultipartCompleteIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

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

    try:
        await audit_log_service.log_audit_event(None, user=current_user, action="MULTIPART_COMPLETE", status="SUCCESS", request=request, meta_data={"storage_key": payload.key, "upload_id": uploadId})
    except Exception:
        pass

    return _json({"message": "Upload complete", "storage_key": payload.key})


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Multipart: Abort
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/uploads/multipart/{uploadId}/abort", summary="Abort multipart upload")
@rate_limit("20/minute")
async def multipart_abort(
    uploadId: str,
    payload: MultipartAbortIn | Dict[str, Any],
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Abort a multipart upload."""
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = MultipartAbortIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    s3 = _ensure_s3()
    try:
        s3.client.abort_multipart_upload(Bucket=s3.bucket, Key=payload.key, UploadId=uploadId)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Abort failed: {e}")

    try:
        await audit_log_service.log_audit_event(None, user=current_user, action="MULTIPART_ABORT", status="SUCCESS", request=request, meta_data={"storage_key": payload.key, "upload_id": uploadId})
    except Exception:
        pass

    return _json({"message": "Upload aborted"})


# ─────────────────────────────────────────────────────────────────────────────
# 📤 Direct Proxy (Small Files)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/uploads/direct-proxy", summary="Direct proxy upload (small files)")
@rate_limit("20/minute")
async def direct_proxy_upload(
    payload: DirectProxyIn | Dict[str, Any],
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Directly proxy small files (≤ 10 MiB) into S3 by base64 payload.

    This is meant for tiny admin assets (icons, thumbnails). For larger files,
    prefer multipart uploads to avoid memory pressure.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = DirectProxyIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Decode + size guard ────────────────────────────────────────
    try:
        data = base64.b64decode(payload.data_base64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 payload")

    if len(data) > MAX_DIRECT_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 10 MiB)")

    s3 = _ensure_s3()
    ext = _ext_for_content_type(payload.content_type)
    prefix = _safe_prefix(payload.key_prefix, "uploads/direct")

    idem_hdr = request.headers.get("Idempotency-Key") or uuid4().hex
    stem_hint = _sanitize_segment(payload.filename_hint, f"direct_{_short_hash(idem_hdr)}")
    key = f"{prefix}/{stem_hint}.{ext}"

    try:
        s3.put_bytes(key, data, content_type=payload.content_type, public=False)
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))

    try:
        await audit_log_service.log_audit_event(None, user=current_user, action="DIRECT_UPLOAD_PROXY", status="SUCCESS", request=request, meta_data={"storage_key": key, "size": len(data)})
    except Exception:
        pass

    return _json({"storage_key": key})
