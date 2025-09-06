"""
📦 MoviesNow · Admin Uploads API (single & multipart, direct proxy)
==================================================================

Production-grade, security-hardened FastAPI routes for **admin uploads** under
`/api/v1/admin`. Supports S3 presigned single-part uploads, multipart uploads,
and a small-file direct proxy. Implements **MFA-enforced admin** access,
**SlowAPI** rate limits, **idempotency** on create flows, **sensitive cache**
headers, and **audit logs** that never block the critical path.

Routes (6)
----------
- POST /api/v1/admin/uploads/init                           → Presigned PUT for single-part upload
- POST /api/v1/admin/uploads/multipart/create               → Create multipart upload (returns uploadId + key)
- GET  /api/v1/admin/uploads/multipart/{uploadId}/part-url  → Presigned URL for a multipart part
- POST /api/v1/admin/uploads/multipart/{uploadId}/complete  → Complete multipart upload
- POST /api/v1/admin/uploads/multipart/{uploadId}/abort     → Abort multipart upload
- POST /api/v1/admin/uploads/direct-proxy                   → Direct proxy small files (≤ 10 MiB)

Security & Operations
---------------------
- **Admin-only** + **MFA** checks on every route.
- **SlowAPI** per-route rate limits; responses are `JSONResponse` for clean header injection.
- **Idempotency** via `Idempotency-Key` with Redis snapshot and deterministic keys.
- **Cache hardening** on presign responses (`Cache-Control: no-store`).
- **Audit logs** emitted best-effort; failures are swallowed.

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
from app.services.audit_log_service import log_audit_event

from app.db.models.user import User
from app.utils.aws import S3Client, S3StorageError

router = APIRouter(tags=["Admin • Uploads"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧰 Helpers & Constants
# ─────────────────────────────────────────────────────────────────────────────
MAX_DIRECT_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_PARTS = 10_000

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
    "video/mp2t": "ts",
    "video/iso.segment": "m4s",
    # text/docs/captions/hls
    "text/plain": "txt",
    "application/pdf": "pdf",
    "text/vtt": "vtt",
    "application/x-subrip": "srt",
    "application/vnd.apple.mpegurl": "m3u8",
    "application/x-mpegurl": "m3u8",
}

_SAFE_SEG_RE = re.compile(r"[^A-Za-z0-9._-]")


def _json(data: Any, status_code: int = 200) -> JSONResponse:
    """Return JSONResponse with strict no-store headers for admin responses."""
    return JSONResponse(
        data,
        status_code=status_code,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _ensure_s3() -> S3Client:
    """Construct an S3 client or raise 503 if not available."""
    try:
        return S3Client()
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))


def _ext_for_content_type(ct: str) -> str:
    """Map a content-type to a safe file extension; fallback to .bin."""
    return _EXT_MAP.get((ct or "").lower(), "bin")


def _default_cache_control(ct: str) -> str:
    """
    Recommend a `Cache-Control` based on content type.

    These defaults should match your CloudFront cache policies.
    """
    ct = (ct or "").lower()

    # HLS playlists are short-lived
    if ct in ("application/vnd.apple.mpegurl", "application/x-mpegurl"):
        return "public,max-age=30"

    # TS/segments immutable for a week
    if ct in ("video/mp2t", "video/iso.segment"):
        return "public,max-age=604800,immutable"

    # Subtitles are text, moderate cache
    if ct in ("text/vtt", "application/x-subrip"):
        return "public,max-age=86400"

    # Images default long cache
    if ct.startswith("image/"):
        return "public,max-age=2592000"

    # Safe default for unknowns
    return "public,max-age=3600"


def _sanitize_segment(s: Optional[str], fallback: str) -> str:
    """
    Sanitize a single path segment.

    - Spaces collapse to underscore
    - Only letters, digits, dot, underscore, hyphen are kept
    - Returns `fallback` if result is empty
    """
    s = (s or fallback).strip()
    s = re.sub(r"\s+", "_", s)
    s = _SAFE_SEG_RE.sub("", s)
    return s or fallback


def _safe_prefix(prefix: Optional[str], default: str) -> str:
    """
    Sanitize a user-supplied prefix **without** performing path resolution.

    Rules
    -----
    - Remove leading slashes and backslashes
    - Drop empty segments and traversal tokens ('.', '..') instead of resolving
    - Keep only [A-Za-z0-9_.-] per segment; strip other characters
    - Collapse multiple slashes

    Examples
    --------
    '/bad//prefix/../ok'  → 'bad/prefix/ok'
    '   uploads/title  '  → 'uploads/title'
    """
    raw = (prefix or default).replace("\\", "/")
    parts: List[str] = []
    for seg in raw.split("/"):
        if not seg or seg in (".", ".."):
            continue
        seg = re.sub(r"[^\w.-]", "", seg)
        if seg:
            parts.append(seg)
    p = "/".join(parts)
    return p or default


def _short_hash(value: str, *, length: int = 8) -> str:
    """Short, deterministic SHA-1 hash (hex)."""
    import hashlib as _hashlib
    return _hashlib.sha1(value.encode("utf-8")).hexdigest()[:length]


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Schemas
# ─────────────────────────────────────────────────────────────────────────────
class UploadInitIn(BaseModel):
    """Input for single-part upload initialization."""
    content_type: str
    key_prefix: Optional[str] = Field("uploads/title", description="Base path prefix; sanitized")
    filename_hint: Optional[str] = None
    cache_control: Optional[str] = Field(None, description="Override Cache-Control stored on object")
    content_disposition: Optional[str] = Field(None, description="Optional Content-Disposition")


class UploadInitOut(BaseModel):
    upload_url: str
    storage_key: str
    headers: Dict[str, str]
    cdn_url: Optional[str] = None


class MultipartCreateIn(BaseModel):
    """Input to create a multipart upload."""
    content_type: str
    key_prefix: Optional[str] = Field("uploads/multipart", description="Base path prefix; sanitized")
    filename_hint: Optional[str] = None
    cache_control: Optional[str] = None
    content_disposition: Optional[str] = None


class MultipartCreateOut(BaseModel):
    uploadId: str
    storage_key: str
    cdn_url: Optional[str] = None


class MultipartCompleteIn(BaseModel):
    """Input to complete a multipart upload."""
    key: str
    parts: List[Dict[str, str]]  # [{ETag:"...", PartNumber:1}, ...]


class MultipartAbortIn(BaseModel):
    """Input to abort a multipart upload."""
    key: str


class DirectProxyIn(BaseModel):
    """Input for small, direct proxy uploads (base64 payload)."""
    content_type: str
    data_base64: str
    key_prefix: Optional[str] = Field("uploads/direct", description="Base path prefix; sanitized")
    filename_hint: Optional[str] = None
    cache_control: Optional[str] = None
    content_disposition: Optional[str] = None


class DirectProxyOut(BaseModel):
    storage_key: str
    cdn_url: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# 🔗 Single-part Presigned Upload
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/uploads/init", summary="Init single upload (presigned PUT)", response_model=UploadInitOut)
@rate_limit("20/minute")
async def uploads_init(
    payload: UploadInitIn | Dict[str, Any],
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """
    Create a presigned **single-part** PUT URL for arbitrary content.

    Steps
    -----
    1. AuthZ/MFA + cache hardening
    2. Build deterministic storage key (idempotency-aware)
    3. Return presigned PUT URL + the headers the client must send

    Returns
    -------
    200 JSON
        `{ upload_url, storage_key, headers, cdn_url? }`
    """
    set_sensitive_cache(response)

    # Normalize body
    if isinstance(payload, dict):
        payload = UploadInitIn.model_validate(payload)

    # AuthZ + MFA
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # Deterministic key
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

    # Presign
    cache_control = payload.cache_control or _default_cache_control(payload.content_type)
    try:
        url = s3.presigned_put(
            key,
            content_type=payload.content_type,
            cache_control=cache_control,
            content_disposition=payload.content_disposition,
            expires_in=900,
            public=False,
        )
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))

    body: Dict[str, Any] = {
        "upload_url": url,
        "storage_key": key,
        "headers": {
            "Content-Type": payload.content_type,
            "Cache-Control": cache_control,
            **({"Content-Disposition": payload.content_disposition} if payload.content_disposition else {}),
        },
        "cdn_url": s3.cdn_url(key),
    }

    # Snapshot + audit (best-effort)
    try:
        await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
    except Exception:
        pass
    try:
        await log_audit_event(
            None,
            user=current_user,
            action="UPLOAD_INIT",
            status="SUCCESS",
            request=request,
            meta_data={"storage_key": key},
        )
    except Exception:
        pass

    return _json(body)


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Multipart: Create
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/uploads/multipart/create", summary="Create multipart upload (returns uploadId)", response_model=MultipartCreateOut)
@rate_limit("20/minute")
async def multipart_create(
    payload: MultipartCreateIn | Dict[str, Any],
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """
    Initialize a **multipart** upload for large files and return `uploadId` + `storage_key`.

    Deterministic key (when `Idempotency-Key` present) ensures replayability.
    """
    # ── Cache hardening ──────────────────────────────────────────────────────
    set_sensitive_cache(response)

    # Normalize body
    if isinstance(payload, dict):
        payload = MultipartCreateIn.model_validate(payload)

    # ── AuthZ + MFA ─────────────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── Build deterministic key (no S3 yet!) ────────────────────────────────
    ext = _ext_for_content_type(payload.content_type)
    prefix = _safe_prefix(payload.key_prefix, "uploads/multipart")

    idem_hdr = request.headers.get("Idempotency-Key") or uuid4().hex
    stem_hint = _sanitize_segment(payload.filename_hint, f"mup_{_short_hash(idem_hdr)}")
    key = f"{prefix}/{stem_hint}.{ext}"

    # ── Idempotency replay (bypass S3 entirely) ─────────────────────────────
    idem_key = f"idemp:admin:uploads:multipart:create:{key}:{idem_hdr}"
    snap = await redis_wrapper.idempotency_get(idem_key)
    if snap:
        return _json(snap)

    # ── S3 multipart init (only if not a replay) ────────────────────────────
    s3 = _ensure_s3()
    cache_control = payload.cache_control or _default_cache_control(payload.content_type)
    try:
        upload = s3.client.create_multipart_upload(
            Bucket=s3.bucket,
            Key=key,
            ContentType=payload.content_type,
            CacheControl=cache_control,
            **({"ContentDisposition": payload.content_disposition} if payload.content_disposition else {}),
            ACL="private",
        )
        upload_id = upload["UploadId"]
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Multipart init failed: {e}")

    body = {"uploadId": upload_id, "storage_key": key, "cdn_url": s3.cdn_url(key)}

    # Best-effort idempotency snapshot + audit
    try:
        await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=3600)
    except Exception:
        pass
    try:
        await log_audit_event(
            None,
            user=current_user,
            action="MULTIPART_CREATE",
            status="SUCCESS",
            request=request,
            meta_data={"storage_key": key, "upload_id": upload_id},
        )
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
    partNumber: int = Query(..., ge=1, le=MAX_PARTS),
    request: Request = None,
    response: Response = None,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """
    Return a presigned **PUT** URL for a specific multipart `partNumber`.

    Notes
    -----
    * The client **must** upload the part with this URL and later provide
      the returned **ETag** exactly (including quotes) during `complete`.

    Returns
    -------
    200 JSON
        `{ "upload_url": str }`
    """
    if response is not None:
        set_sensitive_cache(response)

    # AuthZ + MFA
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
    """
    Complete a multipart upload by supplying `{ETag, PartNumber}` for each part.

    Implementation detail
    ---------------------
    * S3 requires the `Parts` list to be **sorted** by `PartNumber` ascending.
      We enforce that here to avoid subtle 400 errors.

    Returns
    -------
    200 JSON
        `{ "message": "Upload complete", "storage_key": str }`
    """
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = MultipartCompleteIn.model_validate(payload)

    # AuthZ + MFA
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # Sort and coerce parts
    try:
        parts = [
            {"ETag": str(p["ETag"]), "PartNumber": int(p["PartNumber"])}
            for p in payload.parts
        ]
        parts.sort(key=lambda x: x["PartNumber"])
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid parts list")

    s3 = _ensure_s3()
    try:
        s3.client.complete_multipart_upload(
            Bucket=s3.bucket,
            Key=payload.key,
            UploadId=uploadId,
            MultipartUpload={"Parts": parts},
        )
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Complete failed: {e}")

    try:
        await log_audit_event(
            None,
            user=current_user,
            action="MULTIPART_COMPLETE",
            status="SUCCESS",
            request=request,
            meta_data={"storage_key": payload.key, "upload_id": uploadId},
        )
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
    """
    Abort a multipart upload.

    Returns
    -------
    200 JSON
        `{ "message": "Upload aborted" }`
    """
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = MultipartAbortIn.model_validate(payload)

    # AuthZ + MFA
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    s3 = _ensure_s3()
    try:
        s3.client.abort_multipart_upload(Bucket=s3.bucket, Key=payload.key, UploadId=uploadId)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Abort failed: {e}")

    try:
        await log_audit_event(
            None,
            user=current_user,
            action="MULTIPART_ABORT",
            status="SUCCESS",
            request=request,
            meta_data={"storage_key": payload.key, "upload_id": uploadId},
        )
    except Exception:
        pass

    return _json({"message": "Upload aborted"})


# ─────────────────────────────────────────────────────────────────────────────
# 📤 Direct Proxy (Small Files)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/uploads/direct-proxy", summary="Direct proxy upload (small files)", response_model=DirectProxyOut)
@rate_limit("20/minute")
async def direct_proxy_upload(
    payload: DirectProxyIn | Dict[str, Any],
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """
    Directly proxy small files (≤ 10 MiB) into S3 by base64 payload.

    Intended for tiny admin assets (icons, thumbnails). For larger files, prefer
    multipart uploads to avoid memory pressure.

    Returns
    -------
    200 JSON
        `{ "storage_key": str, "cdn_url"?: str }`

    Raises
    ------
    400
        If the base64 payload is invalid.
    413
        If the decoded payload exceeds 10 MiB.
    503
        If storage is temporarily unavailable.
    """
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = DirectProxyIn.model_validate(payload)

    # AuthZ + MFA
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # Decode + size guard
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

    cache_control = payload.cache_control or _default_cache_control(payload.content_type)
    try:
        s3.put_bytes(
            key,
            data,
            content_type=payload.content_type,
            public=False,
            cache_control=cache_control,
            content_disposition=payload.content_disposition,
        )
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))

    try:
        await log_audit_event(
            None,
            user=current_user,
            action="DIRECT_UPLOAD_PROXY",
            status="SUCCESS",
            request=request,
            meta_data={"storage_key": key, "size": len(data)},
        )
    except Exception:
        pass

    return _json({"storage_key": key, "cdn_url": s3.cdn_url(key)})
