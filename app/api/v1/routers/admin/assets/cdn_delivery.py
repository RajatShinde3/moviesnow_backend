"""
🚀 MoviesNow · Admin CDN & Delivery API
======================================

Production‑grade, security‑hardened FastAPI routes for **CDN invalidation** and
**secure asset delivery** under `/api/v1/admin`.

Routes (7)
----------
CDN
- POST /api/v1/admin/cdn/invalidate             → Invalidate CDN paths/prefixes (CloudFront or queue)
- GET  /api/v1/admin/cdn/invalidation/{id}      → Fetch invalidation request status (polls CF if available)

Delivery
- POST /api/v1/admin/delivery/signed-url        → Short‑lived signed GET URL (optional attachment filename)
- POST /api/v1/admin/delivery/download-token    → One‑time download token (stored in Redis)
- GET  /api/v1/admin/delivery/download/{token}  → Redeem one‑time token → 307 redirect or JSON URL
- POST /api/v1/admin/delivery/signed-manifest   → Signed manifest URL for HLS/DASH previews
- POST /api/v1/admin/delivery/download-tokens/batch → Create many one‑time tokens at once

Security & Operations
---------------------
- **Admin‑only** + **MFA** enforcement on all but token redemption.
- **SlowAPI** per‑route rate limits.
- **Sensitive cache headers** on presign responses (`Cache‑Control: no-store`).
- **Idempotency** on CDN invalidation (`Idempotency-Key` snapshot & fingerprint).
- **Redis** for request state, tokens, and distributed locks.
- **Audit logs** are best‑effort and never block the request path.
- Explicit `JSONResponse`/`RedirectResponse` to cooperate with SlowAPI header injection.

Adjust imports/paths for your project layout.
"""
from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# 📦 Imports
# ─────────────────────────────────────────────────────────────────────────────
from typing import Optional, Dict, Any, List, Literal
from uuid import uuid4
from datetime import datetime, timezone, timedelta
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query
from fastapi.responses import JSONResponse, RedirectResponse

from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.core.config import settings
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event

from app.db.models.user import User
from app.utils.aws import S3Client, S3StorageError
import boto3

router = APIRouter(tags=["Admin • CDN & Delivery"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧰 Helpers & Fingerprints
# ─────────────────────────────────────────────────────────────────────────────
INV_STATE_KEY_T = "cdn:inv:{request_id}"          # JSON: invalidation state document
DL_TOKEN_KEY_T  = "download:token:{token}"        # JSON: one‑time token
DEFAULT_TTL     = 24 * 3600                        # 24h persistence for CDN state


def _json(data: Any, status_code: int = 200) -> JSONResponse:
    """Return JSONResponse with strict no‑store headers for admin responses."""
    return JSONResponse(data, status_code=status_code, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


def _ensure_s3() -> S3Client:
    try:
        return S3Client()
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))


def _fp_invalidation(paths: List[str], dist_id: Optional[str]) -> str:
    h = hashlib.sha256()
    for p in sorted(set(paths)):
        h.update(p.encode("utf-8"))
        h.update(b"\0")
    h.update((dist_id or "").encode("utf-8"))
    return h.hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Schemas
# ─────────────────────────────────────────────────────────────────────────────
from pydantic import BaseModel, Field


class CDNInvalidateIn(BaseModel):
    paths: List[str] = Field(default_factory=list, description="Exact paths, e.g. /videos/a.m3u8")
    prefixes: List[str] = Field(default_factory=list, description="Prefix patterns; expanded to prefix*")
    distribution_id: Optional[str] = Field(None, description="Override CloudFront distribution id")


class SignedUrlIn(BaseModel):
    storage_key: str
    expires_in: int = Field(300, ge=60, le=3600)
    attachment_filename: Optional[str] = Field(None, description="If set, add Content‑Disposition attachment")


class DownloadTokenIn(BaseModel):
    storage_key: str
    ttl_seconds: int = Field(3600, ge=60, le=24 * 3600)


class SignedManifestIn(BaseModel):
    """Sign a manifest object for short‑lived preview. Segments are not rewritten."""
    storage_key: str
    expires_in: int = Field(300, ge=60, le=3600)
    format: Optional[Literal["hls", "dash"]] = Field(None, description="Optional override; else by extension")


class BatchTokenItem(BaseModel):
    storage_key: str
    ttl_seconds: int = Field(3600, ge=60, le=24 * 3600)


class BatchTokensIn(BaseModel):
    items: List[BatchTokenItem]


# ─────────────────────────────────────────────────────────────────────────────
# ☁️ CDN: Invalidate
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/cdn/invalidate", summary="Invalidate CDN paths/prefixes")
@rate_limit("6/minute")
async def cdn_invalidate(
    payload: CDNInvalidateIn | Dict[str, Any],
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Invalidate CDN cache paths/prefixes.

    Steps
    -----
    1. AuthZ/MFA + cache hardening
    2. Normalize inputs, expand prefixes → `prefix*`
    3. **Idempotency**: if `Idempotency-Key`, fingerprint and replay
    4. If CloudFront configured → submit invalidation and persist state
       Else: enqueue paths to Redis queue and persist queued state
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = CDNInvalidateIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Normalize paths/prefixes ───────────────────────────────────
    paths: List[str] = []
    for p in payload.paths or []:
        p = (p or "").strip()
        if not p:
            continue
        if not p.startswith("/"):
            p = "/" + p
        paths.append(p)
    for pre in payload.prefixes or []:
        pre = (pre or "").strip()
        if not pre:
            continue
        if not pre.endswith("*"):
            pre = pre + "*"
        if not pre.startswith("/"):
            pre = "/" + pre
        paths.append(pre)
    paths = list(dict.fromkeys(paths))  # stable de‑dup

    if not paths:
        raise HTTPException(status_code=400, detail="Provide at least one path or prefix")

    dist_id = payload.distribution_id or getattr(settings, "CLOUDFRONT_DISTRIBUTION_ID", None)

    # ── [Step 3] Idempotency snapshot ───────────────────────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    if idem_hdr:
        fp = _fp_invalidation(paths, dist_id)
        idem_key = f"idemp:admin:cdn:invalidate:{fp}:{idem_hdr}"
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return _json(snap)

    # ── [Step 4] Execute via CloudFront or queue ────────────────────────────
    request_id = uuid4().hex
    caller_ref = f"inv-{request_id}"

    # Try CloudFront if configured
    if dist_id:
        try:
            cf = boto3.client(
                "cloudfront",
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY.get_secret_value(),
                region_name=getattr(settings, "AWS_REGION", None),
            )
            resp = cf.create_invalidation(
                DistributionId=dist_id,
                InvalidationBatch={"Paths": {"Quantity": len(paths), "Items": paths}, "CallerReference": caller_ref},
            )
            inv_id = (resp or {}).get("Invalidation", {}).get("Id")
            state = {
                "request_id": request_id,
                "provider": "cloudfront",
                "distribution_id": dist_id,
                "invalidation_id": inv_id,
                "paths": paths,
                "status": "SUBMITTED",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "caller_reference": caller_ref,
            }
            try:
                await redis_wrapper.json_set(INV_STATE_KEY_T.format(request_id=request_id), state, ttl_seconds=DEFAULT_TTL)
            except Exception:
                pass
            body = {"status": "SUBMITTED", "distribution_id": dist_id, "paths": paths, "request_id": request_id, "invalidation_id": inv_id}
            # Idempotent snapshot
            if idem_hdr:
                try:
                    await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=DEFAULT_TTL)  # type: ignore[name-defined]
                except Exception:
                    pass
            try:
                await log_audit_event(None, user=current_user, action="CDN_INVALIDATE", status="SUBMITTED", request=request, meta_data={"distribution": dist_id, "count": len(paths), "request_id": request_id, "invalidation_id": inv_id})
            except Exception:
                pass
            return _json(body)
        except Exception:
            # Fall back to queue below
            pass

    # Queue fallback (no CloudFront or CF error)
    try:
        await redis_wrapper.client.rpush("cdn:invalidate:queue", *paths)  # type: ignore
        state = {
            "request_id": request_id,
            "provider": "queue",
            "paths": paths,
            "status": "QUEUED",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            await redis_wrapper.json_set(INV_STATE_KEY_T.format(request_id=request_id), state, ttl_seconds=DEFAULT_TTL)
        except Exception:
            pass
        body = {"status": "QUEUED", "paths": paths, "request_id": request_id}
        if idem_hdr:
            try:
                await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=DEFAULT_TTL)  # type: ignore[name-defined]
            except Exception:
                pass
        try:
            await log_audit_event(None, user=current_user, action="CDN_INVALIDATE", status="QUEUED", request=request, meta_data={"count": len(paths), "request_id": request_id})
        except Exception:
            pass
        return _json(body)
    except Exception:
        raise HTTPException(status_code=503, detail="Could not queue invalidation")


# ─────────────────────────────────────────────────────────────────────────────
# 🛰️ CDN: Invalidation Status
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/cdn/invalidation/{request_id}", summary="Fetch CDN invalidation status")
@rate_limit("60/minute")
async def cdn_invalidation_status(
    request_id: str,
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Return status of a previously submitted CDN invalidation.

    If provider is CloudFront and IDs are present, attempts a live status refresh.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    key = INV_STATE_KEY_T.format(request_id=request_id)
    state = await redis_wrapper.json_get(key)
    if not state:
        raise HTTPException(status_code=404, detail="Invalidation request not found")

    provider = state.get("provider") if isinstance(state, dict) else None
    if provider == "cloudfront":
        dist_id = state.get("distribution_id")
        inv_id = state.get("invalidation_id")
        if dist_id and inv_id:
            try:
                cf = boto3.client(
                    "cloudfront",
                    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY.get_secret_value(),
                    region_name=getattr(settings, "AWS_REGION", None),
                )
                resp = cf.get_invalidation(DistributionId=dist_id, Id=inv_id)
                status = (resp or {}).get("Invalidation", {}).get("Status", state.get("status"))
                state.update({
                    "status": status,
                    "last_checked_at": datetime.now(timezone.utc).isoformat(),
                })
                try:
                    await redis_wrapper.json_set(key, state, ttl_seconds=DEFAULT_TTL)
                except Exception:
                    pass
            except Exception:
                # Ignore refresh failures; return cached state
                pass

    try:
        await log_audit_event(None, user=current_user, action="CDN_INVALIDATE_STATUS", status=str(state.get("status")), request=request, meta_data={"request_id": request_id})
    except Exception:
        pass

    return _json(state)


# ─────────────────────────────────────────────────────────────────────────────
# 🔐 Delivery: Signed URL
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/delivery/signed-url", summary="Short‑lived preview (signed URL)")
@rate_limit("60/minute")
async def delivery_signed_url(
    payload: SignedUrlIn | Dict[str, Any],
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Return a short‑lived presigned GET URL for a storage key.

    Optionally sets `Content‑Disposition: attachment; filename=...` for downloads.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = SignedUrlIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    s3 = _ensure_s3()
    disp = f'attachment; filename="{payload.attachment_filename}"' if payload.attachment_filename else None
    try:
        url = s3.presigned_get(payload.storage_key, expires_in=payload.expires_in, response_content_disposition=disp)
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))

    return _json({"url": url})


# ─────────────────────────────────────────────────────────────────────────────
# 🎫 Delivery: One‑time Download Token (issue)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/delivery/download-token", summary="One‑time download token for premium assets")
@rate_limit("30/minute")
async def delivery_download_token(
    payload: DownloadTokenIn | Dict[str, Any],
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Issue a one‑time, short‑lived download token (stored in Redis)."""
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = DownloadTokenIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    token = uuid4().hex
    key = DL_TOKEN_KEY_T.format(token=token)
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

    return _json({"token": token, "expires_at": data["expires_at"]})


# ─────────────────────────────────────────────────────────────────────────────
# 🎟️ Delivery: Redeem One‑time Token
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/delivery/download/{token}", summary="Redeem one‑time download token", response_model=None)
@rate_limit("60/minute")
async def delivery_download_redeem(
    token: str,
    request: Request,
    response: Response,
    redirect: bool = Query(True, description="If true, 307 redirect to signed URL; else return JSON"),
    filename: Optional[str] = Query(None, description="Optional attachment filename"),
    expires_in: int = Query(300, ge=60, le=3600, description="Signed URL TTL seconds"),
) -> JSONResponse | RedirectResponse:
    """Redeem a one‑time token and return/redirect to a signed URL.

    Semantics
    ---------
    - Tokens live at `download:token:{token}` with TTL and one_time flag.
    - Redemption uses a short Redis lock and deletes the token to prevent reuse.
    - Authentication is **not** required — the token is the capability.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # Serialize redemption via a distributed lock
    async with redis_wrapper.lock(f"lock:download:token:{token}", timeout=5, blocking_timeout=2):
        key = DL_TOKEN_KEY_T.format(token=token)
        data = await redis_wrapper.json_get(key)
        if not data:
            raise HTTPException(status_code=404, detail="Token not found or expired")
        # One‑time semantics: best‑effort delete
        try:
            await redis_wrapper.client.delete(key)  # type: ignore
        except Exception:
            pass

    storage_key = data.get("storage_key") if isinstance(data, dict) else None
    if not storage_key:
        raise HTTPException(status_code=400, detail="Token missing storage_key")

    try:
        s3 = _ensure_s3()
        disp = f'attachment; filename="{filename}"' if filename else None
        url = s3.presigned_get(str(storage_key), expires_in=int(expires_in), response_content_disposition=disp)
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))

    try:
        await log_audit_event(None, user=None, action="DELIVERY_DOWNLOAD_REDEEM", status="SUCCESS", request=request, meta_data={"token": token, "redirect": bool(redirect)})
    except Exception:
        pass

    if redirect:
        # Return a 307 so clients keep the method; add no‑store cache headers
        return RedirectResponse(url=url, status_code=307, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
    return _json({"url": url})


# ─────────────────────────────────────────────────────────────────────────────
# 📜 Delivery: Signed Manifest (HLS/DASH)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/delivery/signed-manifest", summary="Sign a HLS/DASH manifest for preview")
@rate_limit("60/minute")
async def delivery_signed_manifest(
    payload: SignedManifestIn | Dict[str, Any],
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Return a short‑lived signed URL for the manifest object.

    Does **not** rewrite segment URLs; use a private storage layout when the
    manifest alone suffices for ephemeral previews.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = SignedManifestIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    s3 = _ensure_s3()
    fmt = (payload.format or "").lower()
    ctype = None
    key_lower = payload.storage_key.lower()
    if fmt == "hls" or key_lower.endswith(".m3u8"):
        ctype = "application/vnd.apple.mpegurl"
    elif fmt == "dash" or key_lower.endswith(".mpd"):
        ctype = "application/dash+xml"

    try:
        url = s3.presigned_get(payload.storage_key, expires_in=payload.expires_in, response_content_type=ctype)
    except S3StorageError as e:
        raise HTTPException(status_code=503, detail=str(e))

    try:
        await log_audit_event(None, user=current_user, action="DELIVERY_SIGNED_MANIFEST", status="SUCCESS", request=request, meta_data={"storage_key": payload.storage_key, "format": fmt or ("hls" if key_lower.endswith(".m3u8") else "dash" if key_lower.endswith(".mpd") else None)})
    except Exception:
        pass

    return _json({"url": url, "content_type": ctype or "application/octet-stream"})


# ─────────────────────────────────────────────────────────────────────────────
# 📦 Delivery: Batch Download Tokens
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/delivery/download-tokens/batch", summary="Create multiple one‑time download tokens")
@rate_limit("20/minute")
async def batch_download_tokens(
    payload: BatchTokensIn | Dict[str, Any],
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Create multiple one‑time tokens in one call.

    Limits
    ------
    - Max 100 items to prevent abuse & latency spikes.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = BatchTokensIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    max_items = 100
    if not payload.items:
        raise HTTPException(status_code=400, detail="No items provided")
    if len(payload.items) > max_items:
        raise HTTPException(status_code=400, detail=f"Too many items (max {max_items})")

    results: List[Dict[str, Any]] = []
    for it in payload.items:
        token = uuid4().hex
        key = DL_TOKEN_KEY_T.format(token=token)
        exp_at = datetime.now(timezone.utc) + timedelta(seconds=it.ttl_seconds)
        data = {
            "storage_key": it.storage_key,
            "one_time": True,
            "issued_by": str(getattr(current_user, "id", "")),
            "expires_at": exp_at.isoformat(),
        }
        try:
            await redis_wrapper.json_set(key, data, ttl_seconds=it.ttl_seconds)
            results.append({"token": token, "expires_at": data["expires_at"], "storage_key": it.storage_key})
        except Exception as e:
            results.append({"error": str(e), "storage_key": it.storage_key})

    return _json({"results": results})
