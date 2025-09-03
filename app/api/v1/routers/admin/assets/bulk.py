"""
📦 MoviesNow · Admin Bulk Ingestion API (Redis-backed jobs)
==========================================================

Production‑grade, security‑hardened FastAPI routes for **bulk ingestion** under
`/api/v1/admin`. Job envelopes & item arrays are stored in Redis; a separate
worker (out of scope here) consumes from the queue.

Routes (7)
----------
- POST   /api/v1/admin/bulk/manifest            → Submit a bulk manifest (URL or inline items)
- GET    /api/v1/admin/bulk/jobs                → List recent bulk jobs (paged)
- GET    /api/v1/admin/bulk/jobs/{job_id}       → Get job status/envelope
- POST   /api/v1/admin/bulk/jobs/{job_id}/cancel→ Request cancellation (best‑effort)
- GET    /api/v1/admin/bulk/jobs/{job_id}/items → Inspect recorded items & errors (paged)
- POST   /api/v1/admin/bulk/jobs/{job_id}/retry → Re‑queue failed/pending items as new job
- DELETE /api/v1/admin/bulk/jobs/{job_id}       → Purge job envelope & lists (terminal only by default)

Security & Operations
---------------------
- **Admin‑only** + **MFA** on every route.
- **SlowAPI** per‑route rate limits.
- **Idempotency** on manifest submission via `Idempotency-Key` (+ fingerprint).
- **Redis** JSON documents; envelopes & arrays TTL (24h) configurable.
- **Audit logs** are best‑effort and never block the request path.
- Responses use `JSONResponse` to work cleanly with SlowAPI header injection.

Adjust import paths to your project layout as needed.
"""
from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# 📦 Imports
# ─────────────────────────────────────────────────────────────────────────────
from typing import Optional, Dict, Any, List, Literal
from uuid import uuid4
import hashlib
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event

from app.db.models.user import User
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(tags=["Admin • Bulk"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧰 Helpers & Constants
# ─────────────────────────────────────────────────────────────────────────────
JOBS_SET_KEY = "bulk:jobs"                # Redis Set of job ids
JOB_KEY_T = "bulk:job:{job_id}"          # Envelope JSON
ITEMS_KEY_T = "bulk:job:{job_id}:items"   # Items JSON (list)
ERRORS_KEY_T = "bulk:job:{job_id}:errors"  # Errors JSON (list)
QUEUE_LIST_KEY = "bulk:queue"             # Worker queue (list of job ids)
CANCEL_SET_KEY = "bulk:cancels"           # Jobs requested to cancel
DEFAULT_TTL = 24 * 3600                    # 24h retention
MAX_INLINE_ITEMS = 50_000                  # Hard safety guard


def _json(data: Any, status_code: int = 200) -> JSONResponse:
    """Return JSONResponse with strict no‑store headers for admin responses."""
    return JSONResponse(data, status_code=status_code, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


def _now_ms() -> int:
    return int(time.time() * 1000)


def _fingerprint_manifest(url: Optional[str], items: Optional[List[Dict[str, Any]]]) -> str:
    """Stable SHA‑256 fingerprint across URL or inline items (order‑sensitive)."""
    h = hashlib.sha256()
    if url:
        h.update(b"url:")
        h.update(url.strip().encode("utf-8"))
    h.update(b"|items:")
    if items:
        # Minimal canonicalization to avoid massive JSON dumps
        for it in items:
            # Use sorted keys for deterministic hashing
            for k in sorted(it.keys()):
                v = it[k]
                h.update(str(k).encode("utf-8"))
                h.update(b"=")
                h.update(str(v).encode("utf-8"))
                h.update(b";")
            h.update(b"|")
    return h.hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Schemas
# ─────────────────────────────────────────────────────────────────────────────
class BulkManifestIn(BaseModel):
    manifest_url: Optional[str] = Field(None, description="Remote URL to JSON/CSV manifest for worker")
    items: Optional[List[Dict[str, Any]]] = Field(None, description="Inline manifest items (optional)")
    queue_hint: Optional[str] = Field(None, description="Optional worker queue hint/routing key")


class BulkRetryIn(BaseModel):
    """Retry request payload.

    - `only_failed`: when true, only items with status FAILED/ERROR are re‑queued.
    - `include_pending`: include PENDING/QUEUED/RUNNING items in retry set.
    """
    only_failed: bool = True
    include_pending: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# 📥 Submit Bulk Manifest
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/bulk/manifest", status_code=202, summary="Submit bulk manifest (URL/inline)")
@rate_limit("10/minute")
async def bulk_manifest(
    payload: BulkManifestIn | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Submit a bulk manifest by **URL** or **inline items**; returns a queued job id.

    Steps
    -----
    1. AuthZ/MFA + cache hardening
    2. Validate inputs and guard against huge inline arrays
    3. **Idempotency**: if `Idempotency-Key` present, fingerprint and replay
    4. Create job envelope in Redis (JSON) with 24h TTL & index set membership
    5. Push job id onto worker queue (best‑effort)
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = BulkManifestIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Validate ───────────────────────────────────────────────────
    if not payload.manifest_url and not payload.items:
        raise HTTPException(status_code=400, detail="Provide manifest_url or items")
    if payload.items and len(payload.items) > MAX_INLINE_ITEMS:
        raise HTTPException(status_code=413, detail=f"Too many inline items (max {MAX_INLINE_ITEMS})")

    # ── [Step 3] Idempotency ────────────────────────────────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    fp = _fingerprint_manifest(payload.manifest_url, payload.items)
    idem_key = f"idemp:admin:bulk:manifest:{fp}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return _json(snap, status_code=202)

    # ── [Step 4] Create job envelope ────────────────────────────────────────
    job_id = uuid4().hex
    job_key = JOB_KEY_T.format(job_id=job_id)
    env = {
        "id": job_id,
        "status": "QUEUED",
        "submitted_at_ms": _now_ms(),
        "submitted_by": str(getattr(current_user, "id", "")),
        "manifest_url": payload.manifest_url,
        "items_count": len(payload.items) if payload.items else None,
        "queue_hint": payload.queue_hint,
    }

    try:
        await redis_wrapper.json_set(job_key, env, ttl_seconds=DEFAULT_TTL)
        await redis_wrapper.client.sadd(JOBS_SET_KEY, job_id)  # type: ignore
        # Optionally store items array; worker may ignore if it prefers URL
        if payload.items:
            await redis_wrapper.json_set(ITEMS_KEY_T.format(job_id=job_id), payload.items, ttl_seconds=DEFAULT_TTL)
    except Exception:
        raise HTTPException(status_code=503, detail="Could not enqueue job")

    # Best‑effort queue push for worker
    try:
        await redis_wrapper.client.rpush(QUEUE_LIST_KEY, job_id)  # type: ignore
    except Exception:
        pass

    body = {"job_id": job_id, "status": "QUEUED"}

    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=DEFAULT_TTL)
        except Exception:
            pass

    try:
        await log_audit_event(db, user=current_user, action="BULK_MANIFEST", status="QUEUED", request=request, meta_data={"job_id": job_id, "items": env.get("items_count")})
    except Exception:
        pass

    return _json(body, status_code=202)


# ─────────────────────────────────────────────────────────────────────────────
# 📜 List Bulk Jobs
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/bulk/jobs", summary="List bulk jobs (recent)")
@rate_limit("30/minute")
async def bulk_jobs(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    status_filter: Literal["all", "queued", "running", "completed", "failed", "cancelled", "aborted"] = Query("all"),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
) -> JSONResponse:
    """List recent bulk jobs recorded in Redis (paged, newest first)."""
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    # ── [Step 2] Gather & filter ────────────────────────────────────────────
    out: List[Dict[str, Any]] = []
    try:
        ids = await redis_wrapper.client.smembers(JOBS_SET_KEY)  # type: ignore
        ids = list(ids or [])
    except Exception:
        ids = []

    # Pull envelopes
    for jid in ids:
        try:
            data = await redis_wrapper.json_get(JOB_KEY_T.format(job_id=jid))
            if data:
                out.append(data)  # type: ignore[arg-type]
        except Exception:
            continue

    # Filter by status if requested
    sf = str(status_filter or "all").lower()
    if sf != "all":
        def _match(d: Dict[str, Any]) -> bool:
            st = str(d.get("status", "")).lower()
            if sf == "queued":
                return st in {"queued", "retry_queued"}
            if sf == "running":
                return st in {"running"}
            if sf == "completed":
                return st in {"completed"}
            if sf == "failed":
                return st in {"failed"}
            if sf == "cancelled":
                return st in {"cancelled"}
            if sf == "aborted":
                return st in {"aborted"}
            return True
        out = [d for d in out if _match(d)]

    # Sort by submitted_at_ms desc
    out.sort(key=lambda d: int(d.get("submitted_at_ms", 0) or 0), reverse=True)

    total = len(out)
    start = int(offset)
    end = min(start + int(limit), total)
    page = out[start:end]

    return _json({"jobs": page, "total": total, "next_offset": end if end < total else None})


# ─────────────────────────────────────────────────────────────────────────────
# 🔎 Get Bulk Job
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/bulk/jobs/{job_id}", summary="Get bulk job status")
@rate_limit("60/minute")
async def bulk_job_get(
    job_id: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Get a specific bulk job's envelope payload."""
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    data = await redis_wrapper.json_get(JOB_KEY_T.format(job_id=job_id))
    if not data:
        raise HTTPException(status_code=404, detail="Job not found")
    return _json(data)


# ─────────────────────────────────────────────────────────────────────────────
# 🛑 Cancel Bulk Job (best‑effort)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/bulk/jobs/{job_id}/cancel", summary="Request cancel for a bulk job")
@rate_limit("10/minute")
async def bulk_job_cancel(
    job_id: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Request cancellation for a queued/running bulk job (best‑effort).

    The worker is expected to periodically check `bulk:cancels` set.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    key = JOB_KEY_T.format(job_id=job_id)
    data = await redis_wrapper.json_get(key)
    if not data:
        raise HTTPException(status_code=404, detail="Job not found")

    data["status"] = "CANCEL_REQUESTED"
    try:
        await redis_wrapper.json_set(key, data, ttl_seconds=DEFAULT_TTL)
        await redis_wrapper.client.sadd(CANCEL_SET_KEY, job_id)  # type: ignore
    except Exception:
        raise HTTPException(status_code=503, detail="Could not update job")

    try:
        await log_audit_event(db, user=current_user, action="BULK_JOB_CANCEL", status="CANCEL_REQUESTED", request=request, meta_data={"job_id": job_id})
    except Exception:
        pass

    return _json({"status": "CANCEL_REQUESTED"})


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Inspect Items & Errors
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/bulk/jobs/{job_id}/items", summary="Inspect bulk job items and errors")
@rate_limit("60/minute")
async def bulk_job_items(
    job_id: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    status_filter: Literal["all", "failed", "succeeded", "pending", "error"] = Query("all", alias="status"),
    only_errors: bool = Query(False, description="Return only error entries if available"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=1000, description="Pagination limit"),
) -> JSONResponse:
    """Return a slice of recorded items and errors for a bulk job.

    Data Model (Redis)
    ------------------
    - Job envelope: `bulk:job:{job_id}` (JSON)
    - Items array:  `bulk:job:{job_id}:items` (JSON list; optional)
    - Errors array: `bulk:job:{job_id}:errors` (JSON list; optional)

    Notes
    -----
    - If a worker does not populate items/errors, this returns empty arrays.
    - Supports simple pagination and status filtering on the in‑memory list.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    job_key = JOB_KEY_T.format(job_id=job_id)
    job = await redis_wrapper.json_get(job_key)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    items_key = ITEMS_KEY_T.format(job_id=job_id)
    errs_key = ERRORS_KEY_T.format(job_id=job_id)

    items = await redis_wrapper.json_get(items_key, default=[]) or []
    errors = await redis_wrapper.json_get(errs_key, default=[]) or []

    # Defensive normalization
    try:
        items = [i for i in items if isinstance(i, dict)]
    except Exception:
        items = []
    try:
        errors = [e for e in errors if isinstance(e, dict)]
    except Exception:
        errors = []

    # Optional status filter
    sf = str(status_filter or "all").lower()
    if sf != "all":
        def _match(it: Dict[str, Any]) -> bool:
            st = str(it.get("status", "")).lower()
            if sf == "failed":
                return st in {"failed", "error"}
            if sf == "succeeded":
                return st in {"success", "succeeded", "done"}
            if sf == "pending":
                return st in {"queued", "pending", "running"}
            if sf == "error":
                return st == "error"
            return True
        items = [it for it in items if _match(it)]

    total = len(items)
    start = int(offset)
    end = min(start + int(limit), total)
    page = items[start:end]

    return _json({
        "job": {"id": job.get("id"), "status": job.get("status")},
        "items": page,
        "items_total": total,
        "next_offset": end if end < total else None,
        "errors": errors if only_errors else None,
        "errors_total": len(errors) if errors else 0,
    })


# ─────────────────────────────────────────────────────────────────────────────
# 🔁 Retry Bulk Job
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/bulk/jobs/{job_id}/retry", status_code=202, summary="Re‑queue a failed/partial bulk job")
@rate_limit("10/minute")
async def bulk_job_retry(
    job_id: str,
    payload: BulkRetryIn | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Create a new queued job from failed/pending items of an existing job.

    Behavior
    --------
    - Reads `bulk:job:{job_id}` and its `:items` list, if present.
    - Filters items according to `only_failed` and `include_pending`.
    - Creates a new job id and enqueues it with copied items.
    - Marks source job with `retries` count and `last_retry_job_id`.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    if isinstance(payload, dict):
        payload = BulkRetryIn.model_validate(payload)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    src_job_key = JOB_KEY_T.format(job_id=job_id)
    src_job = await redis_wrapper.json_get(src_job_key)
    if not src_job:
        raise HTTPException(status_code=404, detail="Job not found")

    items_key = ITEMS_KEY_T.format(job_id=job_id)
    items = await redis_wrapper.json_get(items_key, default=[]) or []
    if not isinstance(items, list):
        items = []

    def _is_failed(it: Dict[str, Any]) -> bool:
        st = str(it.get("status", "")).lower()
        return st in {"failed", "error"}

    def _is_pending(it: Dict[str, Any]) -> bool:
        st = str(it.get("status", "")).lower()
        return st in {"queued", "pending", "running"}

    retry_pool: List[Dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        if payload.only_failed:
            if _is_failed(it) or (payload.include_pending and _is_pending(it)):
                retry_pool.append(it)
        else:
            retry_pool.append(it)

    # Blind retry allowed when worker uses only manifest_url
    if not retry_pool and not items:
        retry_pool = []

    new_job_id = uuid4().hex
    new_job_key = JOB_KEY_T.format(job_id=new_job_id)

    ttl = DEFAULT_TTL
    try:
        await redis_wrapper.json_set(new_job_key, {
            "id": new_job_id,
            "status": "QUEUED",
            "submitted_at_ms": _now_ms(),
            "submitted_by": str(getattr(current_user, "id", "")),
            "manifest_url": src_job.get("manifest_url"),
            "items_count": len(retry_pool) if retry_pool else src_job.get("items_count"),
            "retry_of": job_id,
        }, ttl_seconds=ttl)
        await redis_wrapper.client.sadd(JOBS_SET_KEY, new_job_id)  # type: ignore
        if retry_pool:
            await redis_wrapper.json_set(ITEMS_KEY_T.format(job_id=new_job_id), retry_pool, ttl_seconds=ttl)
        # Queue push
        try:
            await redis_wrapper.client.rpush(QUEUE_LIST_KEY, new_job_id)  # type: ignore
        except Exception:
            pass

        # Update source job bookkeeping
        src_job["retries"] = int(src_job.get("retries", 0) or 0) + 1
        src_job["last_retry_job_id"] = new_job_id
        src_job["status"] = src_job.get("status") or "RETRY_QUEUED"
        await redis_wrapper.json_set(src_job_key, src_job, ttl_seconds=ttl)
    except Exception:
        raise HTTPException(status_code=503, detail="Could not enqueue retry job")

    try:
        await log_audit_event(
            db=db,
            user=current_user,
            action="BULK_JOB_RETRY",
            status="QUEUED",
            request=request,
            meta_data={
                "source_job_id": job_id,
                "new_job_id": new_job_id,
                "requeued_items": len(retry_pool),
                "only_failed": payload.only_failed,
                "include_pending": payload.include_pending,
            },
        )
    except Exception:
        pass

    return _json({"job_id": new_job_id, "status": "QUEUED", "requeued_items": len(retry_pool)}, status_code=202)


# ─────────────────────────────────────────────────────────────────────────────
# 🧹 Purge Bulk Job
# ─────────────────────────────────────────────────────────────────────────────
@router.delete("/bulk/jobs/{job_id}", status_code=200, summary="Purge a bulk job record")
@rate_limit("10/minute")
async def bulk_job_purge(
    job_id: str,
    request: Request,
    response: Response,
    force: bool = Query(False, description="Force purge regardless of status"),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Delete a bulk job envelope and its associated items/errors from Redis.

    Safety
    ------
    - By default only purges jobs in a terminal state: COMPLETED/FAILED/CANCELLED/ABORTED.
    - Set `force=true` to override (not recommended during active processing).
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    key = JOB_KEY_T.format(job_id=job_id)
    job = await redis_wrapper.json_get(key)
    if not job:
        # Remove from index set if present anyway
        try:
            await redis_wrapper.client.srem(JOBS_SET_KEY, job_id)  # type: ignore
        except Exception:
            pass
        raise HTTPException(status_code=404, detail="Job not found")

    status_str = str(job.get("status", "")).upper()
    terminal = {"COMPLETED", "FAILED", "CANCELLED", "ABORTED"}
    if not force and status_str not in terminal:
        raise HTTPException(status_code=409, detail="Job not in terminal state; set force=true to purge")

    try:
        await redis_wrapper.client.delete(key)  # type: ignore
        await redis_wrapper.client.delete(ITEMS_KEY_T.format(job_id=job_id))  # type: ignore
        await redis_wrapper.client.delete(ERRORS_KEY_T.format(job_id=job_id))  # type: ignore
        await redis_wrapper.client.srem(JOBS_SET_KEY, job_id)  # type: ignore
    except Exception:
        raise HTTPException(status_code=503, detail="Could not purge job")

    try:
        await log_audit_event(db=db, user=current_user, action="BULK_JOB_PURGE", status="SUCCESS", request=request, meta_data={"job_id": job_id, "forced": force})
    except Exception:
        pass

    return _json({"status": "PURGED", "job_id": job_id})
