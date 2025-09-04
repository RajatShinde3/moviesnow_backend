# app/api/v1/routers/admin_api_keys.py
"""
MoviesNow • Admin API Keys (Redis-backed)
=========================================

Admin-only management of public API keys (no database migrations required).
Secrets are **never** persisted; only a SHA-256 hash is stored. The plaintext
secret is returned **only** on creation or rotation.

Endpoints
---------
- POST   /admin/api-keys               → Create an API key (returns plaintext secret)
- GET    /admin/api-keys               → List API keys (masked; no secrets)
- PATCH  /admin/api-keys/{key_id}      → Update/rotate/disable (returns secret on rotate)
- DELETE /admin/api-keys/{key_id}      → Delete an API key

Security & Ops Hardening
------------------------
- Requires ADMIN/SUPERUSER + MFA on **all** routes.
- Per-route SlowAPI rate limits.
- Responses set `Cache-Control: no-store` to avoid caching secrets/metadata.
- Create is best-effort **idempotent** via `Idempotency-Key` snapshot in Redis.
- Concurrency safety: Redis lock on `{key_id}` for update/delete.
- Best-effort structured audit logs (never block main flow).
"""


from typing import List, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.db.models.user import User
from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event
from app.schemas.security import APIKeyCreate, APIKeyOut, APIKeyUpdate
from app.services.api_keys_service import (
    create_api_key,
    list_api_keys,
    update_api_key,
    delete_api_key,
)

router = APIRouter(tags=["Admin API Keys"])


# ─────────────────────────────────────────────────────────────────────────────
# ➕ Create API key (Idempotency-Key supported)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/api-keys", response_model=APIKeyOut, summary="Create API key (returns plaintext secret)")
@rate_limit("10/minute")
async def api_keys_create(
    payload: APIKeyCreate,
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
) -> APIKeyOut:
    """Create a new API key and return its plaintext `secret` once.

    Steps
    -----
    0) Enforce ADMIN + MFA; set `no-store` cache headers.
    1) Best-effort idempotency replay using `Idempotency-Key` (scoped to caller).
    2) Create key in Redis (hash-only storage).
    3) Audit & optionally snapshot idempotent response.
    """
    # Step 0: Security & cache hardening
    await _ensure_admin(user); await _ensure_mfa(request); set_sensitive_cache(response)

    # Step 1: Idempotency (best-effort)
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:api_keys:create:{user.id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            # Snapshot already contains plaintext secret from the original call.
            return APIKeyOut(**snap)

    # Step 2: Create key
    rec = await create_api_key(label=payload.label, scopes=payload.scopes, ttl_days=payload.ttl_days)

    # Step 3: Audit & snapshot
    try:
        await log_audit_event(
            db=None,  # service uses Redis only; pass None for DB session
            user=user,
            action="API_KEYS_CREATE",
            status="SUCCESS",
            request=request,
            meta_data={"key_id": rec.get("id"), "label": rec.get("label")},
        )
    except Exception:
        pass
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, rec, ttl_seconds=600)
        except Exception:
            pass

    return APIKeyOut(**rec)


# ─────────────────────────────────────────────────────────────────────────────
# 📚 List API keys (masked, no secrets)
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/api-keys", response_model=List[APIKeyOut], summary="List API keys (masked)")
@rate_limit("30/minute")
async def api_keys_list(
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
) -> List[APIKeyOut]:
    """List API keys with masked details; **no** secrets returned."""
    await _ensure_admin(user); await _ensure_mfa(request); set_sensitive_cache(response, seconds=0)

    items = await list_api_keys()
    out = [APIKeyOut(**i) for i in items]

    try:
        await log_audit_event(db=None, user=user, action="API_KEYS_LIST", status="SUCCESS", request=request, meta_data={"count": len(out)})
    except Exception:
        pass
    return out


# ─────────────────────────────────────────────────────────────────────────────
# ✏️ Update / Rotate / Disable
# ─────────────────────────────────────────────────────────────────────────────
@router.patch("/api-keys/{key_id}", response_model=APIKeyOut, summary="Update/rotate/disable API key")
@rate_limit("10/minute")
async def api_keys_update(
    key_id: str,
    payload: APIKeyUpdate,
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
) -> APIKeyOut:
    """Update an API key. When `rotate=true`, returns the new plaintext secret.

    Steps
    -----
    0) Enforce ADMIN + MFA; set `no-store`.
    1) Lock on `key_id` to avoid concurrent rotations/updates.
    2) Apply update via service.
    3) Audit and return (includes `secret` only if rotated).
    """
    await _ensure_admin(user); await _ensure_mfa(request); set_sensitive_cache(response)

    lock_key = f"lock:apikey:update:{key_id}"
    async with redis_wrapper.lock(lock_key, timeout=10, blocking_timeout=3):
        try:
            rec = await update_api_key(
                key_id=key_id,
                label=payload.label,
                scopes=payload.scopes,
                disabled=payload.disabled,
                rotate=bool(payload.rotate),
                ttl_days=payload.ttl_days,
            )
        except KeyError:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    try:
        await log_audit_event(
            db=None, user=user, action="API_KEYS_UPDATE", status="SUCCESS", request=request,
            meta_data={"key_id": key_id, "rotated": bool(payload.rotate), "disabled": payload.disabled}
        )
    except Exception:
        pass
    return APIKeyOut(**rec)


# ─────────────────────────────────────────────────────────────────────────────
# 🗑️ Delete API key
# ─────────────────────────────────────────────────────────────────────────────
@router.delete("/api-keys/{key_id}", summary="Delete API key")
@rate_limit("10/minute")
async def api_keys_delete(
    key_id: str,
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
) -> Dict[str, bool]:
    """Delete an API key and remove it from the index.

    Steps
    -----
    0) Enforce ADMIN + MFA; set `no-store`.
    1) Lock on `key_id`; best-effort delete in service.
    2) Audit & return status.
    """
    await _ensure_admin(user); await _ensure_mfa(request); set_sensitive_cache(response)

    lock_key = f"lock:apikey:delete:{key_id}"
    async with redis_wrapper.lock(lock_key, timeout=10, blocking_timeout=3):
        ok = await delete_api_key(key_id)
        if not ok:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    try:
        await log_audit_event(db=None, user=user, action="API_KEYS_DELETE", status="SUCCESS", request=request, meta_data={"key_id": key_id})
    except Exception:
        pass
    return {"deleted": True}
