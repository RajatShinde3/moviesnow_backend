
"""
Admin: API Keys management (Redis-backed, no migrations).

Endpoints
---------
- POST   /admin/api-keys               -> Create an API key
- GET    /admin/api-keys               -> List API keys (masked, no secrets)
- PATCH  /admin/api-keys/{key_id}      -> Update/rotate/disable
- DELETE /admin/api-keys/{key_id}      -> Delete an API key

Security
--------
- Requires an authenticated admin user. Reuses `app.core.security.get_current_user`.
- Secrets are returned only on creation or when `rotate=true` during updates.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.security import get_current_user
from app.db.models.user import User
from app.schemas.enums import OrgRole
from app.schemas.security import APIKeyCreate, APIKeyOut, APIKeyUpdate
from app.services.api_keys_service import (
    create_api_key,
    list_api_keys,
    update_api_key,
    delete_api_key,
)


router = APIRouter(tags=["Admin API Keys"])


def _require_admin(user: User) -> None:
    if getattr(user, "role", None) not in {OrgRole.ADMIN, OrgRole.SUPERUSER} and not getattr(user, "is_superuser", False):
        raise HTTPException(status_code=403, detail="Admin privileges required")


@router.post("/api-keys", response_model=APIKeyOut)
async def api_keys_create(payload: APIKeyCreate, user: User = Depends(get_current_user)) -> APIKeyOut:
    _require_admin(user)
    rec = await create_api_key(label=payload.label, scopes=payload.scopes, ttl_days=payload.ttl_days)
    return APIKeyOut(**rec)


@router.get("/api-keys", response_model=List[APIKeyOut])
async def api_keys_list(user: User = Depends(get_current_user)) -> List[APIKeyOut]:
    _require_admin(user)
    items = await list_api_keys()
    # All items are masked; pydantic model will ignore missing secret
    return [APIKeyOut(**i) for i in items]


@router.patch("/api-keys/{key_id}", response_model=APIKeyOut)
async def api_keys_update(key_id: str, payload: APIKeyUpdate, user: User = Depends(get_current_user)) -> APIKeyOut:
    _require_admin(user)
    try:
        rec = await update_api_key(
            key_id=key_id,
            label=payload.label,
            scopes=payload.scopes,
            disabled=payload.disabled,
            rotate=payload.rotate,
            ttl_days=payload.ttl_days,
        )
        return APIKeyOut(**rec)
    except KeyError:
        raise HTTPException(status_code=404, detail="API key not found")


@router.delete("/api-keys/{key_id}")
async def api_keys_delete(key_id: str, user: User = Depends(get_current_user)) -> dict:
    _require_admin(user)
    ok = await delete_api_key(key_id)
    if not ok:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"deleted": True}


__all__ = ["router"]

