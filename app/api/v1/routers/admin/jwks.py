from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# 🔐 Admin · JWKS Router
# ─────────────────────────────────────────────────────────────────────────────

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status
from pydantic import BaseModel, Field
import logging
try:
    from pydantic import RootModel  # Pydantic v2
except Exception:  # pragma: no cover
    RootModel = None  # type: ignore

logger = logging.getLogger(__name__)

from app.core.limiter import rate_limit
from app.security_headers import set_sensitive_cache
from app.services.jwks_service import (
    rotate_key,
    list_keys,
    delete_key,
    prune_retired,
    get_public_jwks,
)
from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa

router = APIRouter(tags=["Admin · JWKS"])


# ─────────────────────────────────────────────────────────────────────────────
# 📦 Response Models
# ─────────────────────────────────────────────────────────────────────────────

if RootModel is not None:
    class JWKPublic(RootModel[Dict[str, Any]]):  # type: ignore[valid-type]
        # keep it loose: JWK members vary by kty/alg/curve; retain dict for flexibility
        # if you have a shared JWK schema, swap Dict[str, Any] with that model.
        root: Dict[str, Any]
else:  # Fallback for Pydantic v1 (not expected)
    class JWKPublic(BaseModel):
        __root__: Dict[str, Any]


class RotateOut(BaseModel):
    kid: str = Field(..., description="Key ID of the newly active key")
    public_jwk: Dict[str, Any] = Field(..., description="Public JWK for the new key")


class KeysListOut(BaseModel):
    keys: List[Dict[str, Any]] = Field(..., description="All known keys (active + stored)")


class DeleteOut(BaseModel):
    deleted: bool = Field(True, description="True if a non-active key was deleted")


class PruneOut(BaseModel):
    removed: int = Field(..., ge=0, description="Count of retired/expired keys removed")


# ─────────────────────────────────────────────────────────────────────────────
# 📜 List keys
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/jwks/keys",
    summary="List JWKS keys",
    response_model=KeysListOut,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"description": "Unauthorized (admin key/MFA)"},
        403: {"description": "Forbidden"},
    },
)
@rate_limit("30/minute")
async def jwks_list(
    request: Request,
    response: Response,
    _adm=Depends(_ensure_admin),
    _mfa=Depends(_ensure_mfa),
) -> KeysListOut:
    set_sensitive_cache(response)
    keys = await list_keys()
    return KeysListOut(keys=keys)  # type: ignore[arg-type]


# ─────────────────────────────────────────────────────────────────────────────
# 🧭 Rotate (add) a new active key
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/jwks/rotate",
    summary="Rotate (add) a new active key",
    response_model=RotateOut,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"description": "Bad request"},
        401: {"description": "Unauthorized (admin key/MFA)"},
        403: {"description": "Forbidden"},
        409: {"description": "Conflict (e.g., rotation not allowed)"},
    },
)
@rate_limit("10/minute")
async def jwks_rotate(
    request: Request,
    response: Response,
    _adm=Depends(_ensure_admin),
    _mfa=Depends(_ensure_mfa),
) -> RotateOut:
    set_sensitive_cache(response)
    try:
        info = await rotate_key()
        logger.info("jwks.rotate ok kid=%s", info.get("kid"))
        return RotateOut(kid=info["kid"], public_jwk=info["public_jwk"])  # type: ignore[index]
    except KeyError as e:
        # service returned unexpected payload shape
        logger.exception("jwks.rotate payload missing: %s", e)
        raise HTTPException(status_code=500, detail=f"Rotation payload missing: {e}")
    except ValueError as e:
        # domain-level validation/constraints from service
        logger.info("jwks.rotate bad request: %s", e)
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        # collisions, contention, or service-signaled conflicts
        logger.info("jwks.rotate conflict: %s", e)
        raise HTTPException(status_code=409, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
# 🗑️ Delete a non-active key
# ─────────────────────────────────────────────────────────────────────────────

@router.delete(
    "/jwks/keys/{kid}",
    summary="Delete a non-active key",
    response_model=DeleteOut,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"description": "Bad request (e.g., attempting to delete active key)"},
        401: {"description": "Unauthorized (admin key/MFA)"},
        403: {"description": "Forbidden"},
        404: {"description": "Key not found"},
    },
)
@rate_limit("20/minute")
async def jwks_delete(
    kid: str = Path(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._-]+$",
        description="Key ID (safe characters only)",
    ),
    request: Request = None,  # kept for signature symmetry/logging middleware
    response: Response = None,
    _adm=Depends(_ensure_admin),
    _mfa=Depends(_ensure_mfa),
) -> DeleteOut:
    # tolerate optional Response in signature, but always set sensitive headers if present
    if isinstance(response, Response):
        set_sensitive_cache(response)
    try:
        ok = await delete_key(kid)
        if not ok:
            raise HTTPException(status_code=404, detail="Key not found")
        return DeleteOut(deleted=True)
    except ValueError as e:
        # invalid state: e.g., trying to delete the active key
        raise HTTPException(status_code=400, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
# 🧹 Prune retired/expired keys
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/jwks/prune",
    summary="Prune retired/expired keys",
    response_model=PruneOut,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"description": "Unauthorized (admin key/MFA)"},
        403: {"description": "Forbidden"},
    },
)
@rate_limit("10/minute")
async def jwks_prune(
    request: Request,
    response: Response,
    _adm=Depends(_ensure_admin),
    _mfa=Depends(_ensure_mfa),
) -> PruneOut:
    set_sensitive_cache(response)
    removed = await prune_retired()
    return PruneOut(removed=removed)


# ─────────────────────────────────────────────────────────────────────────────
# 🛰️ Show current public JWKS (debug)
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/jwks/public",
    summary="Show current public JWKS (debug)",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    responses={
        401: {"description": "Unauthorized (admin key/MFA)"},
        403: {"description": "Forbidden"},
    },
)
@rate_limit("30/minute")
async def jwks_public_preview(
    request: Request,
    response: Response,
    _adm=Depends(_ensure_admin),
    _mfa=Depends(_ensure_mfa),
) -> Dict[str, Any]:
    set_sensitive_cache(response)
    # Service returns a full JWKS doc, typically: {"keys": [ ... ]}
    return await get_public_jwks()


__all__ = ["router"]
