from __future__ import annotations

"""
Top-level security and discovery endpoints (non-versioned):

- GET /.well-known/jwks.json           -> Publish JWKS (public keys only)
- GET /.well-known/openid-configuration-> OIDC discovery document
- POST /oauth2/token                   -> client_credentials service token
- POST /oauth2/introspect              -> RFC 7662 token introspection
- POST /oauth2/revoke                  -> Revoke a token by JTI
- GET /idempotency/{key}               -> Retrieve an idempotent snapshot

Authentication
--------------
- /oauth2/token: HTTP Basic (client_id:client_secret) or form fields.
- /oauth2/introspect and /oauth2/revoke: require a privileged API key via
  HTTP Basic with "admin" or "introspect" scope.
"""

from typing import Optional
from base64 import b64decode

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from app.core.oidc import build_jwks, build_openid_configuration
from app.core.redis_client import redis_wrapper
from app.schemas.security import (
    ClientCredentialsRequest,
    TokenResponse,
    IntrospectionResponse,
    RevokeRequest,
)
from app.services.oauth2_service import (
    authenticate_client,
    create_service_access_token,
    introspect_token,
    revoke_token,
)


router = APIRouter(tags=["Security"], include_in_schema=True)


@router.get("/.well-known/jwks.json", name="jwks")
async def jwks() -> JSONResponse:
    """Return JWKS with RS256 public keys when configured; otherwise empty."""
    return JSONResponse(build_jwks())


@router.get("/.well-known/openid-configuration", name="openid_configuration")
async def openid_configuration() -> JSONResponse:
    """Return a minimal OpenID Provider configuration document."""
    return JSONResponse(build_openid_configuration())


def _parse_basic_auth(request: Request) -> Optional[tuple[str, str]]:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("basic "):
        return None
    try:
        raw = b64decode(auth.split(" ", 1)[1].strip()).decode("utf-8")
        client_id, client_secret = raw.split(":", 1)
        return client_id, client_secret
    except Exception:
        return None


@router.post("/oauth2/token", response_model=TokenResponse)
async def oauth2_token(request: Request, payload: ClientCredentialsRequest) -> TokenResponse:
    """Issue a service access token for the client_credentials grant.

    Authentication is via HTTP Basic Authorization header or form fields
    `client_id` and `client_secret` (JSON body is accepted too for convenience).
    """
    # Extract client credentials
    creds = _parse_basic_auth(request)
    if creds is None:
        # try body params
        form = await request.form() if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded") else {}
        cid = form.get("client_id") or request.query_params.get("client_id")
        csec = form.get("client_secret") or request.query_params.get("client_secret")
        if not cid or not csec:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing client credentials")
        creds = (str(cid), str(csec))

    client_id, client_secret = creds
    rec = await authenticate_client(client_id, client_secret)

    requested_scopes = sorted({s for s in (payload.scope or "").split() if s})
    allowed_scopes = set(rec.get("scopes", []))
    if requested_scopes and not set(requested_scopes).issubset(allowed_scopes):
        raise HTTPException(status_code=400, detail="Requested scope not allowed for client")
    scopes = requested_scopes or list(allowed_scopes)

    token, claims = await create_service_access_token(client_id=client_id, scopes=scopes)
    return TokenResponse(access_token=token, token_type="bearer", expires_in=int(claims["exp"].timestamp() - claims["iat"].timestamp()), scope=claims.get("scope"))


async def _require_privileged_basic(request: Request) -> str:
    creds = _parse_basic_auth(request)
    if not creds:
        raise HTTPException(status_code=401, detail="Missing Basic auth")
    client_id, client_secret = creds
    rec = await authenticate_client(client_id, client_secret)
    scopes = set(rec.get("scopes", []))
    if not ("admin" in scopes or "introspect" in scopes):
        raise HTTPException(status_code=403, detail="Insufficient scope")
    return client_id


@router.post("/oauth2/introspect", response_model=IntrospectionResponse)
async def oauth2_introspect(request: Request) -> IntrospectionResponse:
    """Token introspection per RFC 7662. Requires privileged Basic auth."""
    await _require_privileged_basic(request)
    form = await request.form()
    token = form.get("token") or request.query_params.get("token")
    if not token:
        raise HTTPException(status_code=400, detail="Missing token")
    data = await introspect_token(str(token))
    return IntrospectionResponse(**data)


@router.post("/oauth2/revoke")
async def oauth2_revoke(request: Request, payload: RevokeRequest) -> dict:
    """Revoke a token immediately. Requires privileged Basic auth."""
    await _require_privileged_basic(request)
    await revoke_token(payload.token)
    return {"revoked": True}


@router.get("/idempotency/{key}")
async def get_idempotency_snapshot(key: str):
    """Return a previously stored idempotent response or 404 when missing."""
    snap = await redis_wrapper.idempotency_get(f"idem:{key}")
    if snap is None:
        raise HTTPException(status_code=404, detail="Not found")
    return snap


__all__ = ["router"]

