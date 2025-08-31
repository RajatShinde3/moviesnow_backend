from __future__ import annotations

"""
OAuth2 service helpers for client_credentials, introspection, and revocation.

Key features:
- Client authentication via API Keys (admin-managed) using Redis storage.
- RS256 signing for service tokens when RSA private key configured; fallback to HS*.
- RFC 7662 token introspection response shape.
- Revocation by JTI using Redis revocation lane shared with user tokens.

Notes
-----
- Service tokens use `sub` formatted as `svc:{client_id}` to avoid collision
  with user UUIDs; `token_type` is `access`.
- JTI is registered in `access:jti:{jti}` for TTL-based validity checks and
  `revoked:jti:{jti}` for explicit revocation.
"""

from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import base64
import logging

from fastapi import HTTPException, status
from jose import jwt

from app.core.config import settings
from app.core.redis_client import redis_wrapper
from app.core.oidc import issuer_url

logger = logging.getLogger("oauth2")


# -- API key client validation -----------------------------------------------
API_KEY_PREFIX = "api_keys"


async def _get_api_key_record(key_id: str) -> Optional[Dict[str, Any]]:
    """Load API key metadata JSON from Redis (admin-managed)."""
    key = f"{API_KEY_PREFIX}:{key_id}"
    try:
        return await redis_wrapper.json_get(key, default=None)
    except Exception:
        return None


def _sha256_hex(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


async def authenticate_client(client_id: str, client_secret: str) -> Dict[str, Any]:
    """Validate client_id/secret against stored API key records.

    Returns the API key record when valid and not disabled/expired.
    """
    rec = await _get_api_key_record(client_id)
    if not rec:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client credentials")
    if rec.get("disabled"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Client disabled")
    # Expiry check (allow None for non-expiring keys)
    exp = rec.get("expires_at")
    if exp is not None:
        try:
            if datetime.fromisoformat(str(exp)) < datetime.now(timezone.utc):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Client expired")
        except HTTPException:
            raise
        except Exception:
            # If stored format is epoch seconds
            try:
                if float(exp) <= datetime.now(timezone.utc).timestamp():
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Client expired")
            except Exception:
                pass

    # Constant-time compare of secrets via sha256 of presented secret
    presented = _sha256_hex(client_secret)
    stored = str(rec.get("hash", ""))
    import hmac

    if not hmac.compare_digest(presented, stored):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client credentials")
    return rec


# -- Token minting ------------------------------------------------------------

def _load_rsa_private_key() -> Optional[Tuple[object, Optional[str]]]:
    """Load RSA private key PEM from settings, return (pem_bytes, kid)."""
    pem: Optional[str] = None
    try:
        priv = getattr(settings, "OIDC_RSA_PRIVATE_KEY_PEM", None)  # type: ignore[attr-defined]
        if priv is not None:
            try:
                pem = priv.get_secret_value()  # type: ignore[attr-defined]
            except Exception:
                pem = str(priv)
    except Exception:
        pem = None
    if not pem:
        try:
            path = getattr(settings, "OIDC_RSA_PRIVATE_KEY_PATH", None)  # type: ignore[attr-defined]
        except Exception:
            path = None
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    pem = f.read()
            except Exception:
                pem = None
    if not pem:
        return None
    kid = None
    try:
        kid = getattr(settings, "OIDC_KID", None)  # type: ignore[attr-defined]
    except Exception:
        kid = None
    return pem.encode("utf-8"), kid


async def create_service_access_token(
    *,
    client_id: str,
    scopes: List[str],
    expires_in_seconds: Optional[int] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Create a signed service access token for client_credentials.

    Returns a tuple of (jwt, claims) for caller logging/testing.
    """
    now = datetime.now(timezone.utc)
    ttl = int(expires_in_seconds or int(getattr(settings, "SERVICE_TOKEN_TTL_SECONDS", 3600)))
    exp = now + timedelta(seconds=ttl)
    jti = str(uuid4())

    iss = issuer_url()
    payload: Dict[str, Any] = {
        "sub": f"svc:{client_id}",
        "client_id": client_id,
        "scope": " ".join(sorted(set(scopes))),
        "token_type": "access",
        "jti": jti,
        "iat": now,
        "nbf": now,
        "exp": exp,
        "iss": iss,
    }

    # Prefer RS256 with explicit kid header, fallback to configured HS*
    rsa = _load_rsa_private_key()
    headers = {}
    if rsa:
        priv_pem, kid = rsa
        if kid:
            headers["kid"] = kid
        alg = "RS256"
        token = jwt.encode(payload, priv_pem, algorithm=alg, headers=headers)
    else:
        alg = settings.JWT_ALGORITHM
        token = jwt.encode(payload, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=alg)

    # Register JTI validity lane for revocation checks
    try:
        ttl_seconds = int((exp - now).total_seconds())
        await redis_wrapper.client.setex(f"access:jti:{jti}", ttl_seconds, "valid")
    except Exception:  # pragma: no cover
        logger.exception("Failed to register service access JTI in Redis")

    return token, payload


# -- Introspection & revocation ----------------------------------------------

async def introspect_token(raw_token: str) -> Dict[str, Any]:
    """Return RFC 7662-style active/introspection JSON for a token.

    Attempts symmetric decode first, then RSA public if configured.
    """
    payload: Optional[Dict[str, Any]] = None
    algs_hs = [settings.JWT_ALGORITHM]
    try:
        payload = jwt.decode(raw_token, settings.JWT_SECRET_KEY.get_secret_value(), algorithms=algs_hs)
        alg_used = algs_hs[0]
    except Exception:
        # Try RSA
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            pub_pem = getattr(settings, "OIDC_RSA_PUBLIC_KEY_PEM", None)  # type: ignore[attr-defined]
            if not pub_pem:
                path = getattr(settings, "OIDC_RSA_PUBLIC_KEY_PATH", None)  # type: ignore[attr-defined]
                if path:
                    with open(path, "r", encoding="utf-8") as f:
                        pub_pem = f.read()
            if pub_pem:
                payload = jwt.decode(raw_token, pub_pem, algorithms=["RS256", "RS512", "RS384"])
                alg_used = "RS256"
        except Exception:  # pragma: no cover
            payload = None
            alg_used = None  # type: ignore

    if not payload:
        return {"active": False}

    # Basic checks and revocation lane lookup
    jti = str(payload.get("jti", ""))
    revoked = False
    if jti:
        try:
            revoked = bool(await redis_wrapper.client.get(f"revoked:jti:{jti}"))
        except Exception:
            revoked = False

    # Exp check; jose already validated exp but tolerate parsing
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        exp_ts = int(exp)
    else:
        try:
            exp_ts = int(datetime.fromisoformat(str(exp)).timestamp())
        except Exception:
            exp_ts = None  # type: ignore

    if revoked:
        return {"active": False}

    # Shape response
    resp: Dict[str, Any] = {
        "active": True,
        "token_type": payload.get("token_type") or payload.get("type") or "access",
        "client_id": payload.get("client_id"),
        "scope": payload.get("scope", ""),
        "sub": payload.get("sub"),
        "iss": payload.get("iss"),
        "aud": payload.get("aud"),
        "jti": jti or None,
        "exp": exp_ts,
        "iat": int(payload.get("iat", 0)) if isinstance(payload.get("iat"), (int, float)) else None,
        "nbf": int(payload.get("nbf", 0)) if isinstance(payload.get("nbf"), (int, float)) else None,
        "alg": alg_used,
    }
    return resp


async def revoke_token(raw_token: str) -> None:
    """Decode token and mark its JTI as revoked in Redis.

    For refresh tokens, callers may also update DB state separately,
    but revocation lane ensures immediate effect for all consumers.
    """
    try:
        # Try decode without caring which algorithm; we only need JTI and exp
        payload = jwt.get_unverified_claims(raw_token)
        header = jwt.get_unverified_header(raw_token)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token") from e

    jti = str(payload.get("jti", ""))
    exp = payload.get("exp")
    if not jti or not exp:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token missing jti/exp")
    try:
        exp_ts = int(exp)
    except Exception:
        try:
            exp_ts = int(datetime.fromisoformat(str(exp)).timestamp())
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid exp in token") from e

    ttl = max(1, int(exp_ts - datetime.now(timezone.utc).timestamp()))
    try:
        await redis_wrapper.client.setex(f"revoked:jti:{jti}", ttl, "revoked")
    except Exception as e:  # pragma: no cover
        logger.exception("Redis revocation set failed: %s", e)
        raise HTTPException(status_code=503, detail="Revocation store unavailable")


__all__ = [
    "authenticate_client",
    "create_service_access_token",
    "introspect_token",
    "revoke_token",
]
