# app/core/jwt.py
from __future__ import annotations

"""
MoviesNow — JWT helpers (hardened, org-free)
============================================
- Robust `decode_token` with optional issuer/audience enforcement
- Redis JTI revocation lane (`revoked:jti:{jti}`)
- Case-insensitive Bearer token extraction
- Convenience to decode directly from a FastAPI `Request`
- Thin `decode_access_token()` wrapper (access-only)

Notes
-----
- Token *creation* lives in `app.core.security`.
- No `leeway` is passed to python-jose (unsupported); standard `exp`/`nbf`/`iat` checks apply.
- If Redis is temporarily unavailable, behavior is controlled by `AUTH_FAIL_OPEN`
  (default: False → fail-closed with HTTP 503).
"""

from typing import Optional, Sequence, Dict, Any
import logging
import os

from fastapi import HTTPException, Request, status
from jose import jwt, JWTError, ExpiredSignatureError

from app.core.config import settings
from app.core.redis_client import redis_wrapper
from app.schemas.auth import TokenPayload

logger = logging.getLogger("auth")


# ─────────────────────────────────────────────────────────────
# 🔧 Internal helpers
# ─────────────────────────────────────────────────────────────

def _get_expected_issuer() -> Optional[str]:
    return getattr(settings, "JWT_ISSUER", None) or None


def _get_expected_audience() -> Optional[str]:
    return getattr(settings, "JWT_AUDIENCE", None) or None


def _bool_env(name: str, default: bool = False) -> bool:
    val = getattr(settings, name, default)
    if isinstance(val, str):
        return val.lower() in {"1", "true", "yes", "on"}
    return bool(val)


async def _is_revoked(jti: str) -> bool:
    """Return True if the token with this JTI is revoked.

    Redis key: `revoked:jti:{jti}`.

    Behavior:
    - Prefer GET; fall back to EXISTS for minimal/mocked clients.
    - If neither op exists, treat as NOT revoked (test/mocked env).
    - On real Redis errors: fail-open if AUTH_FAIL_OPEN, else 503.
    """
    key = f"revoked:jti:{jti}"
    rc = getattr(redis_wrapper, "client", None)

    # No Redis client configured → treat as not revoked (tests/dev).
    if rc is None:
        return False

    try:
        if hasattr(rc, "get"):
            return bool(await rc.get(key))
        if hasattr(rc, "exists"):
            return bool(await rc.exists(key))
        # Extremely skinny mock: no get/exists
        logger.warning("Redis client lacks get/exists; assuming not revoked (test env).")
        return False

    except Exception as e:  # real runtime/IO errors
        if _bool_env("AUTH_FAIL_OPEN", False):
            logger.error(f"Redis unavailable during revocation check (fail-open): {e}")
            return False
        logger.error(f"Redis unavailable during revocation check (fail-closed): {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth service temporarily unavailable.",
        )


# ─────────────────────────────────────────────────────────────
# 🔓 Decode JWT Token with Redis JTI Revocation Check (Async)
# ─────────────────────────────────────────────────────────────
async def decode_token(
    token: str,
    *,
    expected_types: Optional[Sequence[str]] = None,
    verify_revocation: bool = True,
) -> Dict[str, Any]:
    """Decode and validate a JWT.

    Security checks
    ---------------
    1) Verify signature and standard claims (exp/nbf/iat)
    2) Enforce issuer/audience when configured
    3) Require `jti` and optional `token_type` membership
    4) Consult Redis revocation lane

    Raises
    ------
    HTTPException
      - 401 for invalid/expired tokens or type mismatch
      - 503 if Redis is down and fail-closed is configured
    """
    issuer = _get_expected_issuer()
    audience = _get_expected_audience()

    # Build python-jose options. We intentionally avoid any unsupported `leeway`.
    options: Dict[str, Any] = {
        "verify_aud": bool(audience),  # only if audience is configured
        # other defaults verify exp/nbf/iat
    }

    # 1) Decode & base checks (supports JWKS-based verification when enabled)
    try:
        use_jwks = str(getattr(settings, "JWT_VERIFY_WITH_JWKS", os.getenv("JWT_VERIFY_WITH_JWKS", "0"))).lower() in {"1", "true", "yes", "on"}
        key = settings.JWT_SECRET_KEY.get_secret_value()
        algs = [settings.JWT_ALGORITHM]
        if use_jwks:
            try:
                header = jwt.get_unverified_header(token)
                kid = header.get("kid")
                alg = header.get("alg")
                if kid and alg:
                    from app.services.jwks_service import get_public_jwks  # local import to avoid cycles
                    jwks = await get_public_jwks()
                    for k in jwks.get("keys", []):
                        if k.get("kid") == kid and k.get("alg") == alg:
                            key = k
                            algs = [alg]
                            break
            except Exception:
                # Fall back to symmetric secret
                pass

        payload = jwt.decode(
            token,
            key,
            algorithms=algs,
            options=options,
            audience=audience if audience else None,
            issuer=issuer if issuer else None,
        )
    except ExpiredSignatureError:
        logger.info("Token expired.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired.")
    except JWTError as e:
        logger.warning(f"JWT decoding failed: {e}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token.")
    except Exception:  # pragma: no cover — unexpected
        logger.exception("Unexpected error during JWT decoding.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unexpected error while decoding token.")

    # 2) Required subject
    sub = payload.get("sub") or payload.get("user_id")
    if not sub:
        logger.warning("Missing user_id/sub in token payload.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing user ID.")

    # 3) Required JTI
    jti = payload.get("jti")
    if not jti:
        logger.warning("Missing JTI in token.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing JTI.")

    # 4) Token type enforcement (if caller specified)
    if expected_types is not None:
        token_type = payload.get("token_type")
        if token_type not in set(expected_types):
            logger.warning(
                f"Token type mismatch: got '{token_type}', expected one of {list(expected_types)}"
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type.")

    # 5) Revocation lane check
    if verify_revocation and await _is_revoked(jti):
        logger.warning(f"Token with JTI {jti} has been revoked.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked.")

    return payload


# ─────────────────────────────────────────────────────────────
# 📥 Extract Bearer Token from Authorization Header
# ─────────────────────────────────────────────────────────────
def get_bearer_token(request: Request) -> str:
    """Extract a Bearer token from the `Authorization` header (case-insensitive)."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        logger.warning("Missing Authorization header.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header.")

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        logger.warning(f"Malformed Authorization header: {auth_header}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Authorization scheme.")

    token = parts[1].strip()
    if not token:
        logger.warning("Empty Bearer token.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Empty token.")

    return token


# ─────────────────────────────────────────────────────────────
# 📦 Decode Token Payload from Authorization Header
# ─────────────────────────────────────────────────────────────
async def get_token_payload(request: Request) -> Dict[str, Any]:
    """Decode a JWT directly from a `Request`'s Authorization header."""
    token = get_bearer_token(request)
    payload = await decode_token(token)
    logger.debug(f"Decoded JWT payload: sub={payload.get('sub')}")
    return payload


# ─────────────────────────────────────────────────────────────
# ✅ Parse & Validate Token Payload into Pydantic Model
# ─────────────────────────────────────────────────────────────
async def get_token_payload_model(request: Request) -> TokenPayload:
    """Decode a JWT and return a structured `TokenPayload`."""
    token = get_bearer_token(request)
    try:
        payload_dict = await decode_token(token)
        payload = TokenPayload(**payload_dict)
        logger.debug(f"Validated TokenPayload: sub={payload.sub}")
        return payload
    except HTTPException:
        raise
    except Exception as e:  # pragma: no cover
        logger.error(f"Unexpected error parsing TokenPayload: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token payload structure.")


# ─────────────────────────────────────────────────────────────
# 🧩 Backwards-compat shim
# ─────────────────────────────────────────────────────────────
async def decode_access_token(token: str) -> Dict[str, Any]:
    """Compat wrapper for legacy imports; enforces `token_type == 'access'`."""
    return await decode_token(token, expected_types=["access"], verify_revocation=True)


__all__ = [
    "decode_token",
    "decode_access_token",
    "get_bearer_token",
    "get_token_payload",
    "get_token_payload_model",
]
