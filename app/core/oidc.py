from __future__ import annotations

"""
OIDC and JWKS helpers.

Responsibilities:
- Load RSA keys from settings/env for asymmetric JWTs used in service-to-service auth.
- Publish a RFC 7517-compliant JWKS containing public keys only.
- Provide OpenID Connect discovery metadata with stable URLs.

Notes
-----
- Existing user JWTs are HS*-signed (symmetric). JWKS is only meaningful for
  asymmetric (RS/EC) keys; when no RSA public key is configured, JWKS returns
  an empty `keys` array.
- Discovery `issuer` prefers a configured URL; otherwise falls back to
  `settings.public_base_url_str`.
"""

from typing import Any, Dict, Optional
import base64
import json
import logging

from app.core.config import settings

logger = logging.getLogger("oidc")


# -- RSA key handling ---------------------------------------------------------
_RS256 = "RS256"


def _load_rsa_public_numbers() -> Optional[tuple[int, int, str]]:
    """Return (n, e, kid) for configured RSA public key or None if unavailable.

    Sources (in order):
    - settings.OIDC_RSA_PUBLIC_KEY_PEM (PEM string)
    - settings.OIDC_RSA_PUBLIC_KEY_PATH (filesystem path)

    Also reads settings.OIDC_KID for stable key id; generates a trivial one
    when missing (not stable across restarts).
    """
    pem: Optional[str] = None
    try:
        pem = getattr(settings, "OIDC_RSA_PUBLIC_KEY_PEM", None)  # type: ignore[attr-defined]
    except Exception:
        pem = None

    if not pem:
        try:
            path = getattr(settings, "OIDC_RSA_PUBLIC_KEY_PATH", None)  # type: ignore[attr-defined]
        except Exception:
            path = None
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    pem = f.read()
            except Exception as e:  # pragma: no cover
                logger.warning("Failed to read OIDC public key from path: %s", e)
                pem = None

    if not pem:
        return None

    try:
        # Lazy import to avoid hard deps elsewhere
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        public_key = serialization.load_pem_public_key(pem.encode("utf-8"), backend=default_backend())
        numbers = public_key.public_numbers()
        n: int = numbers.n  # type: ignore[attr-defined]
        e: int = numbers.e  # type: ignore[attr-defined]
    except Exception as e:  # pragma: no cover
        logger.error("Invalid RSA public key for OIDC: %s", e)
        return None

    try:
        kid = getattr(settings, "OIDC_KID", None)  # type: ignore[attr-defined]
    except Exception:
        kid = None
    if not kid:
        # Non-stable fallback kid derived from modulus length (dev only)
        kid = f"rsa-{(n.bit_length() + 7) // 8}b"
    return n, e, str(kid)


def _b64url_uint(val: int) -> str:
    """Base64url encode an integer without leading zero bytes or padding."""
    if val == 0:
        return "AA"  # unlikely for RSA, but valid base64url for 0x00
    b = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def build_jwks() -> Dict[str, Any]:
    """Return JWKS dict with RS256 public keys when configured.

    Returns
    -------
    {"keys": [...]} where each key is a JWK public representation.
    """
    info = _load_rsa_public_numbers()
    if not info:
        return {"keys": []}
    n, e, kid = info
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": _RS256,
        "kid": kid,
        "n": _b64url_uint(n),
        "e": _b64url_uint(e),
    }
    return {"keys": [jwk]}


def issuer_url() -> str:
    """Best-effort OIDC issuer URL.

    Preference order:
    1) settings.OIDC_ISSUER (if present and looks like a URL)
    2) settings.public_base_url_str
    3) "http://localhost:8000"
    """
    try:
        iss = getattr(settings, "OIDC_ISSUER", None)  # type: ignore[attr-defined]
        if isinstance(iss, str) and iss.startswith(("http://", "https://")):
            return iss.rstrip("/")
    except Exception:
        pass
    try:
        base = settings.public_base_url_str or "http://localhost:8000"
    except Exception:  # pragma: no cover
        base = "http://localhost:8000"
    return base.rstrip("/")


def build_openid_configuration() -> Dict[str, Any]:
    """Construct a minimal OIDC discovery document for service tokens.

    This advertises only the endpoints we provide: `jwks_uri`, `token_endpoint`,
    `introspection_endpoint`, and `revocation_endpoint`.
    """
    iss = issuer_url()
    return {
        "issuer": iss,
        "jwks_uri": f"{iss}/.well-known/jwks.json",
        "token_endpoint": f"{iss}/oauth2/token",
        "introspection_endpoint": f"{iss}/oauth2/introspect",
        "revocation_endpoint": f"{iss}/oauth2/revoke",
        "scopes_supported": [
            "read", "write", "admin",
        ],
        "grant_types_supported": ["client_credentials"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic", "client_secret_post",
        ],
        "id_token_signing_alg_values_supported": ["HS256", "RS256"],
    }


__all__ = ["build_jwks", "build_openid_configuration", "issuer_url"]

