from __future__ import annotations

"""
Admin CDN cookies (CloudFront signed cookies)
---------------------------------------------
Best-effort endpoint to mint CloudFront signed cookies given a private key.

Requirements
------------
- Env CF_KEY_PAIR_ID and CF_PRIVATE_KEY_PEM must be set.
- `cryptography` must be installed.

Notes
-----
- Uses a canned-policy style: domain/path scope via resource pattern
  (e.g., https://d123.cloudfront.net/downloads/*), TTL enforced by `expires`.
- This endpoint **returns values** for the three cookie names:
    CloudFront-Policy, CloudFront-Signature, CloudFront-Key-Pair-Id
  (it does NOT set cookies on the response because domains typically differ).
- For production, consider CloudFront key groups & modern policies; validate carefully.
"""

# ─────────────────────────────────────────────────────────────────────────────
# 🔐 Admin · CDN Router
# ─────────────────────────────────────────────────────────────────────────────

import os
import time
import json
import base64
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
import logging
logger = logging.getLogger(__name__)

from app.core.limiter import rate_limit
from app.security_headers import set_sensitive_cache
from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa

router = APIRouter(tags=["Admin · CDN"])

__all__ = ["router"]


# ─────────────────────────────────────────────────────────────────────────────
# 📦 Models
# ─────────────────────────────────────────────────────────────────────────────

class SignedCookiesIn(BaseModel):
    resource: str = Field(
        ...,
        description="CloudFront resource pattern (e.g., https://dX.cloudfront.net/downloads/*)",
        examples=["https://d1234abcd.cloudfront.net/downloads/*"],
    )
    ttl_seconds: int = Field(
        600,
        ge=60,
        le=86400,
        description="Cookie TTL in seconds (min 60, max 86400).",
    )


class SignedCookiesOut(BaseModel):
    CloudFront_Policy: str = Field(..., alias="CloudFront-Policy")
    CloudFront_Signature: str = Field(..., alias="CloudFront-Signature")
    CloudFront_Key_Pair_Id: str = Field(..., alias="CloudFront-Key-Pair-Id")
    expires: str


# ─────────────────────────────────────────────────────────────────────────────
# ⚙️ Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _urlsafe_b64_nopad(b: bytes) -> str:
    """URL-safe base64 without padding, per CloudFront cookie requirements."""
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _normalize_pem_from_env(raw: str) -> bytes:
    """
    Cloud-friendly normalization for PEM stored in env:
    - Allows \n-escaped single-line strings.
    - Returns bytes ready for cryptography.load_pem_private_key.
    """
    s = (raw or "").strip()
    if not s:
        return b""
    if "-----BEGIN" in s and "\\n" in s:
        s = s.replace("\\n", "\n")
    return s.encode("utf-8")


def _validate_resource_pattern(resource: str) -> None:
    """
    Minimal, opinionated validation for resource patterns:
    - Must start with http(s)://
    - Must include a path starting with /downloads/ (policy requirement)
    - May end with '*' wildcard
    - No query/fragment allowed
    """
    from urllib.parse import urlparse
    r = (resource or "").strip()
    if not (r.startswith("https://") or r.startswith("http://")):
        raise HTTPException(status_code=400, detail="resource must start with https:// or http://")
    parts = urlparse(r)
    if not parts.netloc:
        raise HTTPException(status_code=400, detail="resource must include a host")
    if not parts.path or not parts.path.startswith("/downloads/"):
        raise HTTPException(status_code=400, detail="path must start with /downloads/")
    if parts.query or parts.fragment:
        raise HTTPException(status_code=400, detail="resource must not include query or fragment")
    # allow trailing wildcard; no further normalization needed


# ─────────────────────────────────────────────────────────────────────────────
# 🍪 Mint CloudFront signed cookies
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/cdn/signed-cookies",
    summary="Mint CloudFront signed cookies",
    response_model=SignedCookiesOut,
    responses={
        200: {"description": "Cookies minted"},
        400: {"description": "Invalid input"},
        401: {"description": "Unauthorized (admin/MFA)"},
        403: {"description": "Forbidden"},
        503: {"description": "Signing unavailable or failed"},
    },
)
@rate_limit("10/minute")
async def mint_signed_cookies(
    payload: SignedCookiesIn,
    request: Request,
    response: Response,
    _adm=Depends(_ensure_admin),
    _mfa=Depends(_ensure_mfa),
) -> SignedCookiesOut:
    """
    Create the values for CloudFront signed cookies using a **canned policy**:

    Policy
    ------
    - Resource pattern is your CloudFront domain + path prefix (e.g., ``.../downloads/*``).
    - Expiration is enforced via ``AWS:EpochTime``.

    Security
    --------
    - Returns neutral 503 errors when signing is unavailable to avoid leaking config details.
    - Responses marked `Cache-Control: no-store`.
    """
    set_sensitive_cache(response)

    # Validate resource pattern early (opinionated)
    _validate_resource_pattern(payload.resource)

    key_pair_id = os.getenv("CF_KEY_PAIR_ID", "").strip()
    priv_pem_env = os.getenv("CF_PRIVATE_KEY_PEM", "")
    private_pem = _normalize_pem_from_env(priv_pem_env)

    if not key_pair_id or not private_pem:
        raise HTTPException(status_code=503, detail="Signing unavailable")

    try:
        # cryptography imports (lazy) — keep import errors neutral
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
    except Exception as e:
        logger.info("cdn.signed-cookies unavailable: %s", e)
        raise HTTPException(status_code=503, detail="Signing unavailable")

    # Build canned policy
    expires = int(time.time()) + int(payload.ttl_seconds)
    policy_obj = {
        "Statement": [
            {
                "Resource": payload.resource,
                "Condition": {"DateLessThan": {"AWS:EpochTime": expires}},
            }
        ]
    }
    policy_json = json.dumps(policy_obj, separators=(",", ":"), ensure_ascii=False)
    policy_b64 = _urlsafe_b64_nopad(policy_json.encode("utf-8"))

    # RSA-SHA1 per CloudFront signed cookie requirements
    try:
        private_key = load_pem_private_key(private_pem, password=None)
        signature = private_key.sign(
            policy_json.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA1(),
        )
    except Exception as e:
        logger.info("cdn.signed-cookies signing failed: %s", e)
        raise HTTPException(status_code=503, detail="Signing failed")

    sig_b64 = _urlsafe_b64_nopad(signature)

    # Return cookie values (caller must set them for the CloudFront domain)
    return SignedCookiesOut(
        **{
            "CloudFront-Policy": policy_b64,
            "CloudFront-Signature": sig_b64,
            "CloudFront-Key-Pair-Id": key_pair_id,
            "expires": str(expires),
        }
    )
