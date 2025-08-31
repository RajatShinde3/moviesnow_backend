from __future__ import annotations

"""
Signing utilities for time-limited media URLs.

Best practices applied:
- Single source of truth for stream quality enum (reuse API schema enum).
- Hardened path normalization to prevent path traversal.
- Clear, concise docstrings for generated tokens/URLs.
"""

import hashlib
import hmac
import logging
import os
import time

from fastapi import HTTPException
from pydantic import BaseModel

# Reuse the public API enum instead of redefining it here
from app.schemas.titles import QualityEnum  # re-exported below for compatibility


logger = logging.getLogger(__name__)


class SignedURL(BaseModel):
    """Data returned when issuing a signed media URL.

    - url: Fully-qualified path including query params (q, exp, sig, use).
    - expires_at: Epoch seconds when the URL stops being valid.
    - token: The HMAC signature (hex) over path|purpose|quality|exp.
    """

    url: str
    expires_at: int
    token: str


def generate_signed_url(
    *,
    resource_path: str,
    quality: QualityEnum,
    expires_in: int = 3600,
    purpose: str = "stream",
) -> SignedURL:
    """Generate a CDN-friendly HMAC-signed URL for streaming/download.

    Environment variables:
    - STREAM_URL_SIGNING_SECRET: Required in production. If missing and
      ALLOW_DEV_SIGNING is truthy, a dev secret is used (with a warning).
    - STREAM_BASE_URL: Base URL prefix for signed resources (default: "/media").
    - ALLOW_DEV_SIGNING: Set to 1/true to allow missing secret in dev.
    """
    base_url = os.environ.get("STREAM_BASE_URL", "/media")
    secret_env = os.environ.get("STREAM_URL_SIGNING_SECRET")
    allow_dev = os.environ.get("ALLOW_DEV_SIGNING") in {"1", "true", "True"}
    if not secret_env:
        if allow_dev:
            secret_env = "dev-secret-change-me"
            logger.warning("STREAM_URL_SIGNING_SECRET missing; using dev-secret (DEV MODE)")
        else:
            raise HTTPException(status_code=500, detail="Signing secret not configured")
    secret = secret_env.encode("utf-8")

    now = int(time.time())
    exp = now + int(expires_in)

    # Normalize and harden the path
    resource_path = "/" + resource_path.lstrip("/")
    safe_path = "/" + "/".join([seg for seg in resource_path.split("/") if seg and seg not in {"..", "."}])

    # token: HMAC(secret, path|purpose|quality|exp)
    to_sign = f"{safe_path}|{purpose}|{quality.value}|{exp}".encode("utf-8")
    sig = hmac.new(secret, to_sign, hashlib.sha256).hexdigest()
    url = f"{base_url}{safe_path}?q={quality.value}&exp={exp}&sig={sig}&use={purpose}"
    return SignedURL(url=url, expires_at=exp, token=sig)


# Re-export for legacy imports: from app.services.signing import QualityEnum
__all__ = ["SignedURL", "QualityEnum", "generate_signed_url"]
