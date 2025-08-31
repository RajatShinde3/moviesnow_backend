from __future__ import annotations

import hmac
import hashlib
import os
import time
import logging
from enum import Enum
from pydantic import BaseModel
from fastapi import HTTPException


logger = logging.getLogger(__name__)


class SignedURL(BaseModel):
    url: str
    expires_at: int
    token: str


class QualityEnum(str, Enum):
    auto = "auto"
    q240p = "240p"
    q480p = "480p"
    q720p = "720p"
    q1080p = "1080p"
    q2160p = "2160p"


def generate_signed_url(
    *,
    resource_path: str,
    quality: QualityEnum,
    expires_in: int = 3600,
    purpose: str = "stream",
) -> SignedURL:
    """
    Generate a CDN-friendly HMAC-signed URL for streaming/download.

    Env:
      - STREAM_URL_SIGNING_SECRET: required in production. If not set and
        ALLOW_DEV_SIGNING is true, uses a dev secret (logs a warning).
      - STREAM_BASE_URL: base URL for signed resources (default: /media).
      - ALLOW_DEV_SIGNING: set to 1/true to allow missing secret in dev.
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

    # Normalize and harden path
    resource_path = "/" + resource_path.lstrip("/")
    safe_path = "/" + "/".join([seg for seg in resource_path.split("/") if seg and seg not in {"..", "."}])

    # token: HMAC(secret, path|purpose|quality|exp)
    to_sign = f"{safe_path}|{purpose}|{quality.value}|{exp}".encode("utf-8")
    sig = hmac.new(secret, to_sign, hashlib.sha256).hexdigest()
    url = f"{base_url}{safe_path}?q={quality.value}&exp={exp}&sig={sig}&use={purpose}"
    return SignedURL(url=url, expires_at=exp, token=sig)

