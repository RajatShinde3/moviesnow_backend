# app/utils/aws.py
from __future__ import annotations

"""
🧊 MoviesNow • S3 Utilities
===========================

Hardened, production-ready S3 wrapper used by:
- Admin Assets (artwork, trailers, subtitles, streams)
- Generic uploads (single & multipart)
- Delivery (short-lived signed GET)
- CDN-aware public URL building

🎯 Goals
--------
- Safe presigned PUT/GET (v4 signing) with optional SSE/KMS
- Explicit timeouts + retry policy
- Defensive key normalization (no leading slash, no `..`)
- Pluggable creds (env/role/IRSA) with explicit override if provided
- Optional CDN base URL for public asset links
- Zero secret leakage in logs

🔗 Compatibility
---------------
Routers call these directly (do **not** rename):
- `S3Client`, `S3StorageError`
- `S3Client.presigned_put(...)`
- `S3Client.presigned_get(...)`
- `S3Client.put_bytes(...)`
- `S3Client.delete(...)`
- `S3Client.client` (for multipart: create/part/complete/abort)
"""

from typing import Dict, Optional, Tuple, Any
import logging
import os
import re

try:
    from pydantic import SecretStr  # for type hints only
except Exception:  # pragma: no cover
    SecretStr = str  # type: ignore

import botocore
from botocore.config import Config as BotoConfig
import boto3

from app.core.config import settings

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# 🧱 Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class S3StorageError(RuntimeError):
    """Raised when a storage operation fails (network, auth, policy, etc.)."""


# ─────────────────────────────────────────────────────────────────────────────
# 🧱 Helpers (key normalization, env access)
# ─────────────────────────────────────────────────────────────────────────────

_KEY_ALLOWED_RE = re.compile(r"[A-Za-z0-9._\-/+=@() ]+")


def _normalize_key(key: str) -> str:
    """
    🧰 Normalize and validate S3 keys:
      - strip whitespace
      - drop leading `/`
      - collapse `//`
      - reject traversal (`..`) and disallowed characters
    """
    k = str(key or "").strip().lstrip("/")
    k = re.sub(r"/{2,}", "/", k)
    if ".." in k:
        raise S3StorageError("Invalid storage key: path traversal detected")
    if not _KEY_ALLOWED_RE.fullmatch(k):
        raise S3StorageError("Invalid storage key: contains forbidden characters")
    if not k:
        raise S3StorageError("Invalid storage key: empty")
    return k


def _secret_value(v: Optional[SecretStr | str]) -> Optional[str]:
    if v is None:
        return None
    try:
        # pydantic SecretStr
        return v.get_secret_value() if hasattr(v, "get_secret_value") else str(v)
    except Exception:
        return str(v)


# ─────────────────────────────────────────────────────────────────────────────
# 📦 S3 Client
# ─────────────────────────────────────────────────────────────────────────────

class S3Client:
    """
    📦 High-level S3 wrapper with safe defaults.

    Parameters
    ----------
    bucket : Optional[str]
        Bucket name. Defaults to `settings.AWS_BUCKET_NAME`.
    region_name : Optional[str]
        Region. Defaults to `settings.AWS_REGION` (falls back to bucket location if empty).
    endpoint_url : Optional[str]
        Custom endpoint (S3-compatible). Defaults to `settings.AWS_S3_ENDPOINT_URL` if present.
    cdn_base_url : Optional[str]
        CDN base (e.g., https://cdn.example.com). If set, `cdn_url()` joins this with keys.
    use_public_acls : bool
        For rare cases where ACLs are allowed. Defaults False (modern buckets disable ACLs).
    sse_mode : Optional[str]
        Server-side encryption mode: "AES256" or "aws:kms". Defaults from `settings.AWS_SSE_MODE`.
    kms_key_id : Optional[str]
        KMS key id/arn. Defaults from `settings.AWS_KMS_KEY_ID`.

    Notes
    -----
    - Credentials: If explicit `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` exist in settings,
      they are used. Otherwise, rely on the **standard AWS credential chain** (env, profile, IAM role, IRSA).
    - Retries: Standard botocore retries with bounded attempts.
    - Timeouts: small connect timeout + moderate read timeout to fail fast.
    """

    def __init__(
        self,
        bucket: Optional[str] = None,
        *,
        region_name: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        cdn_base_url: Optional[str] = None,
        use_public_acls: bool = False,
        sse_mode: Optional[str] = None,
        kms_key_id: Optional[str] = None,
    ) -> None:
        # ── Read config from settings
        self.bucket = bucket or getattr(settings, "AWS_BUCKET_NAME", None)
        if not self.bucket:
            raise S3StorageError("AWS_BUCKET_NAME not configured")

        region_cfg = region_name or getattr(settings, "AWS_REGION", None)
        endpoint_cfg = endpoint_url or getattr(settings, "AWS_S3_ENDPOINT_URL", None)

        # Optional CDN base (normalized, no trailing slash)
        cdn_env = cdn_base_url or getattr(settings, "cdn_base_url", None) or getattr(settings, "CDN_BASE_URL", None)
        self._cdn_base = (cdn_env or "").rstrip("/")

        # SSE defaults
        self._sse_mode = sse_mode or getattr(settings, "AWS_SSE_MODE", None)
        self._kms_key_id = kms_key_id or getattr(settings, "AWS_KMS_KEY_ID", None)

        # ── Build boto3 client with safe defaults
        cfg = BotoConfig(
            signature_version="s3v4",
            retries={"max_attempts": 5, "mode": "standard"},
            connect_timeout=3,
            read_timeout=10,
            s3={"addressing_style": "virtual"},
        )

        # Use explicit keys only if provided; otherwise rely on default chain
        ak = getattr(settings, "AWS_ACCESS_KEY_ID", None)
        sk = _secret_value(getattr(settings, "AWS_SECRET_ACCESS_KEY", None))
        st = _secret_value(getattr(settings, "AWS_SESSION_TOKEN", None))

        client_kwargs: Dict[str, Any] = {"config": cfg}
        if region_cfg:
            client_kwargs["region_name"] = region_cfg
        if endpoint_cfg:
            client_kwargs["endpoint_url"] = endpoint_cfg

        if ak and sk:
            client_kwargs.update(
                aws_access_key_id=ak,
                aws_secret_access_key=sk,
            )
            if st:
                client_kwargs["aws_session_token"] = st

        try:
            self.client = boto3.client("s3", **client_kwargs)
        except Exception as e:  # pragma: no cover
            raise S3StorageError(f"Failed to create S3 client: {e}") from e

        # If region not specified, try to infer from bucket location (once)
        self.region = region_cfg or self._infer_region_safely()

        # ACL policy flag (most modern buckets have ACLs disabled)
        self._use_public_acls = bool(use_public_acls)

        # Safe, minimal `__repr__` (no secrets)
        self._repr = f"S3Client(bucket={self.bucket}, region={self.region}, endpoint={'yes' if endpoint_cfg else 'no'})"

    # ────────────────────────────────────────────────────────────────────────
    # 🔐  Signed URL helpers
    # ────────────────────────────────────────────────────────────────────────

    def presigned_put(
        self,
        key: str,
        *,
        content_type: str,
        public: bool = False,
        expires_in: int = 900,
        cache_control: Optional[str] = None,
        content_disposition: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        🔐 Generate a presigned PUT URL (v4) for direct-to-S3 uploads.

        Parameters
        ----------
        key : str
            Object key (will be normalized; no leading `/`, no `..`).
        content_type : str
            MIME type clients **must** include on upload.
        public : bool
            If True and bucket allows ACLs, sets `ACL=public-read`.
        expires_in : int
            URL TTL seconds (default 15m).
        cache_control : Optional[str]
            Optional response caching directive to store with object metadata.
        content_disposition : Optional[str]
            Optional `Content-Disposition` metadata.
        extra_headers : Optional[Dict[str, str]]
            Additional request parameters (e.g., SSE headers). Values are **not** logged.

        Returns
        -------
        str
            Fully signed URL for HTTP PUT.
        """
        k = _normalize_key(key)

        params: Dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": k,
            "ContentType": content_type,
        }

        # Server-side encryption policy
        sse_mode = (extra_headers or {}).get("ServerSideEncryption") or self._sse_mode
        kms_key = (extra_headers or {}).get("SSEKMSKeyId") or self._kms_key_id
        if sse_mode:
            params["ServerSideEncryption"] = sse_mode
            if sse_mode == "aws:kms" and kms_key:
                params["SSEKMSKeyId"] = kms_key

        if cache_control:
            params["CacheControl"] = cache_control
        if content_disposition:
            params["ContentDisposition"] = content_disposition
        if public and self._use_public_acls:
            params["ACL"] = "public-read"

        # Merge any additional safe headers
        for hk, hv in (extra_headers or {}).items():
            # Protect core parameters from being clobbered by mistake
            if hk in {"Bucket", "Key", "Expires"}:
                continue
            params[hk] = hv

        try:
            url = self.client.generate_presigned_url(
                ClientMethod="put_object",
                Params=params,
                ExpiresIn=int(expires_in),
                HttpMethod="PUT",
            )
            return url
        except Exception as e:
            raise S3StorageError(f"Failed to create presigned PUT: {e}") from e

    def presigned_get(
        self,
        key: str,
        *,
        expires_in: int = 300,
        response_content_type: Optional[str] = None,
        response_content_disposition: Optional[str] = None,
    ) -> str:
        """
        🔐 Generate a short-lived presigned GET URL.

        Parameters
        ----------
        key : str
            Object key.
        expires_in : int
            TTL in seconds (default 5m).
        response_content_type : Optional[str]
            Force response content-type (useful for downloads/previews).
        response_content_disposition : Optional[str]
            e.g., `attachment; filename="..."` for downloads.
        """
        k = _normalize_key(key)
        params: Dict[str, Any] = {"Bucket": self.bucket, "Key": k}
        if response_content_type:
            params["ResponseContentType"] = response_content_type
        if response_content_disposition:
            params["ResponseContentDisposition"] = response_content_disposition

        try:
            return self.client.generate_presigned_url(
                ClientMethod="get_object",
                Params=params,
                ExpiresIn=int(expires_in),
            )
        except Exception as e:
            raise S3StorageError(f"Failed to create presigned GET: {e}") from e

    # ────────────────────────────────────────────────────────────────────────
    # 🚀  Direct server-side ops (small files, best-effort delete)
    # ────────────────────────────────────────────────────────────────────────

    def put_bytes(
        self,
        key: str,
        data: bytes,
        *,
        content_type: str,
        public: bool = False,
        cache_control: Optional[str] = None,
        content_disposition: Optional[str] = None,
        extra_args: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        🚀 Upload small payloads from the server (<= ~10MB ideal).

        Notes
        -----
        Prefer presigned PUT from clients. This is used by the
        `/uploads/direct-proxy` endpoint for tiny objects.
        """
        k = _normalize_key(key)
        args: Dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": k,
            "Body": data,
            "ContentType": content_type,
        }

        if cache_control:
            args["CacheControl"] = cache_control
        if content_disposition:
            args["ContentDisposition"] = content_disposition

        # SSE defaulting
        sse_mode = (extra_args or {}).get("ServerSideEncryption") or self._sse_mode
        kms_key = (extra_args or {}).get("SSEKMSKeyId") or self._kms_key_id
        if sse_mode:
            args["ServerSideEncryption"] = sse_mode
            if sse_mode == "aws:kms" and kms_key:
                args["SSEKMSKeyId"] = kms_key

        if public and self._use_public_acls:
            args["ACL"] = "public-read"

        # Merge extra args (safe)
        for karg, varg in (extra_args or {}).items():
            if karg in {"Bucket", "Key", "Body"}:
                continue
            args[karg] = varg

        try:
            self.client.put_object(**args)
        except Exception as e:
            raise S3StorageError(f"Failed to upload object: {e}") from e

    def delete(self, key: str) -> bool:
        """
        🧹 Best-effort delete (swallows 'Not Found' as success).
        Returns True when request went through; False only on explicit error.
        """
        k = _normalize_key(key)
        try:
            self.client.delete_object(Bucket=self.bucket, Key=k)
            return True
        except self.client.exceptions.NoSuchKey:
            return True
        except Exception as e:
            logger.warning("delete_object failed (non-fatal): %s", e)
            return False

    # ────────────────────────────────────────────────────────────────────────
    # 🌐  Public/CDN URL helpers
    # ────────────────────────────────────────────────────────────────────────

    def cdn_url(self, key: str) -> Optional[str]:
        """
        🌐 Build a CDN URL for a key if a CDN base is configured.
        Returns None when not configured.
        """
        if not self._cdn_base:
            return None
        return f"{self._cdn_base}/{_normalize_key(key)}"

    def object_url(self, key: str) -> str:
        """
        🌐 Build a direct S3 HTTPS URL (non-signed, private objects still require auth).
        For custom endpoints, uses the configured endpoint host.
        """
        k = _normalize_key(key)
        # Custom endpoint?
        ep = getattr(self.client, "meta", None)
        if ep and getattr(ep, "endpoint_url", None):
            base = str(ep.endpoint_url).rstrip("/")
            return f"{base}/{self.bucket}/{k}"
        # AWS standard form
        region = self.region or "us-east-1"
        return f"https://{self.bucket}.s3.{region}.amazonaws.com/{k}"

    # ────────────────────────────────────────────────────────────────────────
    # 🔎  Metadata helpers
    # ────────────────────────────────────────────────────────────────────────

    def head(self, key: str) -> Optional[Dict[str, Any]]:
        """HEAD the object; returns metadata or None if not found."""
        k = _normalize_key(key)
        try:
            resp = self.client.head_object(Bucket=self.bucket, Key=k)
            return dict(resp or {})
        except self.client.exceptions.NoSuchKey:
            return None
        except Exception as e:
            logger.debug("head_object error: %s", e)
            return None

    def exists(self, key: str) -> bool:
        """Boolean existence check using HEAD."""
        return self.head(key) is not None

    # ────────────────────────────────────────────────────────────────────────
    # 🧪  Internals
    # ────────────────────────────────────────────────────────────────────────

    def _infer_region_safely(self) -> Optional[str]:
        """Try to read the bucket's region without failing the client."""
        try:
            resp = self.client.get_bucket_location(Bucket=self.bucket)
            loc = resp.get("LocationConstraint")
            # us-east-1 returns None in older APIs
            return loc or "us-east-1"
        except Exception as e:
            logger.debug("get_bucket_location failed: %s", e)
            # Fall back to env/defaults; not fatal
            return getattr(settings, "AWS_REGION", None)

    def __repr__(self) -> str:  # pragma: no cover
        return self._repr
