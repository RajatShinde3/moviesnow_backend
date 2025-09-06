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
- Safe presigned PUT/GET (SigV4) with optional SSE/KMS
- Explicit timeouts + bounded retries
- Defensive key normalization (no leading slash, no `..`)
- Pluggable creds (env / role / IRSA) with explicit override if provided
- Optional CDN base URL for public asset links
- Zero secret leakage in logs

🔗 Contract (do **not** rename these)
-------------------------------------
- Class: `S3Client`, `S3StorageError`
- Methods: `S3Client.presigned_put(...)`
           `S3Client.presigned_get(...)`
           `S3Client.put_bytes(...)`
           `S3Client.delete(...)`
           `S3Client.client`   # used externally for multipart ops
           (plus helpers: `head`, `exists`, `cdn_url`, `object_url`)

Implementation notes
--------------------
- This module is intentionally **thin** over boto3 to keep failure modes
  familiar and observable. Validation focuses on *inputs we control*
  (keys, headers), while S3-specific errors bubble as S3StorageError.
"""

from typing import Any, Dict, Optional
import logging
import re

try:
    # Optional: only for type hints; code works without pydantic
    from pydantic import SecretStr  # type: ignore
except Exception:  # pragma: no cover
    SecretStr = str  # type: ignore

import boto3
import botocore
from botocore.config import Config as BotoConfig

from app.core.config import settings

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# 🧱 Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class S3StorageError(RuntimeError):
    """Raised when a storage operation fails (network, auth, policy, etc.)."""


# ─────────────────────────────────────────────────────────────────────────────
# 🧰 Key and value validation
# ─────────────────────────────────────────────────────────────────────────────

# Keep keys strict: readable + safe across tools, CDNs, and logs.
_KEY_ALLOWED_RE = re.compile(r"[A-Za-z0-9._\-/+=@() ]+")

def _normalize_key(key: str) -> str:
    """
    Normalize and validate S3 object keys.

    Steps
    -----
    1) Coerce to str, strip whitespace
    2) Remove leading '/'
    3) Collapse '//' runs
    4) Reject path traversal ('..') and disallowed characters

    Raises
    ------
    S3StorageError
        If key is empty or contains unsafe characters.
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
    """Return the underlying secret string without raising if not SecretStr."""
    if v is None:
        return None
    try:
        return v.get_secret_value() if hasattr(v, "get_secret_value") else str(v)  # type: ignore[attr-defined]
    except Exception:
        return str(v)


# ─────────────────────────────────────────────────────────────────────────────
# 📦 S3 Client
# ─────────────────────────────────────────────────────────────────────────────

class S3Client:
    """
    High-level S3 wrapper with safe defaults.

    Parameters
    ----------
    bucket : str | None
        Destination bucket. Defaults to `settings.AWS_BUCKET_NAME`.
    region_name : str | None
        Region to use for the client. Defaults to `settings.AWS_REGION`.
        If not provided anywhere, we attempt to infer from bucket location.
    endpoint_url : str | None
        Custom S3-compatible endpoint (e.g., LocalStack/MinIO). Defaults
        to `settings.AWS_S3_ENDPOINT_URL` if present.
    cdn_base_url : str | None
        If set, `cdn_url()` joins this with normalized keys for public links.
        Defaults to `settings.CDN_BASE_URL` or `settings.cdn_base_url`.
    use_public_acls : bool
        If True and the bucket allows ACLs, `presigned_put`/`put_bytes`
        can request `ACL=public-read`. Defaults False.
    sse_mode : str | None
        "AES256" or "aws:kms". Defaults from `settings.AWS_SSE_MODE`.
    kms_key_id : str | None
        KMS key id/arn when `sse_mode="aws:kms"`. Defaults from settings.

    Notes
    -----
    * Credentials:
        - If `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` are in settings,
          they are used explicitly; otherwise we rely on the standard AWS
          credential chain (env, profile, ECS/EC2 role, IRSA).
    * Retries/Timeouts:
        - Bounded retry policy (5 attempts) and short connect timeout help fail fast.
    """

    # ────────────────────────────────────────────────────────────────────────
    # 🔧 Construction
    # ────────────────────────────────────────────────────────────────────────

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
        # 1) Resolve configuration from explicit args → settings
        self.bucket = bucket or getattr(settings, "AWS_BUCKET_NAME", None)
        if not self.bucket:
            raise S3StorageError("AWS_BUCKET_NAME not configured")

        region_cfg   = region_name  or getattr(settings, "AWS_REGION", None)
        endpoint_cfg = endpoint_url or getattr(settings, "AWS_S3_ENDPOINT_URL", None)

        # Optional CDN base (normalized, no trailing slash)
        cdn_env = cdn_base_url or getattr(settings, "cdn_base_url", None) or getattr(settings, "CDN_BASE_URL", None)
        self._cdn_base = (cdn_env or "").rstrip("/")

        # SSE defaults (never log these)
        self._sse_mode  = sse_mode  or getattr(settings, "AWS_SSE_MODE", None)
        self._kms_key_id = kms_key_id or getattr(settings, "AWS_KMS_KEY_ID", None)

        # 2) Build the boto3 client with safe defaults
        cfg = BotoConfig(
            signature_version="s3v4",
            retries={"max_attempts": 5, "mode": "standard"},
            connect_timeout=3,
            read_timeout=10,
            s3={"addressing_style": "virtual"},
        )

        ak = getattr(settings, "AWS_ACCESS_KEY_ID", None)
        sk = _secret_value(getattr(settings, "AWS_SECRET_ACCESS_KEY", None))
        st = _secret_value(getattr(settings, "AWS_SESSION_TOKEN", None))

        client_kwargs: Dict[str, Any] = {"config": cfg}
        if region_cfg:
            client_kwargs["region_name"] = region_cfg
        if endpoint_cfg:
            client_kwargs["endpoint_url"] = endpoint_cfg
        if ak and sk:
            client_kwargs["aws_access_key_id"] = ak
            client_kwargs["aws_secret_access_key"] = sk
            if st:
                client_kwargs["aws_session_token"] = st

        try:
            self.client = boto3.client("s3", **client_kwargs)
        except Exception as e:  # pragma: no cover
            raise S3StorageError(f"Failed to create S3 client: {e}") from e

        # 3) Region inference (best effort)
        self.region = region_cfg or self._infer_region_safely()

        # 4) ACL flag (most modern buckets have ACLs disabled)
        self._use_public_acls = bool(use_public_acls)

        # 5) Safe, minimal repr (no secrets, no URLs)
        self._repr = f"S3Client(bucket={self.bucket}, region={self.region}, endpoint={'yes' if endpoint_cfg else 'no'})"

    # ────────────────────────────────────────────────────────────────────────
    # 🔐 Signed URL helpers
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
        Generate a **presigned PUT** URL for direct-to-S3 uploads.

        Parameters
        ----------
        key : str
            Object key (will be normalized; no leading `/`, no `..`).
        content_type : str
            MIME type clients **must** include on upload (`Content-Type` header).
        public : bool
            If True and bucket allows ACLs, also requests `ACL=public-read`.
        expires_in : int
            URL TTL in seconds (default 900s = 15m).
        cache_control : str | None
            Value to store as object `Cache-Control` metadata.
        content_disposition : str | None
            Optional `Content-Disposition` metadata.
        extra_headers : dict[str,str] | None
            Extra params merged into the request (e.g., SSE headers).

        Returns
        -------
        str
            Fully signed URL for HTTP PUT.

        Raises
        ------
        S3StorageError
            On signing failure or invalid key.
        """
        k = _normalize_key(key)

        params: Dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": k,
            "ContentType": content_type,
        }

        # Server-side encryption policy
        sse_mode = (extra_headers or {}).get("ServerSideEncryption") or self._sse_mode
        kms_key  = (extra_headers or {}).get("SSEKMSKeyId")          or self._kms_key_id
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

        # Merge extra headers safely (never override core identity fields)
        for hk, hv in (extra_headers or {}).items():
            if hk in {"Bucket", "Key", "Expires"}:
                continue
            params[hk] = hv

        try:
            return self.client.generate_presigned_url(
                ClientMethod="put_object",
                Params=params,
                ExpiresIn=int(expires_in),
                HttpMethod="PUT",
            )
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
        Generate a short-lived **presigned GET** URL.

        Parameters
        ----------
        key : str
            Object key (normalized).
        expires_in : int
            TTL seconds (default 300s = 5m).
        response_content_type : str | None
            Optional override for the `Content-Type` returned to the client.
        response_content_disposition : str | None
            e.g., `attachment; filename="..."` to force downloads.

        Returns
        -------
        str
            Fully signed URL for HTTP GET.
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
    # 🚀 Direct server-side ops (small files, best-effort delete)
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
        Upload a small payload from the server (≤ ~10MB ideal).

        Notes
        -----
        Prefer presigned PUT from clients to reduce server egress and
        improve parallelism. This exists for tiny writes or service-side
        generated content.

        Raises
        ------
        S3StorageError
            On upload failure or invalid key.
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
        kms_key  = (extra_args or {}).get("SSEKMSKeyId")          or self._kms_key_id
        if sse_mode:
            args["ServerSideEncryption"] = sse_mode
            if sse_mode == "aws:kms" and kms_key:
                args["SSEKMSKeyId"] = kms_key

        if public and self._use_public_acls:
            args["ACL"] = "public-read"

        # Merge extra args (keep core fields protected)
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
        Best-effort delete.

        Behavior
        --------
        - Returns True on successful request submission.
        - Returns True for "NoSuchKey" (idempotent delete).
        - Returns False only on non-ignorable errors (logged at WARNING).
        """
        k = _normalize_key(key)
        try:
            self.client.delete_object(Bucket=self.bucket, Key=k)
            return True
        except getattr(self.client, "exceptions", object()).NoSuchKey:  # type: ignore[attr-defined]
            return True
        except Exception as e:
            logger.warning("delete_object failed (non-fatal): %s", e)
            return False

    # ────────────────────────────────────────────────────────────────────────
    # 🌐 Public URL helpers
    # ────────────────────────────────────────────────────────────────────────

    def cdn_url(self, key: str) -> Optional[str]:
        """
        Build a CDN URL for a normalized key if a CDN base is configured.

        Returns
        -------
        str | None
            The CDN URL (e.g., https://dxxx.cloudfront.net/path) or None.
        """
        if not self._cdn_base:
            return None
        return f"{self._cdn_base}/{_normalize_key(key)}"

    def object_url(self, key: str) -> str:
        """
        Build a direct S3 HTTPS URL (non-signed). Private objects will still
        require auth at fetch time.

        For custom endpoints, uses the configured endpoint host.
        """
        k = _normalize_key(key)
        ep = getattr(self.client, "meta", None)
        if ep and getattr(ep, "endpoint_url", None):
            base = str(ep.endpoint_url).rstrip("/")
            return f"{base}/{self.bucket}/{k}"
        region = self.region or "us-east-1"
        return f"https://{self.bucket}.s3.{region}.amazonaws.com/{k}"

    # ────────────────────────────────────────────────────────────────────────
    # 🔎 Metadata helpers
    # ────────────────────────────────────────────────────────────────────────

    def head(self, key: str) -> Optional[Dict[str, Any]]:
        """
        HEAD the object and return metadata dictionary or None if not found.

        Safe failure: returns None for common "not found" cases.
        """
        k = _normalize_key(key)
        try:
            resp = self.client.head_object(Bucket=self.bucket, Key=k)
            # boto3 returns a dict-like; cast to plain dict to detach from botocore model
            return dict(resp or {})
        except getattr(self.client, "exceptions", object()).NoSuchKey:  # type: ignore[attr-defined]
            return None
        except botocore.exceptions.ClientError as e:
            # Normalize 404/403-without-object into None; others bubble via debug
            code = e.response.get("Error", {}).get("Code")
            if code in {"404", "NoSuchKey", "NotFound"}:
                return None
            logger.debug("head_object client error: %s", e)
            return None
        except Exception as e:
            logger.debug("head_object unexpected error: %s", e)
            return None

    def exists(self, key: str) -> bool:
        """Boolean existence check using `HEAD`."""
        return self.head(key) is not None

    # ────────────────────────────────────────────────────────────────────────
    # 🧪 Internals
    # ────────────────────────────────────────────────────────────────────────

    def _infer_region_safely(self) -> Optional[str]:
        """
        Try to read the bucket's region without failing the client.

        Returns
        -------
        str | None
            Region or None if not discoverable (we tolerate failure here).
        """
        try:
            resp = self.client.get_bucket_location(Bucket=self.bucket)
            loc = resp.get("LocationConstraint")
            # Old APIs return None for us-east-1
            return loc or "us-east-1"
        except Exception as e:
            logger.debug("get_bucket_location failed: %s", e)
            return getattr(settings, "AWS_REGION", None)

    def __repr__(self) -> str:  # pragma: no cover
        return self._repr
