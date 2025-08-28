# app/utils/aws.py
from __future__ import annotations

"""
MoviesNow — S3 + CloudFront Utilities (private-by-default)
=========================================================

Lightweight helpers for uploads/downloads via S3, plus CDN URL builder.

What’s included
---------------
- S3StorageError (safe error wrapper)
- _normalize_key (sanitizes keys)
- S3Client:
  • put_bytes          → upload bytes (private by default)
  • presigned_put      → browser/client uploads
  • presigned_get      → private downloads
  • cloudfront_url     → build public CDN URL
  • head / exists      → object metadata & existence
  • delete / copy      → basic object management
"""

from typing import Final, Optional, Dict, Any
import logging

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import settings

log = logging.getLogger(__name__)

URLStr = str
_DEFAULT_CONTENT_TYPE: Final[str] = "application/octet-stream"
_DEFAULT_PUT_TTL: Final[int] = 3600     # 1h
_DEFAULT_GET_TTL: Final[int] = 3600     # 1h


class S3StorageError(RuntimeError):
    """Raised when S3 or presigning operations fail (never includes secrets)."""


def _normalize_key(key: str) -> str:
    """Normalize S3 object keys (strip leading slash, collapse `//`)."""
    if not key:
        raise S3StorageError("S3 key cannot be empty.")
    k = key.lstrip("/")
    while "//" in k:
        k = k.replace("//", "/")
    return k


class S3Client:
    """Typed, safe wrapper around boto3 S3 for uploads and presigned URLs."""

    def __init__(self, *, endpoint_url: Optional[str] = None, region_name: Optional[str] = None) -> None:
        try:
            self.client = boto3.client(
                "s3",
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY.get_secret_value(),
                region_name=region_name or settings.AWS_REGION,
                endpoint_url=endpoint_url,
            )
        except Exception as e:  # pragma: no cover
            raise S3StorageError(f"S3 client initialization failed: {e}") from e

        self.bucket: str = settings.AWS_BUCKET_NAME
        self._cdn_base: URLStr = settings.cdn_base_url  # normalized like 'https://cdn.example.com'
        log.debug("s3.client.init ok", extra={"bucket": self.bucket, "region": region_name or settings.AWS_REGION})

    # ─────────────────────────────────────────────────────────────

    def put_bytes(
        self,
        key: str,
        data: bytes,
        content_type: str = _DEFAULT_CONTENT_TYPE,
        *,
        cache_control: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
        public: bool = False,
        sse: Optional[str] = None,           # e.g., "AES256" or "aws:kms"
        kms_key_id: Optional[str] = None,    # if using KMS CMK
    ) -> None:
        """Upload bytes to S3 (ACL private by default)."""
        key = _normalize_key(key)
        put_args: Dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": data,
            "ContentType": content_type or _DEFAULT_CONTENT_TYPE,
            "ACL": "public-read" if public else "private",
        }
        if cache_control:
            put_args["CacheControl"] = cache_control
        if metadata:
            put_args["Metadata"] = metadata
        if sse:
            put_args["ServerSideEncryption"] = sse
        if kms_key_id:
            put_args["SSEKMSKeyId"] = kms_key_id

        try:
            self.client.put_object(**put_args)
            log.debug("s3.put_object ok", extra={"key": key, "public": public})
        except (BotoCoreError, ClientError) as e:
            raise S3StorageError(f"Failed to upload s3://{self.bucket}/{key}: {e}") from e

    def presigned_put(
        self,
        key: str,
        *,
        content_type: str = _DEFAULT_CONTENT_TYPE,
        expires_in: int = _DEFAULT_PUT_TTL,
        public: bool = False,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> URLStr:
        """Generate a presigned PUT URL for browser/client uploads."""
        key = _normalize_key(key)
        params: Dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": key,
            "ContentType": content_type or _DEFAULT_CONTENT_TYPE,
        }
        if public:
            params["ACL"] = "public-read"
        if extra_headers:
            params.update({k: v for k, v in extra_headers.items() if k.lower().startswith("x-amz-")})

        try:
            url = self.client.generate_presigned_url(
                ClientMethod="put_object",
                Params=params,
                ExpiresIn=expires_in,
                HttpMethod="PUT",
            )
            log.debug("s3.presigned_put ok", extra={"key": key, "ttl": expires_in, "public": public})
            return url
        except (BotoCoreError, ClientError) as e:
            raise S3StorageError(f"Failed to generate presigned PUT for {key}: {e}") from e

    def presigned_get(
        self,
        key: str,
        *,
        expires_in: int = _DEFAULT_GET_TTL,
        response_content_type: Optional[str] = None,
        response_content_disposition: Optional[str] = None,
    ) -> URLStr:
        """Generate a presigned GET URL for private downloads."""
        key = _normalize_key(key)
        params: Dict[str, Any] = {"Bucket": self.bucket, "Key": key}
        if response_content_type:
            params["ResponseContentType"] = response_content_type
        if response_content_disposition:
            params["ResponseContentDisposition"] = response_content_disposition
        try:
            url = self.client.generate_presigned_url(
                ClientMethod="get_object",
                Params=params,
                ExpiresIn=expires_in,
                HttpMethod="GET",
            )
            log.debug("s3.presigned_get ok", extra={"key": key, "ttl": expires_in})
            return url
        except (BotoCoreError, ClientError) as e:
            raise S3StorageError(f"Failed to generate presigned GET for {key}: {e}") from e

    def cloudfront_url(self, key: str) -> URLStr:
        """Build a public CloudFront URL (unsigned) for safe-to-public assets."""
        key = _normalize_key(key)
        return f"{self._cdn_base}/{key}"

    def head(self, key: str) -> Dict[str, Any]:
        """Return object metadata (raises on error)."""
        key = _normalize_key(key)
        try:
            resp = self.client.head_object(Bucket=self.bucket, Key=key)
            log.debug("s3.head ok", extra={"key": key})
            return resp
        except (BotoCoreError, ClientError) as e:
            raise S3StorageError(f"Failed to head s3://{self.bucket}/{key}: {e}") from e

    def exists(self, key: str) -> bool:
        """Check if an object exists."""
        try:
            self.head(_normalize_key(key))
            return True
        except S3StorageError:
            return False

    def delete(self, key: str) -> None:
        """Delete an object (no error if already absent)."""
        key = _normalize_key(key)
        try:
            self.client.delete_object(Bucket=self.bucket, Key=key)
            log.debug("s3.delete ok", extra={"key": key})
        except (BotoCoreError, ClientError) as e:
            raise S3StorageError(f"Failed to delete s3://{self.bucket}/{key}: {e}") from e

    def copy(self, src_key: str, dst_key: str, *, metadata_directive: str = "COPY") -> None:
        """Server-side copy within the same bucket."""
        src_key = _normalize_key(src_key)
        dst_key = _normalize_key(dst_key)
        try:
            self.client.copy_object(
                Bucket=self.bucket,
                Key=dst_key,
                CopySource={"Bucket": self.bucket, "Key": src_key},
                MetadataDirective=metadata_directive,
            )
            log.debug("s3.copy ok", extra={"src": src_key, "dst": dst_key})
        except (BotoCoreError, ClientError) as e:
            raise S3StorageError(
                f"Failed to copy s3://{self.bucket}/{src_key} → s3://{self.bucket}/{dst_key}: {e}"
            ) from e
