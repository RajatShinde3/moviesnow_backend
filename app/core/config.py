# app/core/config.py
from __future__ import annotations

"""
# MoviesNow — Centralized Configuration (Pydantic v2)

Single `settings` object with strongly-typed, environment-driven config.

## Goals
- Safe defaults for local/dev; explicit where prod needs secrets.
- Robust URL normalization and CSV → list helpers.
- Optional external systems (AWS/CDN/DRM) so imports never crash in dev.
- Security-first defaults (bounded JWT TTLs, CORS allow-lists, HSTS off in dev).

## Usage
    from app.core.config import settings
"""

import os
import logging
from pathlib import Path
from typing import List, Optional, Union, Literal

from dotenv import load_dotenv
from pydantic import Field, SecretStr, AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger(__name__)
load_dotenv()  # harmless in prod; convenient in dev


# ─────────────────────────────────────────────────────────────
# Small helpers
# ─────────────────────────────────────────────────────────────
def _split_csv(v: str | None) -> list[str]:
    """Split a comma-separated string into a trimmed list (empty-safe)."""
    if not v:
        return []
    return [s.strip() for s in str(v).split(",") if s and s.strip()]


def _normalize_url_like(v: str | None, *, require_scheme: bool = True) -> str:
    """Normalize to a string URL without trailing slash."""
    s = (v or "").strip()
    if not s:
        return ""
    if require_scheme and not (s.startswith("http://") or s.startswith("https://")):
        s = "https://" + s
    return s.rstrip("/")


# ─────────────────────────────────────────────────────────────
# Settings
# ─────────────────────────────────────────────────────────────
class Settings(BaseSettings):
    """
    Global application settings sourced from environment.

    Security:
        - Explicit secrets for JWT; TLS and HSTS are configurable.
        - DRM & CDN are optional (safe dev defaults).

    Observability:
        - `SENTRY_DSN` supported (optional).

    Notes:
        - Prefer the string convenience properties when composing URLs.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # don't crash on unknown keys
    )

    # ── App meta ──────────────────────────────────────────────
    PROJECT_NAME: str = "MoviesNow API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    ENV: Literal["development", "staging", "production"] = "development"
    ENABLE_DOCS: bool = True  # you can flip to False in prod if desired

    # ── Security / JWT ────────────────────────────────────────
    JWT_SECRET_KEY: SecretStr = Field(...)
    JWT_ALGORITHM: Literal["HS256", "HS384", "HS512"] = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(60, ge=5, le=24 * 60)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(7, ge=1, le=365)
    
    # Admin auth policies
    ADMIN_REQUIRE_MFA: bool = True
    ADMIN_LOGIN_NEUTRAL_ERRORS: bool = True

    # ── Redis / Rate limiting ─────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_USE_TLS: bool = False
    DEFAULT_RATE_LIMIT: Optional[str] = None  # e.g., "200/minute"
    RATELIMIT_STORAGE_URI: Optional[str] = None  # fallback to REDIS_URL if unset

    # ── Database (PostgreSQL) ─────────────────────────────────
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: SecretStr = Field(...)
    POSTGRES_DB: str = "moviesnow"

    # ── CORS & Hosts ─────────────────────────────────────────
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = Field(
        default_factory=lambda: ["http://localhost:8000", "http://localhost:5173"]
    )
    TRUSTED_HOSTS: List[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    FRONTEND_ORIGINS: Optional[str] = None  # CSV
    ALLOW_ORIGINS_REGEX: Optional[str] = None

    # ── CDN / Storage (optional in dev) ───────────────────────
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[SecretStr] = None
    AWS_REGION: str = "us-east-1"
    AWS_BUCKET_NAME: Optional[str] = None
    CLOUDFRONT_DOMAIN: Optional[str] = None  # e.g., cdn.example.com or https://cdn.example.com
    CDN_SIGN_TTL_SECONDS: int = Field(300, ge=60, le=24 * 60 * 60)  # manifest signed URL TTL

    # ── DRM (optional; enable per environment) ────────────────
    DRM_PROVIDER: Literal["none", "widevine", "multi"] = "none"
    DRM_ISSUER: Optional[str] = None
    DRM_KEY_ID: Optional[str] = None
    DRM_PRIVATE_KEY_PEM: Optional[SecretStr] = None
    DRM_FAIRPLAY_KEY_ID: Optional[str] = None
    DRM_FAIRPLAY_PRIVATE_KEY_PEM: Optional[SecretStr] = None
    DRM_FAIRPLAY_IV_HEX: Optional[str] = None  # if needed by your provider

    # ── Concurrency & Downloads ───────────────────────────────
    CONCURRENCY_MAX_STREAMS: int = Field(2, ge=1, le=10)
    CONCURRENCY_HEARTBEAT_SEC: int = Field(30, ge=10, le=300)
    DOWNLOADS_ENABLED: bool = True
    DOWNLOAD_MAX_DEVICES: int = Field(5, ge=1, le=10)
    DOWNLOAD_MAX_TITLES_PER_DEVICE: int = Field(10, ge=1, le=100)
    DOWNLOAD_LICENSE_TTL_HOURS: int = Field(72, ge=1, le=24 * 30)

    # ── Security headers (mirrors env used by security middleware) ───────────
    ENABLE_HTTPS_REDIRECT: bool = False
    HSTS_MAX_AGE: int = 0
    HSTS_INCLUDE_SUBDOMAINS: bool = False
    HSTS_PRELOAD: bool = False

    CSP_DEFAULT_SRC: Optional[str] = None
    CSP_SCRIPT_SRC: Optional[str] = None
    CSP_STYLE_SRC: Optional[str] = None
    CSP_IMG_SRC: Optional[str] = None
    CSP_FONT_SRC: Optional[str] = None
    CSP_CONNECT_SRC: Optional[str] = None
    CSP_FRAME_ANCESTORS: Optional[str] = None

    REFERRER_POLICY: Optional[str] = "strict-origin-when-cross-origin"
    PERMISSIONS_POLICY: Optional[str] = None
    CROSS_ORIGIN_OPENER_POLICY: Optional[str] = "same-origin"
    CROSS_ORIGIN_RESOURCE_POLICY: Optional[str] = "same-origin"
    CROSS_ORIGIN_EMBEDDER_POLICY: Optional[str] = "unsafe-none"

    SECURITY_SKIP_PATHS: Optional[str] = "/health,/metrics,/docs,/openapi.json,/static/"

    # ── Email (optional; useful for transactional flows) ─────────────────────
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[SecretStr] = None
    EMAIL_FROM: Optional[str] = None
    EMAIL_TEMPLATE_DIR: Path = Path("app/templates/emails")
    FRONTEND_URL: AnyHttpUrl = "http://localhost:8000"
    PUBLIC_BASE_URL: AnyHttpUrl = "http://localhost:8000"
    EMAIL_VERIFY_BASE_URL: Union[AnyHttpUrl, str] = "http://localhost:8000"

    # ── Observability ─────────────────────────────────────────
    SENTRY_DSN: Optional[AnyHttpUrl] = None

    # ── Validators / normalizers ──────────────────────────────
    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def _assemble_cors_origins(cls, v: str | List[str]):
        if isinstance(v, str):
            return _split_csv(v)
        return v

    @field_validator("TRUSTED_HOSTS", mode="before")
    @classmethod
    def _assemble_trusted_hosts(cls, v: str | List[str]):
        if isinstance(v, str):
            return _split_csv(v)
        return v

    @field_validator("FRONTEND_ORIGINS", mode="before")
    @classmethod
    def _normalize_frontend_csv(cls, v):
        return None if v is None else ",".join(_split_csv(str(v)))

    @field_validator("EMAIL_VERIFY_BASE_URL", mode="before")
    @classmethod
    def _normalize_email_base(cls, v) -> str:
        """Normalize to a **string** URL without trailing slash."""
        return _normalize_url_like(str(v or "http://localhost:8000"))

    @field_validator("CLOUDFRONT_DOMAIN", mode="before")
    @classmethod
    def _normalize_cdn_domain(cls, v: str | None) -> str | None:
        """
        Accepts either 'cdn.example.com' or 'https://cdn.example.com' and
        normalizes to 'https://cdn.example.com' (no trailing slash).
        """
        s = (v or "").strip()
        if not s:
            return None
        return _normalize_url_like(s, require_scheme=not (s.startswith("http://") or s.startswith("https://")))

    # ── Derived / convenience properties ─────────────────────
    @property
    def is_production(self) -> bool:
        return self.ENV.lower() == "production"

    @property
    def is_staging(self) -> bool:
        return self.ENV.lower() == "staging"

    @property
    def is_development(self) -> bool:
        return self.ENV.lower() == "development"

    # Database DSNs (stringified for simplicity)
    @property
    def DATABASE_URL(self) -> str:
        """Sync DSN."""
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD.get_secret_value()}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def ASYNC_DATABASE_URL(self) -> str:
        """Async SQLAlchemy DSN."""
        return self.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

    @property
    def TEST_DATABASE_URL(self) -> str:
        """Async test DSN (suffix `_test`)."""
        return (
            self.DATABASE_URL
            .replace(self.POSTGRES_DB, f"{self.POSTGRES_DB}_test")
            .replace("postgresql://", "postgresql+asyncpg://")
        )

    @property
    def frontend_origins_list(self) -> List[str]:
        """
        Preferred CORS allowlist:
        Priority → FRONTEND_ORIGINS (CSV) → BACKEND_CORS_ORIGINS (typed list).
        """
        if self.FRONTEND_ORIGINS:
            return _split_csv(self.FRONTEND_ORIGINS)
        return [str(u) for u in (self.BACKEND_CORS_ORIGINS or [])]

    @property
    def security_skip_paths_list(self) -> List[str]:
        """List form of `SECURITY_SKIP_PATHS` for middleware checks."""
        return _split_csv(self.SECURITY_SKIP_PATHS or "")

    @property
    def ratelimit_storage(self) -> Optional[str]:
        """
        Storage URI for SlowAPI/limits; prefer RATELIMIT_STORAGE_URI,
        otherwise use REDIS_URL when present.
        """
        return self.RATELIMIT_STORAGE_URI or (self.REDIS_URL if self.REDIS_URL else None)

    @property
    def public_base_url_str(self) -> str:
        """`PUBLIC_BASE_URL` as a plain string (normalized by Pydantic)."""
        return str(self.PUBLIC_BASE_URL).rstrip("/")

    @property
    def email_verify_base_url_str(self) -> str:
        """
        Preferred base for verification links.
        Uses normalized `EMAIL_VERIFY_BASE_URL` (string) if set,
        otherwise falls back to `PUBLIC_BASE_URL` (string).
        """
        return (self.EMAIL_VERIFY_BASE_URL or self.PUBLIC_BASE_URL).__str__().rstrip("/")

    @property
    def cdn_base_url(self) -> str:
        """
        CloudFront base URL normalized to a full https URL without trailing slash.
        Examples:
          'cdn.example.com'             -> 'https://cdn.example.com'
          'https://cdn.example.com'     -> 'https://cdn.example.com'
        """
        d = (self.CLOUDFRONT_DOMAIN or "").strip().rstrip("/")
        if not d:
            return ""
        return d if d.startswith(("http://", "https://")) else f"https://{d}"


# Singleton instance
settings = Settings()
