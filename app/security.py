# app/security.py
from __future__ import annotations
"""
MoviesNow — security utils (production-grade)
=============================================
Thin, well-typed helpers you can reuse across routers/services.

Design
------
- Delegate CSP/HSTS/CORS to `app.security_headers` (nonce-aware).
- HTML sanitization (bleach if available; strict fallback otherwise).
- Idempotency-Key validator.
- ETag helpers (If-Match / If-None-Match).
- UUID parsing w/ friendly HTTP 400s.
- Timing-safe comparisons & modern digests.
- Secret/PII redaction for safe logs.
- Small extras: safe b64url, JSON dumps, HTTPS guard.

Notes
-----
- JWT verification lives in your auth modules.
- `set_security_headers`, `set_sensitive_cache`, `set_static_cache`,
  `install_security`, and `configure_cors` are re-exported when available.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple, Union
from uuid import UUID

from fastapi import HTTPException, Request, Response, status

logger = logging.getLogger("moviesnow.security")

# ─────────────────────────────────────────────────────────────
# 🔌 Prefer your project header/CORS helpers (nonce-aware)
# ─────────────────────────────────────────────────────────────
# These symbols are optional re-exports. If your app.security_headers exists,
# we surface them; otherwise the module keeps working without them.
try:  # pragma: no cover
    from app.security_headers import (  # type: ignore
        set_security_headers as _project_set_headers,
        set_sensitive_cache as set_sensitive_cache,
        set_static_cache as set_static_cache,
        install_security as install_security,
        configure_cors as configure_cors,
    )

    def set_security_headers(response: Response, request: Optional[Request] = None) -> None:
        """Idempotent. Uses MoviesNow CSP nonce from request.state.csp_nonce."""
        _project_set_headers(response, request)  # type: ignore[misc]

except Exception:  # pragma: no cover
    # Fallback: minimal header setter (nonce-agnostic). You rarely hit this path.
    def set_security_headers(response: Response, request: Optional[Request] = None) -> None:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")


# ─────────────────────────────────────────────────────────────
# 🧼 HTML sanitization (tight defaults)
# ─────────────────────────────────────────────────────────────
ALLOWED_TAGS: Tuple[str, ...] = (
    "b", "i", "strong", "em", "code", "pre", "kbd", "samp",
    "ul", "ol", "li", "p", "br", "blockquote", "hr",
    "a", "span",
)
ALLOWED_ATTRS: Mapping[str, Sequence[str]] = {
    "a": ("href", "title", "rel"),
    "span": ("title",),
}
ALLOWED_PROTOCOLS: Tuple[str, ...] = ("http", "https", "mailto")

def sanitize_html(
    html: Optional[str],
    *,
    tags: Sequence[str] = ALLOWED_TAGS,
    attrs: Mapping[str, Sequence[str]] = ALLOWED_ATTRS,
    protocols: Sequence[str] = ALLOWED_PROTOCOLS,
) -> str:
    """Sanitize potentially unsafe HTML (bleach preferred; strict fallback)."""
    if not html:
        return ""
    try:
        import bleach  # type: ignore
        cleaned = bleach.clean(html, tags=list(tags), attributes=dict(attrs), protocols=list(protocols), strip=True)
        cleaned = cleaned.replace('target="_blank"', "")  # avoid reverse tabnabbing unless rel is set
        cleaned = re.sub(r"<a ", '<a rel="nofollow noopener noreferrer" ', cleaned)
        return cleaned
    except Exception:
        s = re.sub(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", "", html, flags=re.I | re.S)
        s = re.sub(r"<\s*style[^>]*>.*?<\s*/\s*style\s*>", "", s, flags=re.I | re.S)
        s = re.sub(r"on[a-z]+\s*=\s*\"[^\"]*\"", "", s, flags=re.I)
        s = re.sub(r"on[a-z]+\s*=\s*'[^']*'", "", s, flags=re.I)
        s = re.sub(r"javascript:\s*", "", s, flags=re.I)
        s = re.sub(r"<[^>]+>", "", s)
        s = re.sub(r"\s+", " ", s).strip()
        return s


# ─────────────────────────────────────────────────────────────
# 🧾 Idempotency & ETag helpers
# ─────────────────────────────────────────────────────────────
_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")

def validate_idempotency_key(key: Optional[str]) -> str:
    """Validate/normalize an Idempotency-Key header value (HTTP 400 on error)."""
    if key is None:
        raise HTTPException(status_code=400, detail="Missing Idempotency-Key header")
    k = key.strip()
    if not k or not _IDEMPOTENCY_KEY_RE.fullmatch(k):
        raise HTTPException(status_code=400, detail="Invalid Idempotency-Key format")
    return k

def make_etag(resource_id: Union[str, UUID], *, version: Optional[Union[int, str]] = None,
              timestamp: Optional[datetime] = None) -> str:
    """Create a weak ETag W/"{id}:{version|timestamp}"."""
    rid = str(resource_id)
    token = str(version) if version is not None else (timestamp or datetime.now(timezone.utc)).isoformat()
    return f'W/"{rid}:{token}"'

def assert_if_match(expected_etag: str, provided_if_match: Optional[str]) -> None:
    """Raise HTTP 412 if `If-Match` missing or mismatched."""
    if not provided_if_match:
        raise HTTPException(status_code=status.HTTP_412_PRECONDITION_FAILED, detail="Missing If-Match header")
    if provided_if_match != expected_etag:
        raise HTTPException(status_code=status.HTTP_412_PRECONDITION_FAILED, detail="Stale version. Re-fetch and retry.")

def is_fresh_if_none_match(current_etag: str, provided: Optional[str]) -> bool:
    """Return True if a client’s `If-None-Match` matches the current ETag."""
    return bool(provided) and provided.strip() == current_etag


# ─────────────────────────────────────────────────────────────
# 🆔 UUID / input validation
# ─────────────────────────────────────────────────────────────
def parse_uuid(value: Union[str, UUID], *, field: str = "id") -> UUID:
    """Parse a UUID or raise 400 (friendly error for clients)."""
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid {field} format")


# ─────────────────────────────────────────────────────────────
# 🔐 Cryptographic helpers
# ─────────────────────────────────────────────────────────────
_DEF_HASH_ALGO = os.getenv("APP_HASH_ALGO", "sha256")

def secure_digest(data: Union[str, bytes], *, algo: str = _DEF_HASH_ALGO) -> str:
    """Modern hex digest (default sha256)."""
    b = data.encode("utf-8") if isinstance(data, str) else data
    h = hashlib.new(algo)
    h.update(b)
    return h.hexdigest()

def compare_signatures(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """Timing-safe constant-time comparison (e.g., webhook signatures)."""
    ba = a.encode("utf-8") if isinstance(a, str) else a
    bb = b.encode("utf-8") if isinstance(b, str) else b
    return hmac.compare_digest(ba, bb)


# ─────────────────────────────────────────────────────────────
# 🙈 Redaction / logging hygiene
# ─────────────────────────────────────────────────────────────
_SECRET_SNIPPETS = ("api_key", "apikey", "password", "secret", "authorization", "bearer ", "token")

def redact_secrets(text: Optional[str]) -> str:
    """Redact obvious secret substrings & JWT-ish blobs for safe logs."""
    if not text:
        return ""
    s = text
    for needle in _SECRET_SNIPPETS:
        s = re.sub(re.escape(needle), "[REDACTED]", s, flags=re.I)
    s = re.sub(r"[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "[REDACTED_JWT]", s)
    s = re.sub(r"[A-Fa-f0-9]{24,}", "[REDACTED_HEX]", s)
    return s

def mask_email(email: Optional[str]) -> str:
    """john.doe@example.com → j***@example.com"""
    if not email or "@" not in email:
        return ""
    name, domain = email.split("@", 1)
    return (name[0] + "***@" + domain) if name else ("***@" + domain)


# ─────────────────────────────────────────────────────────────
# 🔗 Misc helpers
# ─────────────────────────────────────────────────────────────
def safe_b64url(data: Union[str, bytes]) -> str:
    """Base64-url encode without padding (opaque cursors etc.)."""
    b = data.encode("utf-8") if isinstance(data, str) else data
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def safe_json(obj: Any) -> str:
    """Compact JSON dumps safe for logs (never raises)."""
    try:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    except Exception:
        return "{}"

def is_secure_request(request: Request) -> bool:
    """
    Heuristic: request considered secure if:
    - URL scheme is https, or
    - behind a proxy setting X-Forwarded-Proto=https.
    """
    try:
        if request.url.scheme == "https":
            return True
        xfp = request.headers.get("x-forwarded-proto", "")
        return "https" in {p.strip().lower() for p in xfp.split(",")}
    except Exception:
        return False

def require_https(request: Request) -> None:
    """Fail closed on insecure transport in production."""
    if os.getenv("ENVIRONMENT", "development") != "development" and not is_secure_request(request):
        raise HTTPException(status_code=400, detail="HTTPS required")
