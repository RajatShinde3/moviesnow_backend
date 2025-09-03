# app/security_headers.py
from __future__ import annotations

"""
# MoviesNow — Security Headers & CORS

Production-grade security headers and CORS utilities for FastAPI/Starlette.

## What you get
- **Headers**: CSP, HSTS, CORP/COOP/COEP, Referrer-Policy, X-Content-Type-Options,
  X-Frame-Options, X-Permitted-Cross-Domain-Policies.
- **Per-request CSP nonce**: available as `request.state.csp_nonce`.
- **CORS installer**: strict allow-list via env (safe localhost defaults in dev).
- **Skip list**: configurable path prefixes (e.g., static/docs/health) to avoid CSP noise.
- **Cache helpers**: `set_sensitive_cache()` for correct HTTP caching.
- **Report-only CSP (optional)**: trial CSP without breaking traffic.

## Quick start
    from app.security_headers import install_security, configure_cors

    app = FastAPI()
    install_security(app)   # HTTPS redirect (optional) + headers middleware
    configure_cors(app)     # CORS allow-list from env

Inside a route (optional):
    from app.security_headers import set_sensitive_cache

    @router.post("/auth/login")
    async def login(request: Request, response: Response):
        # Mark as sensitive; middleware applies headers automatically
        set_sensitive_cache(request)

## Env knobs
- ENABLE_HTTPS_REDIRECT (default "true")
- SECURITY_SKIP_PATHS (CSV; default "/health,/metrics,/docs,/openapi.json,/static/")
- FRONTEND_ORIGINS (CSV; exact origins), ALLOW_ORIGINS_REGEX (single regex)
- HSTS_MAX_AGE (31536000), HSTS_INCLUDE_SUBDOMAINS ("true"), HSTS_PRELOAD ("true")
- CSP_DEFAULT_SRC, CSP_SCRIPT_SRC, CSP_STYLE_SRC, CSP_IMG_SRC, CSP_FONT_SRC, CSP_CONNECT_SRC, CSP_FRAME_ANCESTORS
- CSP_REPORT_ONLY ("false"), CSP_REPORT_URI (URL)
- REFERRER_POLICY (default "strict-origin-when-cross-origin")
- PERMISSIONS_POLICY (sane locked-down default)
- CROSS_ORIGIN_OPENER_POLICY / RESOURCE_POLICY / EMBEDDER_POLICY
"""

import base64
import os
import secrets
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple, List, Union

from fastapi import Request, Response
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send


# ─────────────────────────────────────────────────────────────
# ⚙️ Configuration
# ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SecurityHeadersConfig:
    """Runtime configuration for security headers and CSP (env-driven)."""

    # HSTS
    hsts_max_age: int = int(os.getenv("HSTS_MAX_AGE", "31536000"))
    hsts_include_subdomains: bool = os.getenv("HSTS_INCLUDE_SUBDOMAINS", "true").lower() == "true"
    hsts_preload: bool = os.getenv("HSTS_PRELOAD", "true").lower() == "true"

    # CSP directives
    csp_default_src: str = os.getenv("CSP_DEFAULT_SRC", "'self'")
    csp_script_src: str = os.getenv("CSP_SCRIPT_SRC", "'self' 'strict-dynamic'")
    csp_style_src: str = os.getenv("CSP_STYLE_SRC", "'self' 'unsafe-inline'")  # tighten via hashes in prod
    csp_img_src: str = os.getenv("CSP_IMG_SRC", "'self' data:")
    csp_font_src: str = os.getenv("CSP_FONT_SRC", "'self' data:")
    csp_connect_src: str = os.getenv("CSP_CONNECT_SRC", "'self'")
    csp_frame_ancestors: str = os.getenv("CSP_FRAME_ANCESTORS", "'none'")

    # CSP report-only mode (optional)
    csp_report_only: bool = os.getenv("CSP_REPORT_ONLY", "false").lower() == "true"
    csp_report_uri: Optional[str] = os.getenv("CSP_REPORT_URI") or None

    # Other security headers
    referrer_policy: str = os.getenv("REFERRER_POLICY", "strict-origin-when-cross-origin")
    permissions_policy: str = os.getenv(
        "PERMISSIONS_POLICY",
        "accelerometer=(), autoplay=(), camera=(), display-capture=(), geolocation=(), "
        "gyroscope=(), microphone=(), payment=(), usb=()",
    )
    coop: str = os.getenv("CROSS_ORIGIN_OPENER_POLICY", "same-origin")
    corp: str = os.getenv("CROSS_ORIGIN_RESOURCE_POLICY", "same-origin")
    coep: str = os.getenv("CROSS_ORIGIN_EMBEDDER_POLICY", "require-corp")

    # Skipped paths (prefix match)
    skip_paths_csv: str = os.getenv("SECURITY_SKIP_PATHS", "/health,/metrics,/docs,/openapi.json,/static/")


_CFG = SecurityHeadersConfig()


def _build_csp(*, nonce: Optional[str] = None, cfg: SecurityHeadersConfig = _CFG) -> str:
    """Build the Content Security Policy string (includes nonce if provided)."""
    script_src = cfg.csp_script_src
    style_src = cfg.csp_style_src
    if nonce:
        script_src = f"{script_src} 'nonce-{nonce}'"
        style_src = f"{style_src} 'nonce-{nonce}'"

    parts = [
        f"default-src {cfg.csp_default_src}",
        f"script-src {script_src}",
        f"style-src {style_src}",
        f"img-src {cfg.csp_img_src}",
        f"font-src {cfg.csp_font_src}",
        f"connect-src {cfg.csp_connect_src}",
        f"frame-ancestors {cfg.csp_frame_ancestors}",
        # Optional hardening (enable when HTTPS is end-to-end):
        # "upgrade-insecure-requests",
        # "block-all-mixed-content",
    ]
    if cfg.csp_report_uri:
        parts.append(f"report-uri {cfg.csp_report_uri}")
    return "; ".join(parts)


# ─────────────────────────────────────────────────────────────
# 🧩 Middleware (headers + CSP nonce + optional cache flags)
# ─────────────────────────────────────────────────────────────

class SecurityHeadersMiddleware:
    """
    ASGI middleware that:
    - Generates a per-request CSP nonce (exposed as `request.state.csp_nonce`).
    - Applies security headers idempotently on every response.
    - Optionally applies **sensitive cache** headers if marked on the `Request`.
    - Skips configured path prefixes (docs/static/health, etc.).
    """

    def __init__(self, app: ASGIApp, cfg: SecurityHeadersConfig = _CFG) -> None:
        self.app = app
        self.cfg = cfg
        self._skip_prefixes: Tuple[str, ...] = tuple(
            p.strip() for p in (cfg.skip_paths_csv or "").split(",") if p.strip()
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        is_skipped = any(path.startswith(prefix) for prefix in self._skip_prefixes)
        nonce = base64.b64encode(secrets.token_bytes(16)).decode().rstrip("=")

        # Expose per-request state (nonce + cache flags)
        state = scope.setdefault("state", {})
        state["csp_nonce"] = nonce

        async def send_wrapper(message):
            if message.get("type") == "http.response.start":
                raw_headers: List[Tuple[bytes, bytes]] = message.setdefault("headers", [])  # type: ignore[assignment]
                if not is_skipped:
                    _apply_headers_to_raw(raw_headers, nonce, self.cfg)

                # Apply sensitive cache headers if requested via Request flag
                sc_flag = bool(state.get("_sensitive_cache"))
                sc_seconds = int(state.get("_sensitive_cache_seconds") or 0)
                if sc_flag or sc_seconds > 0:
                    _apply_sensitive_cache_to_raw(raw_headers, seconds=max(0, sc_seconds))

            await send(message)

        await self.app(scope, receive, send_wrapper)


def _has_header(raw_headers: List[Tuple[bytes, bytes]], name: str) -> bool:
    lname = name.lower().encode("latin-1")
    return any(h[0].lower() == lname for h in raw_headers)


def _append_header(raw_headers: List[Tuple[bytes, bytes]], name: str, value: str) -> None:
    raw_headers.append((name.encode("latin-1"), value.encode("latin-1")))


def _apply_headers_to_raw(
    raw_headers: List[Tuple[bytes, bytes]],
    nonce: Optional[str],
    cfg: SecurityHeadersConfig,
) -> None:
    """Append security headers idempotently to the ASGI raw header list."""
    # HSTS
    hsts = f"max-age={cfg.hsts_max_age}"
    if cfg.hsts_include_subdomains:
        hsts += "; includeSubDomains"
    if cfg.hsts_preload:
        hsts += "; preload"

    if not _has_header(raw_headers, "Strict-Transport-Security"):
        _append_header(raw_headers, "Strict-Transport-Security", hsts)
    if not _has_header(raw_headers, "X-Content-Type-Options"):
        _append_header(raw_headers, "X-Content-Type-Options", "nosniff")
    if not _has_header(raw_headers, "X-Frame-Options"):
        _append_header(raw_headers, "X-Frame-Options", "DENY")
    if not _has_header(raw_headers, "Referrer-Policy"):
        _append_header(raw_headers, "Referrer-Policy", cfg.referrer_policy)
    if not _has_header(raw_headers, "Permissions-Policy"):
        _append_header(raw_headers, "Permissions-Policy", cfg.permissions_policy)
    if not _has_header(raw_headers, "Cross-Origin-Opener-Policy"):
        _append_header(raw_headers, "Cross-Origin-Opener-Policy", cfg.coop)
    if not _has_header(raw_headers, "Cross-Origin-Resource-Policy"):
        _append_header(raw_headers, "Cross-Origin-Resource-Policy", cfg.corp)
    if not _has_header(raw_headers, "Cross-Origin-Embedder-Policy"):
        _append_header(raw_headers, "Cross-Origin-Embedder-Policy", cfg.coep)
    if not _has_header(raw_headers, "X-Permitted-Cross-Domain-Policies"):
        _append_header(raw_headers, "X-Permitted-Cross-Domain-Policies", "none")

    csp = _build_csp(nonce=nonce, cfg=cfg)
    header_name = "Content-Security-Policy-Report-Only" if cfg.csp_report_only else "Content-Security-Policy"
    if not _has_header(raw_headers, header_name):
        _append_header(raw_headers, header_name, csp)


def _apply_sensitive_cache_to_raw(raw_headers: List[Tuple[bytes, bytes]], *, seconds: int = 0) -> None:
    """Inject Cache-Control/Pragma/Expires/Vary directly to ASGI raw headers."""
    def _ensure(name: str, value: str) -> None:
        if not _has_header(raw_headers, name):
            _append_header(raw_headers, name, value)

    if seconds <= 0:
        _ensure("Cache-Control", "no-store")
        _ensure("Pragma", "no-cache")
        _ensure("Expires", "0")
    else:
        _ensure("Cache-Control", f"private, max-age={seconds}")
        # Protect shared caches from cross-user leakage
        if not _has_header(raw_headers, "Vary"):
            _append_header(raw_headers, "Vary", "Authorization, Cookie")


# ─────────────────────────────────────────────────────────────
# 🔓 Public helpers (idempotent; safe to call in routes)
# ─────────────────────────────────────────────────────────────

# Note: per-route `set_security_headers` helper removed (unused).


def set_sensitive_cache(target: Union[Response, Request], *, seconds: int = 0) -> None:
    """
    Mark a **Response** or **Request** as sensitive for caching.

    - If `Response`: headers are set immediately (idempotent).
    - If `Request`: sets flags read by the middleware at response start.

    `seconds > 0` enables a short **private** cache and adds a conservative
    `Vary: Authorization, Cookie` to prevent proxy leakage.
    """
    if isinstance(target, Response):
        if seconds <= 0:
            target.headers.setdefault("Cache-Control", "no-store")
            target.headers.setdefault("Pragma", "no-cache")
            target.headers.setdefault("Expires", "0")
        else:
            target.headers.setdefault("Cache-Control", f"private, max-age={seconds}")
            vary = target.headers.get("Vary")
            needed = {"Authorization", "Cookie"}
            if vary:
                existing = {v.strip() for v in vary.split(",") if v.strip()}
                target.headers["Vary"] = ", ".join(sorted(existing | needed))
            else:
                target.headers["Vary"] = ", ".join(sorted(needed))
        return

    if isinstance(target, Request):
        state = getattr(target, "state", None)
        if state is not None:
            setattr(state, "_sensitive_cache", True)
            setattr(state, "_sensitive_cache_seconds", int(seconds))
        return

    raise TypeError("set_sensitive_cache expects a Response or Request")


# Note: `set_static_cache` removed (unused); rely on CDN/static server for caching.


# ─────────────────────────────────────────────────────────────
# 🌐 CORS installer (allow-list, not '*')
# ─────────────────────────────────────────────────────────────

def configure_cors(
    app,
    *,
    allow_credentials: bool = True,
    allow_methods: Optional[Iterable[str]] = None,
    allow_headers: Optional[Iterable[str]] = None,
) -> None:
    """Install strict CORS based on env configuration."""
    allow_methods = allow_methods or ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
    allow_headers = allow_headers or [
        "Authorization",
        "Content-Type",
        "X-Request-ID",
        "X-CSRF-Token",
        "If-None-Match",
        "If-Match",
        "Idempotency-Key",
    ]

    origins_csv = os.getenv("FRONTEND_ORIGINS", "").strip()
    origins = [o.strip() for o in origins_csv.split(",") if o.strip()]
    origins_regex = os.getenv("ALLOW_ORIGINS_REGEX", "").strip() or None

    if not origins and not origins_regex:
        # localhost-friendly defaults in dev
        origins = [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_origin_regex=origins_regex,
        allow_credentials=allow_credentials,
        allow_methods=list(allow_methods),
        allow_headers=list(allow_headers),
        expose_headers=["ETag", "Location", "Retry-After", "X-Request-ID"],
        max_age=3600,
    )


# ─────────────────────────────────────────────────────────────
# 🔐 HTTPS redirect + headers middleware
# ─────────────────────────────────────────────────────────────

def install_security(app) -> None:
    """Add HTTPS redirect (optional) and the security headers middleware."""
    if os.getenv("ENABLE_HTTPS_REDIRECT", "true").lower() == "true":
        app.add_middleware(HTTPSRedirectMiddleware)

    app.add_middleware(SecurityHeadersMiddleware, cfg=_CFG)


__all__ = [
    "SecurityHeadersConfig",
    "SecurityHeadersMiddleware",
    "install_security",
    "configure_cors",
    "set_sensitive_cache",
]
