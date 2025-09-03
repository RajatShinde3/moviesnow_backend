# app/api/v1/routers/observability.py
# ╔════════════════════════════════════════════════════════════════════════════╗
# ║ 🧩 MoviesNow · Observability                                               ║
# ║                                                                            ║
# ║ Endpoints                                                                  ║
# ║  - GET/HEAD /healthz                          → Liveness (fast)            ║
# ║  - GET/HEAD /readyz                           → Readiness w/ deps          ║
# ║  - GET      /metrics                          → Prometheus metrics          ║
# ║  - GET      /version                          → Build/version info          ║
# ║  - GET      /debug/audit-logs                 → Admin-only audit viewer     ║
# ║  - POST     /webhooks/*                       → HMAC-verified webhooks      ║
# ╠────────────────────────────────────────────────────────────────────────────╣
# ║ Security & Ops                                                              
# ║  - Per-route rate limiting (Prometheus scrape is lightweight anyway).       ║
# ║  - Webhooks: HMAC signature required + in-memory TTL dedupe.                ║
# ║  - Secret scrubbing for logged headers (Authorization, signatures, etc.).   ║
# ║  - Cache-Control: no-store for probes/webhooks/version/debug.               ║
# ║  - Optional “deep” checks via HEALTHCHECK_DEEP=1.                           ║
# ║  - Correlation headers echoed back when present (X-Request-Id/traceparent). ║
# ╚════════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import os
import time
from typing import Any, Dict, Mapping, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from app.api.http_utils import (
    rate_limit,
    json_no_store,
    require_admin,
    verify_webhook_signature,
)
from app.core.cache import TTLCache
from app.repositories.audit import get_audit_repository
from app.repositories.titles import get_titles_repository
from app.repositories.user import get_user_repository
from app.repositories.player import get_player_repository
from app.security_headers import set_sensitive_cache

router = APIRouter(tags=["Observability"], responses={404: {"description": "Not found"}})


# ─────────────────────────────────────────────────────────────────────────────
# 🧰 Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _echo_correlation_headers(request: Request, response: Response) -> None:
    """Echo common correlation headers back to the caller (best-effort)."""
    for h in ("x-request-id", "traceparent"):
        if h in request.headers:
            response.headers[h] = request.headers[h]


def _no_store_json(payload: Any, status_code: int = 200, request: Optional[Request] = None) -> JSONResponse:
    """Return a JSONResponse with strict no-store caching and correlation headers."""
    resp = JSONResponse(payload, status_code=status_code)
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    if request is not None:
        _echo_correlation_headers(request, resp)
    return resp


def _scrub_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    """Redact sensitive headers before logging; truncate very long values."""
    REDACT = {"authorization", "x-signature", "x-signature-v2", "x-api-key", "cookie", "set-cookie"}
    out: Dict[str, str] = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in REDACT:
            out[k] = "[REDACTED]"
        else:
            out[k] = v if len(v) <= 256 else (v[:256] + "…")
    return out


def _with_timing(fn) -> Tuple[Dict[str, Any], float]:
    """Run a check and return (result, duration_ms)."""
    t0 = time.monotonic()
    res = fn()
    dt = (time.monotonic() - t0) * 1000.0
    return res, dt


# ─────────────────────────────────────────────────────────────────────────────
# 🧪 Liveness / Readiness
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/healthz")
def healthz(request: Request, response: Response, _rl=Depends(rate_limit)):
    """
    🧪 Liveness probe (fast path).

    Steps
    -----
    1) Apply strict `no-store` headers.
    2) Echo correlation headers (X-Request-Id/traceparent) back to the caller.
    3) Return a tiny payload with a UNIX epoch timestamp.

    Returns
    -------
    {"status": "ok", "ts": <int>}
    """
    set_sensitive_cache(response, seconds=0)
    _echo_correlation_headers(request, response)
    return _no_store_json({"status": "ok", "ts": int(time.time())}, request=request)


@router.head("/healthz")
def healthz_head(request: Request, response: Response, _rl=Depends(rate_limit)):
    """HEAD variant of /healthz for super-lightweight probes."""
    set_sensitive_cache(response, seconds=0)
    _echo_correlation_headers(request, response)
    return Response(status_code=200)


def _check_database() -> Dict[str, Any]:
    url = os.environ.get("DATABASE_URL") or os.environ.get("DB_URL")
    if not url:
        return {"name": "database", "configured": False, "ok": True, "detail": "no-config"}
    try:
        import sqlalchemy  # type: ignore
        from sqlalchemy import create_engine  # type: ignore

        timeout = float(os.environ.get("HEALTHCHECK_DB_TIMEOUT", "1.0"))
        engine = create_engine(url, pool_pre_ping=True, connect_args={})
        try:
            with engine.connect() as conn:
                conn.execution_options(timeout=timeout)
                conn.execute(sqlalchemy.text("SELECT 1"))
        finally:
            try:
                engine.dispose()
            except Exception:
                pass
        return {"name": "database", "configured": True, "ok": True}
    except Exception as e:
        return {"name": "database", "configured": True, "ok": False, "error": str(e)}


def _check_redis() -> Dict[str, Any]:
    url = os.environ.get("REDIS_URL") or os.environ.get("CACHE_URL")
    if not url:
        return {"name": "redis", "configured": False, "ok": True, "detail": "no-config"}
    try:
        import redis  # type: ignore

        client = redis.StrictRedis.from_url(
            url, socket_timeout=float(os.environ.get("HEALTHCHECK_REDIS_TIMEOUT", "0.5"))
        )
        client.ping()
        return {"name": "redis", "configured": True, "ok": True}
    except Exception as e:
        return {"name": "redis", "configured": True, "ok": False, "error": str(e)}


def _check_s3() -> Dict[str, Any]:
    bucket = os.environ.get("AWS_S3_BUCKET")
    if not bucket:
        return {"name": "s3", "configured": False, "ok": True, "detail": "no-config"}
    deep = os.environ.get("HEALTHCHECK_DEEP") in {"1", "true", "True"}
    try:
        import boto3  # type: ignore

        if not deep:
            return {"name": "s3", "configured": True, "ok": True}
        s3 = boto3.client("s3")
        s3.head_bucket(Bucket=bucket)
        return {"name": "s3", "configured": True, "ok": True}
    except Exception as e:
        return {"name": "s3", "configured": True, "ok": False, "error": str(e)}


def _check_kms() -> Dict[str, Any]:
    key_id = os.environ.get("AWS_KMS_KEY_ID")
    if not key_id:
        return {"name": "kms", "configured": False, "ok": True, "detail": "no-config"}
    deep = os.environ.get("HEALTHCHECK_DEEP") in {"1", "true", "True"}
    try:
        import boto3  # type: ignore

        if not deep:
            return {"name": "kms", "configured": True, "ok": True}
        kms = boto3.client("kms")
        kms.describe_key(KeyId=key_id)
        return {"name": "kms", "configured": True, "ok": True}
    except Exception as e:
        return {"name": "kms", "configured": True, "ok": False, "error": str(e)}


def _check_repositories() -> Dict[str, Any]:
    try:
        # Validate DI wiring and import-time side effects
        get_titles_repository()
        get_user_repository()
        get_player_repository()
        return {"name": "repositories", "ok": True}
    except Exception as e:
        return {"name": "repositories", "ok": False, "error": str(e)}


@router.get("/readyz")
def readyz(request: Request, response: Response, _rl=Depends(rate_limit)):
    """
    🧪 Readiness probe with light dependency checks (optionally deep).

    Behavior
    --------
    - By default performs shallow checks only.
    - Set `HEALTHCHECK_DEEP=1` to enable deeper provider calls (S3 head, KMS describe).
    - Includes per-check durations to facilitate SLO/SLA dashboards.

    Steps
    -----
    1) Apply `no-store` headers and echo correlation headers.
    2) Run DB/Redis/S3/KMS/repository checks with timing.
    3) Return 200 if all OK, else 503 with structured details.

    Returns
    -------
    {
      "ok": bool,
      "ts": <unix_epoch>,
      "checks": [
        {"name": "...", "ok": true, "configured": true, "duration_ms": 2.1, ...},
        ...
      ]
    }
    """
    set_sensitive_cache(response, seconds=0)
    _echo_correlation_headers(request, response)

    checks_with_fns = [
        ("database", _check_database),
        ("redis", _check_redis),
        ("s3", _check_s3),
        ("kms", _check_kms),
        ("repositories", _check_repositories),
    ]

    checks: list[Dict[str, Any]] = []
    all_ok = True
    for name, fn in checks_with_fns:
        res, ms = _with_timing(fn)
        res["name"] = name  # enforce name presence
        res["duration_ms"] = round(ms, 2)
        checks.append(res)
        all_ok = all_ok and bool(res.get("ok", False))

    status_code = 200 if all_ok else 503
    return _no_store_json({"ok": all_ok, "checks": checks, "ts": int(time.time())}, status_code, request)


@router.head("/readyz")
def readyz_head(request: Request, response: Response, _rl=Depends(rate_limit)):
    """HEAD variant of /readyz (useful for super-lightweight load balancer checks)."""
    set_sensitive_cache(response, seconds=0)
    _echo_correlation_headers(request, response)
    return Response(status_code=200)


# ─────────────────────────────────────────────────────────────────────────────
# 📈 Metrics & 🔢 Version
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/metrics")
def metrics(_rl=Depends(rate_limit)):
    """
    📈 Prometheus metrics endpoint.

    Notes
    -----
    - If `prometheus_client` is unavailable, serves a tiny fallback so scrapes
      still succeed and LB health checks remain green.
    - Avoids explicit cache headers: Prometheus expects fresh content per scrape.
    """
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest  # type: ignore

        data = generate_latest()
        return Response(content=data, media_type=CONTENT_TYPE_LATEST)
    except Exception:
        lines = [
            "# HELP app_heartbeat Always 1 to indicate the app is alive",
            "# TYPE app_heartbeat gauge",
            "app_heartbeat 1",
        ]
        return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


def _read_version() -> Dict[str, Any]:
    version = os.environ.get("APP_VERSION")
    build = os.environ.get("APP_BUILD")
    commit = os.environ.get("GIT_SHA")
    runtime_env = os.environ.get("RUNTIME", "unknown")
    if not version:
        for path in ("VERSION", "app/VERSION", "version.txt"):
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        version = f.read().strip()
                        break
                except Exception:
                    pass
    return {
        "version": version or "0.0.0-dev",
        "build": build,
        "commit": commit,
        "runtime": runtime_env,
    }


@router.get("/version")
def version(request: Request, response: Response, _rl=Depends(rate_limit)):
    """
    🔢 Build/version info.

    Steps
    -----
    1) Apply `no-store` headers (avoid stale versions through proxies).
    2) Read env or VERSION file(s); return a small structured payload.
    3) Echo correlation headers for easier end-to-end tracing.
    """
    set_sensitive_cache(response, seconds=0)
    _echo_correlation_headers(request, response)
    return _no_store_json(_read_version(), request=request)


# ─────────────────────────────────────────────────────────────────────────────
# 🛡️ Admin debug: audit log viewer
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/debug/audit-logs")
def debug_audit_logs(
    request: Request,
    response: Response,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    source: Optional[str] = Query(None),
    actor: Optional[str] = Query(None),
    _=Depends(require_admin),
):
    """
    🛡️ Admin-only paginated audit log viewer.

    Steps
    -----
    1) Apply `no-store` headers and echo correlation headers.
    2) Fetch logs from repository with optional filters (source/actor).
    3) Return items with pagination metadata.

    Security
    --------
    - Requires admin (validated by `require_admin` dependency).
    - Response has sensitive cache-control to avoid leaking PII via caches.
    """
    set_sensitive_cache(response, seconds=0)
    _echo_correlation_headers(request, response)
    repo = get_audit_repository()
    items, total = repo.list(page=page, page_size=page_size, source=source, actor=actor)
    return json_no_store(
        {"items": items, "page": page, "page_size": page_size, "total": total}, response=response
    )


# ─────────────────────────────────────────────────────────────────────────────
# 📬 Webhooks (HMAC verified + idempotent)
# ─────────────────────────────────────────────────────────────────────────────

_webhook_seen = TTLCache(maxsize=8192)

async def _handle_webhook(request: Request, *, secret_env: str, source: str) -> Response:
    """
    📬 Generic webhook handler (HMAC verified + TTL dedupe).

    Steps
    -----
    0) Apply strict `no-store` cache headers and echo correlation headers.
    1) Verify HMAC signature with shared secret from env (`secret_env`).
    2) Deduplicate by `X-Event-Id`/`x-event-id` or JSON `id`/`event_id` using a
       process-local TTL cache (Redis-free for minimal latency/cost).
    3) Record an audit entry with scrubbed headers and size-safe body.
    4) Return 202 to indicate asynchronous acceptance (providers can retry).

    Fail-Closed
    -----------
    - Signature verification failure → 401.
    """
    # Step 0: Prepare response early with cache & correlation headers
    resp = Response(status_code=202)
    set_sensitive_cache(resp, seconds=0)
    _echo_correlation_headers(request, resp)

    # Step 1: Verify signature
    ok = await verify_webhook_signature(request, secret_env=secret_env)
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse body leniently; providers sometimes send non-JSON for ping events.
    try:
        body = await request.json()
    except Exception:
        body = {}

    # Step 2: Idempotency / dedupe
    event_id = (
        request.headers.get("x-event-id")
        or request.headers.get("X-Event-Id")
        or (body.get("id") if isinstance(body, dict) else None)
        or (body.get("event_id") if isinstance(body, dict) else None)
    )
    if event_id:
        key = f"wh:{source}:{event_id}"
        if _webhook_seen.seen(key):
            return resp  # already processed—accept again but no-op
        _webhook_seen.set(key, ttl_seconds=int(os.environ.get("WEBHOOKS_DEDUP_TTL", "600")))

    # Step 3: Audit log (scrub headers; truncate body if huge)
    repo = get_audit_repository()
    actor = request.headers.get("x-sender") or request.headers.get("X-Sender")
    headers = _scrub_headers(dict(request.headers))
    if isinstance(body, dict):
        max_keys = int(os.environ.get("WEBHOOK_LOG_BODY_MAX_KEYS", "512"))
        if len(body) > max_keys:
            keep_keys = list(body)[:max_keys]
            body = {k: body[k] for k in keep_keys}
            body["_truncated"] = True
    repo.add(source=source, action="webhook", actor=actor, meta={"headers": headers, "body": body})

    # Step 4: Respond
    return resp


@router.post("/webhooks/cdn/invalidation-callback")
async def webhooks_cdn_invalidation(request: Request, _rl=Depends(rate_limit)):
    """📦 CDN invalidation callback webhook (HMAC verified; idempotent)."""
    return await _handle_webhook(request, secret_env="WEBHOOKS_CDN_SECRET", source="cdn")


@router.post("/webhooks/email-events")
async def webhooks_email_events(request: Request, _rl=Depends(rate_limit)):
    """📧 Email provider events webhook (HMAC verified; idempotent)."""
    return await _handle_webhook(request, secret_env="WEBHOOKS_EMAIL_SECRET", source="email")


@router.post("/webhooks/encoding-status")
async def webhooks_encoding_status(request: Request, _rl=Depends(rate_limit)):
    """🎞️ Encoding pipeline status webhook (HMAC verified; idempotent)."""
    return await _handle_webhook(request, secret_env="WEBHOOKS_ENCODING_SECRET", source="encoding")


@router.post("/webhooks/payments")
async def webhooks_payments(request: Request, _rl=Depends(rate_limit)):
    """💸 Payments provider webhook (HMAC verified; idempotent)."""
    return await _handle_webhook(request, secret_env="WEBHOOKS_PAYMENTS_SECRET", source="payments")
