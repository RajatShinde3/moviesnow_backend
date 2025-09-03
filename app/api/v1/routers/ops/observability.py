
# ╔════════════════════════════════════════════════════════════════════════════╗
# ║ MoviesNow · Observability                                                  ║
# ║                                                                            ║
# ║ Endpoints                                                                  ║
# ║  - GET/HEAD /healthz                          → Liveness (fast)            ║
# ║  - GET      /readyz                           → Readiness w/ deps          ║
# ║  - GET      /metrics                          → Prometheus metrics          ║
# ║  - GET      /version                          → Build/version info          ║
# ║  - GET      /debug/audit-logs                 → Admin-only audit viewer     ║
# ║  - POST     /webhooks/*                       → HMAC-verified webhooks      ║
# ╠────────────────────────────────────────────────────────────────────────────╣
# ║ Security & Ops                                                              
# ║  - Rate limiting on all routes (except Prometheus pull cadence is usually   ║
# ║    low anyway).                                                              ║
# ║  - Webhooks: HMAC signature required + Redis-free in-memory TTL dedupe.     ║
# ║  - Secret scrubbing for logged headers (Authorization, signatures, etc.).    ║
# ║  - Cache-Control: no-store for probes/webhooks/version/debug.                ║
# ║  - Optional “deep” checks via HEALTHCHECK_DEEP=1.                            ║
# ╚════════════════════════════════════════════════════════════════════════════╝

import os
import time
from typing import Any, Dict, Mapping, Optional

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
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _no_store_json(payload: Any, status_code: int = 200) -> JSONResponse:
    """Return a JSONResponse with strict no-store caching."""
    resp = JSONResponse(payload, status_code=status_code)
    # Defense-in-depth alongside set_sensitive_cache (used on Response objects).
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


def _scrub_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    """Remove or redact potentially sensitive headers before logging."""
    REDACT = {"authorization", "x-signature", "x-signature-v2", "x-api-key", "cookie"}
    out: Dict[str, str] = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in REDACT:
            out[k] = "[REDACTED]"
        else:
            # Keep short values intact; truncate very long ones to avoid log bloat.
            out[k] = v if len(v) <= 256 else (v[:256] + "…")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Liveness / Readiness
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/healthz")
def healthz(response: Response, _rl=Depends(rate_limit)):
    """
    Liveness probe: returns quickly if process is alive.

    Steps
    -----
    1) Apply `no-store` headers.
    2) Return an epoch timestamp for simple monotonicity checks.
    """
    set_sensitive_cache(response, seconds=0)
    return _no_store_json({"status": "ok", "ts": int(time.time())})


@router.head("/healthz")
def healthz_head(response: Response, _rl=Depends(rate_limit)):
    """HEAD variant of /healthz for super-lightweight probes."""
    set_sensitive_cache(response, seconds=0)
    return Response(status_code=200)


def _check_database() -> Dict[str, Any]:
    url = os.environ.get("DATABASE_URL") or os.environ.get("DB_URL")
    if not url:
        return {"name": "database", "configured": False, "ok": True, "detail": "no-config"}
    try:
        import sqlalchemy  # type: ignore
        from sqlalchemy import create_engine  # type: ignore

        timeout = float(os.environ.get("HEALTHCHECK_DB_TIMEOUT", "1.0"))
        # NOTE: pool_pre_ping helps detect dead connections.
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
            url,
            socket_timeout=float(os.environ.get("HEALTHCHECK_REDIS_TIMEOUT", "0.5")),
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
        get_titles_repository()
        get_user_repository()
        get_player_repository()
        return {"name": "repositories", "ok": True}
    except Exception as e:
        return {"name": "repositories", "ok": False, "error": str(e)}


@router.get("/readyz")
def readyz(response: Response, _rl=Depends(rate_limit)):
    """
    Readiness probe with light dependency checks.

    Behavior
    --------
    - By default performs shallow checks only.
    - Set `HEALTHCHECK_DEEP=1` to enable deeper provider calls (S3 head, KMS describe).

    Steps
    -----
    1) Apply `no-store` headers.
    2) Run DB/Redis/S3/KMS/repository checks.
    3) Return 200 if all OK, else 503 with details for dashboards.
    """
    set_sensitive_cache(response, seconds=0)
    checks = [
        _check_database(),
        _check_redis(),
        _check_s3(),
        _check_kms(),
        _check_repositories(),
    ]
    ok = all(c.get("ok", False) for c in checks)
    status_code = 200 if ok else 503
    return _no_store_json({"ok": ok, "checks": checks, "ts": int(time.time())}, status_code=status_code)


# ─────────────────────────────────────────────────────────────────────────────
# Metrics & Version
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/metrics")
def metrics(_rl=Depends(rate_limit)):
    """
    Prometheus metrics endpoint.

    Notes
    -----
    - If `prometheus_client` is missing, serves a tiny fallback so load balancers
      and uptime checks still have a scrape target.
    - Avoids cache headers: Prometheus expects fresh content each scrape.
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
    if not version:
        for path in ("VERSION", "app/VERSION", "version.txt"):
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        version = f.read().strip()
                        break
                except Exception:
                    pass
    return {"version": version or "0.0.0-dev", "build": build, "commit": commit}


@router.get("/version")
def version(response: Response, _rl=Depends(rate_limit)):
    """
    Return build/version info from env/files.

    Steps
    -----
    1) Apply `no-store` headers to avoid proxy caching stale build info.
    2) Read env or VERSION file(s) and return structured payload.
    """
    set_sensitive_cache(response, seconds=0)
    return _no_store_json(_read_version())


# ─────────────────────────────────────────────────────────────────────────────
# Admin debug: audit log viewer
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/debug/audit-logs")
def debug_audit_logs(
    response: Response,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    source: Optional[str] = Query(None),
    actor: Optional[str] = Query(None),
    _=Depends(require_admin),
):
    """
    Admin-only paginated audit log viewer.

    Steps
    -----
    1) Apply `no-store` headers.
    2) Fetch logs from repository with filters.
    """
    set_sensitive_cache(response, seconds=0)
    repo = get_audit_repository()
    items, total = repo.list(page=page, page_size=page_size, source=source, actor=actor)
    return json_no_store({"items": items, "page": page, "page_size": page_size, "total": total})


# ─────────────────────────────────────────────────────────────────────────────
# Webhooks (HMAC verified + idempotent)
# ─────────────────────────────────────────────────────────────────────────────

_webhook_seen = TTLCache(maxsize=8192)

async def _handle_webhook(request: Request, *, secret_env: str, source: str) -> Response:
    """
    Generic webhook handler.

    Steps
    -----
    1) Verify HMAC signature with shared secret from env (`secret_env`).
    2) Deduplicate by `X-Event-Id`/`x-event-id`/body.id/body.event_id using TTL cache.
    3) Record an audit entry with scrubbed headers and body (size-safe).
    4) Return 202 to indicate asynchronous acceptance.
    """
    # 1) Verify signature (fail closed).
    ok = await verify_webhook_signature(request, secret_env=secret_env)
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse body leniently; providers sometimes send non-JSON for ping events.
    try:
        body = await request.json()
    except Exception:
        body = {}

    # 2) Idempotency / dedupe
    event_id = (
        request.headers.get("x-event-id")
        or request.headers.get("X-Event-Id")
        or body.get("id")
        or body.get("event_id")
    )
    if event_id:
        key = f"wh:{source}:{event_id}"
        if _webhook_seen.seen(key):
            # Already processed—accept again but no-op.
            resp = Response(status_code=202)
            set_sensitive_cache(resp, seconds=0)
            return resp
        _webhook_seen.set(key, ttl_seconds=int(os.environ.get("WEBHOOKS_DEDUP_TTL", "600")))

    # 3) Audit log with scrubbed headers. Avoid logging huge/sensitive payloads.
    repo = get_audit_repository()
    actor = request.headers.get("x-sender") or request.headers.get("X-Sender")
    headers = _scrub_headers(dict(request.headers))
    # Optionally truncate body to a safe size
    if isinstance(body, dict) and int(os.environ.get("WEBHOOK_LOG_BODY_MAX_KEYS", "512")) < len(body):
        body = {k: body[k] for k in list(body)[: int(os.environ.get("WEBHOOK_LOG_BODY_MAX_KEYS", "512"))]}
        body["_truncated"] = True

    repo.add(source=source, action="webhook", actor=actor, meta={"headers": headers, "body": body})

    # 4) Respond
    resp = Response(status_code=202)
    set_sensitive_cache(resp, seconds=0)
    return resp


@router.post("/webhooks/cdn/invalidation-callback")
async def webhooks_cdn_invalidation(request: Request, _rl=Depends(rate_limit)):
    """CDN invalidation callback webhook (HMAC verified; idempotent)."""
    return await _handle_webhook(request, secret_env="WEBHOOKS_CDN_SECRET", source="cdn")


@router.post("/webhooks/email-events")
async def webhooks_email_events(request: Request, _rl=Depends(rate_limit)):
    """Email provider events webhook (HMAC verified; idempotent)."""
    return await _handle_webhook(request, secret_env="WEBHOOKS_EMAIL_SECRET", source="email")


@router.post("/webhooks/encoding-status")
async def webhooks_encoding_status(request: Request, _rl=Depends(rate_limit)):
    """Encoding pipeline status webhook (HMAC verified; idempotent)."""
    return await _handle_webhook(request, secret_env="WEBHOOKS_ENCODING_SECRET", source="encoding")


@router.post("/webhooks/payments")
async def webhooks_payments(request: Request, _rl=Depends(rate_limit)):
    """Payments provider webhook (HMAC verified; idempotent)."""
    return await _handle_webhook(request, secret_env="WEBHOOKS_PAYMENTS_SECRET", source="payments")
