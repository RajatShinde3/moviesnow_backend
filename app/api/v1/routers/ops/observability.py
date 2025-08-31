from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from app.api.http_utils import rate_limit, json_no_store, require_admin, verify_webhook_signature
from app.core.cache import TTLCache
from app.repositories.audit import get_audit_repository
from app.repositories.titles import get_titles_repository
from app.repositories.user import get_user_repository
from app.repositories.player import get_player_repository


router = APIRouter(tags=["Observability"], responses={404: {"description": "Not found"}})


@router.get("/healthz")
def healthz(_rl=Depends(rate_limit)):
    """Liveness probe: returns quickly if process is alive."""
    return JSONResponse({"status": "ok", "ts": int(time.time())})


def _check_database() -> Dict[str, Any]:
    url = os.environ.get("DATABASE_URL") or os.environ.get("DB_URL")
    if not url:
        return {"name": "database", "configured": False, "ok": True, "detail": "no-config"}
    try:
        import sqlalchemy  # type: ignore
        from sqlalchemy import create_engine  # type: ignore

        timeout = float(os.environ.get("HEALTHCHECK_DB_TIMEOUT", "1.0"))
        engine = create_engine(url, pool_pre_ping=True, connect_args={})
        with engine.connect() as conn:
            conn.execution_options(timeout=timeout)
            conn.execute(sqlalchemy.text("SELECT 1"))
        return {"name": "database", "configured": True, "ok": True}
    except Exception as e:
        return {"name": "database", "configured": True, "ok": False, "error": str(e)}


def _check_redis() -> Dict[str, Any]:
    url = os.environ.get("REDIS_URL") or os.environ.get("CACHE_URL")
    if not url:
        return {"name": "redis", "configured": False, "ok": True, "detail": "no-config"}
    try:
        import redis  # type: ignore

        client = redis.StrictRedis.from_url(url, socket_timeout=float(os.environ.get("HEALTHCHECK_REDIS_TIMEOUT", "0.5")))
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
def readyz(_rl=Depends(rate_limit)):
    """Readiness probe with light dependency checks (deep checks via HEALTHCHECK_DEEP=1)."""
    checks = [_check_database(), _check_redis(), _check_s3(), _check_kms(), _check_repositories()]
    ok = all(c.get("ok", False) for c in checks)
    status_code = 200 if ok else 503
    return JSONResponse({"ok": ok, "checks": checks, "ts": int(time.time())}, status_code=status_code)


@router.get("/metrics")
def metrics(_rl=Depends(rate_limit)):
    """Prometheus metrics endpoint (uses prometheus_client when available)."""
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
def version(_rl=Depends(rate_limit)):
    """Return build version information from env/FILES."""
    return JSONResponse(_read_version())


@router.get("/debug/audit-logs")
def debug_audit_logs(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500), source: Optional[str] = Query(None), actor: Optional[str] = Query(None), _=Depends(require_admin)):
    """Admin-only paginated audit log viewer."""
    repo = get_audit_repository()
    items, total = repo.list(page=page, page_size=page_size, source=source, actor=actor)
    return json_no_store({"items": items, "page": page, "page_size": page_size, "total": total})


_webhook_seen = TTLCache(maxsize=8192)


async def _handle_webhook(request: Request, *, secret_env: str, source: str) -> Response:
    ok = await verify_webhook_signature(request, secret_env=secret_env)
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid signature")
    try:
        body = await request.json()
    except Exception:
        body = {}
    event_id = request.headers.get("x-event-id") or request.headers.get("X-Event-Id") or body.get("id") or body.get("event_id")
    if event_id:
        key = f"{source}:{event_id}"
        if _webhook_seen.seen(key):
            return Response(status_code=202)
        _webhook_seen.set(key, ttl_seconds=int(os.environ.get("WEBHOOKS_DEDUP_TTL", "600")))

    repo = get_audit_repository()
    actor = request.headers.get("x-sender") or request.headers.get("X-Sender")
    # Avoid logging full headers in production if sensitive; adjust as needed
    repo.add(source=source, action="webhook", actor=actor, meta={"headers": dict(request.headers), "body": body})
    return Response(status_code=202)


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

