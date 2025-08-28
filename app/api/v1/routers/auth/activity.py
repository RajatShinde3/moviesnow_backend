# app/api/v1/auth/activity.py

"""
Enterprise-grade Login Activity & Security Alerts API
====================================================

What this router provides
-------------------------
- **Readable activity feed** for the signed-in user (auth + security events)
- **Security alerts subscription** surface (new device / location / impossible travel)

Design goals
------------
- **Privacy**: never returns sensitive bearer material or full user agents unless required
- **Resilience**: DB-first (`AuditLog`) with **Redis ring buffer** fallback
- **No-store**: responses set Cache-Control: no-store
- **Rate-limited**: per-route guards complement global throttles
- **Auditable**: all reads/writes recorded (best-effort)

Data sources
------------
- **DB (preferred)**: `app.db.models.audit_log.AuditLog` with
  `(id, user_id, action, status, created_at, ip, user_agent, meta_json)`.
- **Redis fallback**: `audit:recent:{user_id}` (RPUSH newest; LTRIM to max).
"""

import json
import logging
from datetime import datetime, timezone
from typing import List, Optional, Literal, Callable, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.redis_client import redis_wrapper
from app.core.limiter import rate_limit
from app.core.dependencies import get_async_db, get_current_user
from app.security_headers import set_sensitive_cache
from app.db.models.user import User
from app.schemas.auth import ActivityItem, ActivityResponse, AlertsSubscription
from app.services.audit_log_service import log_audit_event

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Activity & Alerts"])

# ──────────────────────────────────────────────────────────────
# Redis keys
# ──────────────────────────────────────────────────────────────
RB_KEY: Callable[[UUID], str] = lambda user_id: f"audit:recent:{user_id}"
SUB_KEY: Callable[[UUID], str] = lambda user_id: f"alert:sub:{user_id}"

MAX_RB = int(getattr(settings, "ACTIVITY_RING_MAX", 200))
DEFAULT_LIMIT = 50


# ──────────────────────────────────────────────────────────────
# 🧩 Small Lua snippets (atomic counter + TTL on first increment)
# ──────────────────────────────────────────────────────────────
INCR_EXPIRE_LUA = """
local v = redis.call('incr', KEYS[1])
if v == 1 then redis.call('expire', KEYS[1], ARGV[1]) end
return v
"""


# ──────────────────────────────────────────────────────────────
# Redis helpers (best-effort; safe on outages)
# ──────────────────────────────────────────────────────────────
def _rc():
    """Return the shared Redis client (mock or real), or None."""
    try:
        return getattr(redis_wrapper, "client", None)
    except Exception:
        return None


async def _r_lrange(key: str, start: int, end: int) -> list[Any]:
    r = _rc()
    if not r:
        return []
    try:
        return await r.lrange(key, start, end)
    except Exception:
        return []


async def _r_hgetall(key: str) -> dict[str, Any]:
    r = _rc()
    if not r:
        return {}
    try:
        raw = await r.hgetall(key)
        # Some clients return dict[bytes, bytes]; normalize
        out: dict[str, Any] = {}
        for k, v in (raw or {}).items():
            ks = k.decode() if isinstance(k, (bytes, bytearray)) else str(k)
            vs = v.decode() if isinstance(v, (bytes, bytearray)) else v
            out[ks] = vs
        return out
    except Exception:
        return {}


async def _r_hset(key: str, mapping: dict[str, Any]) -> None:
    r = _rc()
    if not r:
        raise RuntimeError("KV not available")
    try:
        await r.hset(key, mapping=mapping)
    except Exception as e:
        raise RuntimeError("KV write failed") from e


# ──────────────────────────────────────────────────────────────
# Decoders / mappers
# ──────────────────────────────────────────────────────────────
def _as_str(b: Any) -> str:
    return b.decode() if isinstance(b, (bytes, bytearray)) else str(b)


def _safe_iso(ts: Optional[str]) -> datetime:
    try:
        return datetime.fromisoformat(ts) if ts else datetime.now(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _match_filter(action: str, tfilter: Optional[str]) -> bool:
    a = (action or "").upper()
    if not tfilter or tfilter == "all":
        return True
    if tfilter == "auth":
        return a.startswith(("LOGIN", "LOGOUT", "MFA", "REFRESH", "SIGNUP"))
    if tfilter == "security":
        return a.startswith(("TRUSTED_DEVICE", "RECOVERY", "REAUTH", "ACCOUNT", "VERIFY", "DELETE", "DEACTIVATE"))
    return True


# ──────────────────────────────────────────────────────────────
# Readers
# ──────────────────────────────────────────────────────────────
async def _read_recent_from_redis(user_id: UUID, limit: int, tfilter: Optional[str]) -> List[ActivityItem]:
    raw = await _r_lrange(RB_KEY(user_id), -limit, -1)
    items: List[ActivityItem] = []
    for b in raw or []:
        try:
            obj = json.loads(_as_str(b))
            act = str(obj.get("action", "") or "")
            if not _match_filter(act, tfilter):
                continue
            items.append(
                ActivityItem(
                    id=str(obj.get("id")) or None,
                    at=_safe_iso(obj.get("at")),
                    action=act,
                    status=str(obj.get("status", "") or ""),
                    ip=obj.get("ip"),
                    user_agent=obj.get("user_agent"),
                    geo=obj.get("geo"),
                    device=obj.get("device"),
                    meta=obj.get("meta") if isinstance(obj.get("meta"), dict) else None,
                )
            )
        except Exception:
            continue
    return items


async def _read_recent_from_db(
    db: AsyncSession, user_id: UUID, limit: int, tfilter: Optional[str]
) -> List[ActivityItem]:
    """
    Best-effort DB query using a conventional `AuditLog` model.

    Expected columns: id, user_id, action, status, created_at, ip, user_agent, meta_json
    If the model is not available, returns an empty list.
    """
    try:
        from app.db.models.audit_log import AuditLog  # type: ignore
    except Exception:
        return []

    q = (
        select(AuditLog)
        .where(AuditLog.user_id == user_id)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
    )
    rows = (await db.execute(q)).scalars().all()

    items: List[ActivityItem] = []
    for r in rows:
        try:
            meta_raw = getattr(r, "meta_json", None)
            if isinstance(meta_raw, (bytes, bytearray)):
                meta_raw = meta_raw.decode()
            meta = {}
            if isinstance(meta_raw, str):
                try:
                    meta = json.loads(meta_raw)
                except Exception:
                    meta = {}
            elif isinstance(meta_raw, dict):
                meta = meta_raw

            action = str(getattr(r, "action", "") or "")
            if not _match_filter(action, tfilter):
                continue

            items.append(
                ActivityItem(
                    id=str(getattr(r, "id", "") or None) or None,
                    at=getattr(r, "created_at", datetime.now(timezone.utc)),
                    action=action,
                    status=str(getattr(r, "status", "") or ""),
                    ip=getattr(r, "ip", None),
                    user_agent=getattr(r, "user_agent", None),
                    geo=(meta.get("geo") if isinstance(meta, dict) else None),
                    device=(meta.get("device") if isinstance(meta, dict) else None),
                    meta=meta if isinstance(meta, dict) else None,
                )
            )
        except Exception:
            continue

    return items


async def _load_subscription(user_id: UUID) -> AlertsSubscription:
    h = await _r_hgetall(SUB_KEY(user_id))
    if not h:
        return AlertsSubscription()
    def _to_bool(v: Any) -> bool:
        return str(v).lower() in ("1", "true", "yes", "on")
    return AlertsSubscription(
        new_device=_to_bool(h.get("new_device", "1")),
        new_location=_to_bool(h.get("new_location", "1")),
        impossible_travel=_to_bool(h.get("impossible_travel", "1")),
        email_notifications=_to_bool(h.get("email_notifications", "1")),
    )


# ──────────────────────────────────────────────────────────────
# 🔎 GET /activity — recent login & security activity
# ──────────────────────────────────────────────────────────────
@router.get(
    "/activity",
    response_model=ActivityResponse,
    summary="View recent login/security activity for the current user",
)
@rate_limit("30/minute")
async def get_activity(
    request: Request,
    response: Response,
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=200),
    type: Optional[Literal["all", "auth", "security"]] = Query("all"),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> ActivityResponse:
    """
    Return the most recent **auth & security** events for the caller.

    Behavior
    --------
    - **DB-first**: attempt to read from `AuditLog`; if unavailable, fall back to
      the Redis ring buffer `audit:recent:{user_id}`.
    - Results are best-effort filtered and limited to `limit`.
    - Response is marked **no-store**.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Query data sources ──────────────────────────────────────────
    tfilter = None if type == "all" else type
    items_db = await _read_recent_from_db(db, current_user.id, limit, tfilter)
    items = items_db[:limit] if items_db else await _read_recent_from_redis(current_user.id, limit, tfilter)

    # ── [Step 2] Audit & respond ─────────────────────────────────────────────
    try:
        await log_audit_event(db, action="ACTIVITY_VIEW", user=current_user, status="SUCCESS", request=request)
    except Exception:
        # do not fail the read on audit hiccups
        pass

    return ActivityResponse(total=len(items), items=items)


# ──────────────────────────────────────────────────────────────
# 🔔 GET /alerts/subscription — view alert preferences
# ──────────────────────────────────────────────────────────────
@router.get(
    "/alerts/subscription",
    response_model=AlertsSubscription,
    summary="View current security alert subscription preferences",
)
@rate_limit("30/minute")
async def get_alert_subscription(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> AlertsSubscription:
    """
    Return the user's current alert subscription preferences.

    Storage
    -------
    - Backed by Redis `HSET alert:sub:{user_id}` for low-latency checks by login flows.
    - If Redis is unavailable, returns defaults (all True).
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)
    return await _load_subscription(current_user.id)


# ──────────────────────────────────────────────────────────────
# 🔔 POST /alerts/subscribe — update alert preferences
# ──────────────────────────────────────────────────────────────
@router.post(
    "/alerts/subscribe",
    response_model=AlertsSubscription,
    summary="Update security alert subscription preferences",
)
@rate_limit("10/minute")
async def update_alert_subscription(
    payload: AlertsSubscription,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> AlertsSubscription:
    """
    Update the user's security alert preferences.

    Storage
    -------
    - Preferences are stored in Redis under `alert:sub:{user_id}` as an `HSET`.
    - If Redis is down, returns **503** (since preferences would not persist).
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Persist in Redis (HSET) ─────────────────────────────────────
    mapping = {
        "new_device": "1" if payload.new_device else "0",
        "new_location": "1" if payload.new_location else "0",
        "impossible_travel": "1" if payload.impossible_travel else "0",
        "email_notifications": "1" if payload.email_notifications else "0",
    }
    try:
        await _r_hset(SUB_KEY(current_user.id), mapping=mapping)
    except Exception:
        try:
            await log_audit_event(
                db, action="ALERTS_UPDATE", user=current_user, status="FAILURE", request=request, meta_data={"reason": "kv_unavailable"}
            )
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Preferences storage unavailable.")

    # ── [Step 2] Audit & respond ─────────────────────────────────────────────
    try:
        await log_audit_event(db, action="ALERTS_UPDATE", user=current_user, status="SUCCESS", request=request, meta_data=mapping)
    except Exception:
        pass
    return await _load_subscription(current_user.id)


__all__ = ["router"]
