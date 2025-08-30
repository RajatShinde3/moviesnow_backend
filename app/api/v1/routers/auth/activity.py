# app/api/v1/auth/activity.py

"""
MoviesNow — Login Activity & Security Alerts API (production-grade)
==================================================================

What this router provides
-------------------------
- **Readable activity feed** for the signed-in user (auth + security events)
- **Security alerts subscription** surface (new device / location / impossible travel)

Security & Reliability
----------------------
- **Privacy:** never returns sensitive bearer material; trims UA/IP only for display
- **Resilience:** DB-first (`AuditLog`) with **Redis ring buffer** fallback
- **No-store:** responses are hardened with `Cache-Control: no-store`
- **Rate-limited:** per-route guards complement global throttles
- **Auditable:** reads/writes recorded via `log_audit_event` (best-effort, non-blocking)

Data sources
------------
- **DB (preferred):** `app.db.models.audit_log.AuditLog` with
  `(id, user_id, action, status, occurred_at, ip_address, user_agent, metadata_json)`.
- **Redis fallback:** `audit:recent:{user_id}` (RPUSH newest; LTRIM to max).

Notes
-----
- This router requires a signed-in user (uses `get_current_user`). It does **not**
  enforce `mfa_authenticated=True` itself; enforce MFA at the dependency level
  (e.g., `get_current_user_mfa`) if your policy requires it for these reads/writes.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.limiter import rate_limit
from app.core.redis_client import redis_wrapper
from app.core.security import get_current_user
from app.db.models.user import User
from app.db.session import get_async_db
from app.schemas.auth import ActivityItem, ActivityResponse, AlertsSubscription
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event, AuditEvent

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Activity & Alerts"])

# ──────────────────────────────────────────────────────────────
# Redis keys & tunables
# ──────────────────────────────────────────────────────────────

RB_KEY: Callable[[UUID], str] = lambda user_id: f"audit:recent:{user_id}"
SUB_KEY: Callable[[UUID], str] = lambda user_id: f"alert:sub:{user_id}"

# Ring buffer maximum (fallback path only)
MAX_RB = int(getattr(settings, "ACTIVITY_RING_MAX", 200))
DEFAULT_LIMIT = 50

# (Kept for future use if you add counters/rate metrics in Redis)
INCR_EXPIRE_LUA = """
local v = redis.call('incr', KEYS[1])
if v == 1 then redis.call('expire', KEYS[1], ARGV[1]) end
return v
"""

# ──────────────────────────────────────────────────────────────
# Small helpers
# ──────────────────────────────────────────────────────────────

def _rc():
    """Return the shared Redis client (mock or real), or None if unavailable."""
    try:
        return getattr(redis_wrapper, "client", None)
    except Exception:
        return None


def _b2s(v: Any) -> Any:
    """Bytes → str pass-through for Redis values; leave other types untouched."""
    return v.decode() if isinstance(v, (bytes, bytearray)) else v


def _safe_iso(ts: Optional[str]) -> datetime:
    """Parse an ISO timestamp defensively; return now (UTC) on failure/absence."""
    try:
        if not ts:
            return datetime.now(timezone.utc)
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.now(timezone.utc)


def _match_filter(action: str, tfilter: Optional[str]) -> bool:
    """Simple category filter for actions."""
    a = (action or "").upper()
    if not tfilter or tfilter == "all":
        return True
    if tfilter == "auth":
        return a.startswith(("LOGIN", "LOGOUT", "MFA", "REFRESH", "SIGNUP", "REAUTH"))
    if tfilter == "security":
        return a.startswith(("TRUSTED_DEVICE", "RECOVERY", "ACCOUNT", "VERIFY", "DELETE", "DEACTIVATE"))
    return True


# ──────────────────────────────────────────────────────────────
# Redis I/O (best-effort; tolerate outages)
# ──────────────────────────────────────────────────────────────

async def _r_lrange(key: str, start: int, end: int) -> List[Any]:
    r = _rc()
    if not r:
        return []
    try:
        res = await r.lrange(key, start, end)
        return [_b2s(x) for x in (res or [])]
    except Exception:
        logger.debug("Redis lrange failed for key=%s", key, exc_info=True)
        return []


async def _r_hgetall(key: str) -> Dict[str, Any]:
    r = _rc()
    if not r:
        return {}
    try:
        raw = await r.hgetall(key)
        return {str(_b2s(k)): _b2s(v) for k, v in (raw or {}).items()}
    except Exception:
        logger.debug("Redis hgetall failed for key=%s", key, exc_info=True)
        return {}


async def _r_hset(key: str, mapping: Dict[str, Any]) -> None:
    r = _rc()
    if not r:
        raise RuntimeError("KV not available")
    try:
        await r.hset(key, mapping=mapping)
    except Exception as e:
        logger.warning("Redis hset failed for key=%s", key, exc_info=True)
        raise RuntimeError("KV write failed") from e


# ──────────────────────────────────────────────────────────────
# Readers (DB-first, Redis fallback)
# ──────────────────────────────────────────────────────────────

async def _read_recent_from_redis(
    user_id: UUID, limit: int, tfilter: Optional[str]
) -> List[ActivityItem]:
    """Read recent entries from the Redis ring buffer for the user."""
    # We store newest at the tail; lrange -limit..-1 returns last `limit`
    raw = await _r_lrange(RB_KEY(user_id), -limit, -1)
    items: List[ActivityItem] = []
    for entry in raw:
        try:
            obj = json.loads(str(entry))
            act = str(obj.get("action", "") or "")
            if not _match_filter(act, tfilter):
                continue
            items.append(
                ActivityItem(
                    id=str(obj.get("id") or "") or None,
                    at=_safe_iso(obj.get("at")),
                    action=act,
                    status=str(obj.get("status", "") or ""),
                    ip=(obj.get("ip") or None),
                    user_agent=(obj.get("user_agent") or None),
                    geo=obj.get("geo"),
                    device=obj.get("device"),
                    meta=obj.get("meta") if isinstance(obj.get("meta"), dict) else None,
                )
            )
        except Exception:
            # Ignore malformed rows
            continue
    return items


async def _read_recent_from_db(
    db: AsyncSession, user_id: UUID, limit: int, tfilter: Optional[str]
) -> List[ActivityItem]:
    """Best-effort DB query using MoviesNow `AuditLog`.

    Expected columns:
      - id, user_id, action, status, occurred_at, ip_address, user_agent, metadata_json
    Returns an empty list if the model is missing or on unexpected failures.
    """
    try:
        from app.db.models.audit_log import AuditLog  # type: ignore
    except Exception:
        # Model not available in some deployments/tests — ok to fallback
        return []

    q = (
        select(AuditLog)
        .where(AuditLog.user_id == user_id)
        .order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
        .limit(limit)
    )

    try:
        rows = (await db.execute(q)).scalars().all()
    except Exception:  # DB hiccup — prefer silent fallback
        logger.warning("DB activity query failed", exc_info=True)
        return []

    items: List[ActivityItem] = []
    for r in rows:
        try:
            meta_raw = getattr(r, "metadata_json", None)
            meta: Dict[str, Any] = {}
            if isinstance(meta_raw, (bytes, bytearray)):
                try:
                    meta = json.loads(meta_raw.decode())
                except Exception:
                    meta = {}
            elif isinstance(meta_raw, str):
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
                    id=str(getattr(r, "id", "") or "") or None,
                    at=getattr(r, "occurred_at", datetime.now(timezone.utc)),
                    action=action,
                    status=str(getattr(r, "status", "") or ""),
                    ip=getattr(r, "ip_address", None),
                    user_agent=getattr(r, "user_agent", None),
                    geo=(meta.get("geo") if isinstance(meta, dict) and isinstance(meta.get("geo"), dict) else None),
                    device=(meta.get("device") if isinstance(meta, dict) and isinstance(meta.get("device"), dict) else None),
                    meta=meta if isinstance(meta, dict) else None,
                )
            )
        except Exception as e:
            # Skip malformed row
            continue

    return items


async def _load_subscription(user_id: UUID) -> AlertsSubscription:
    """Load alert preferences from Redis, returning safe defaults if missing."""
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
# 🔎 GET /auth/activity — recent login & security activity
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
    type: Optional[Literal["all", "auth", "security"]] = Query("all"),  # noqa: A002 (intentional param name)
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> ActivityResponse:
    """Return the most recent **auth & security** events for the caller.

    Behavior
    --------
    - **DB-first:** attempt to read from `AuditLog`; if unavailable or empty,
      fall back to the Redis ring buffer `audit:recent:{user_id}`.
    - Best-effort filtered and limited to `limit`.
    - Response is marked **no-store**.
    """
    # [Step 0] Cache hardening
    set_sensitive_cache(response)

    # [Step 1] Query data sources
    tfilter = None if type == "all" else type
    items_db = await _read_recent_from_db(db, current_user.id, limit, tfilter)
    items_rb = await _read_recent_from_redis(current_user.id, limit, tfilter)

    # Prefer DB but include Redis fallback entries as well; then sort and limit
    items_combined = (items_db or []) + (items_rb or [])
    items = sorted(items_combined, key=lambda it: it.at, reverse=True)[:limit]

    # Debug aid for tests: log selected actions (safe)
    # [Step 2] Audit (non-blocking)
    try:
        await log_audit_event(db, action=AuditEvent.ACTIVITY_VIEW, user=current_user, status="SUCCESS", request=request)
    except Exception:
        logger.debug("audit log write failed (ACTIVITY_VIEW)", exc_info=True)

    return ActivityResponse(total=len(items), items=items)


# ──────────────────────────────────────────────────────────────
# 🔔 GET /auth/alerts/subscription — view alert preferences
# ──────────────────────────────────────────────────────────────

@router.get(
    "/alerts/subscription",
    response_model=AlertsSubscription,
    summary="View current security alert subscription preferences",
)
@rate_limit("30/minute")
async def get_alert_subscription(
    request: Request,  # kept for symmetry / future audit needs
    response: Response,
    current_user: User = Depends(get_current_user),
) -> AlertsSubscription:
    """Return the user's current alert subscription preferences.

    Storage
    -------
    - Backed by Redis `HSET alert:sub:{user_id}` for low-latency checks by login flows.
    - If Redis is unavailable, returns defaults (all True).
    """
    set_sensitive_cache(response)
    return await _load_subscription(current_user.id)


# ──────────────────────────────────────────────────────────────
# 🔔 POST /auth/alerts/subscribe — update alert preferences
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
    """Update the user's security alert preferences.

    Storage
    -------
    - Preferences are stored in Redis under `alert:sub:{user_id}` as an `HSET`.
    - If Redis is down, returns **503** (since preferences would not persist).
    """
    set_sensitive_cache(response)

    mapping = {
        "new_device": "1" if payload.new_device else "0",
        "new_location": "1" if payload.new_location else "0",
        "impossible_travel": "1" if payload.impossible_travel else "0",
        "email_notifications": "1" if payload.email_notifications else "0",
    }

    # [Step 1] Persist in Redis (HSET)
    try:
        await _r_hset(SUB_KEY(current_user.id), mapping=mapping)
    except Exception:
        # Audit best-effort, then surface a 503 (persistence required)
        try:
            await log_audit_event(
                db,
                action=AuditEvent.ALERTS_UPDATE,
                user=current_user,
                status="FAILURE",
                request=request,
                meta_data={"reason": "kv_unavailable"},
            )
        except Exception:
            logger.debug("audit log write failed (ALERTS_UPDATE failure)", exc_info=True)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Preferences storage unavailable.")

    # [Step 2] Audit success & respond
    try:
        await log_audit_event(
            db,
            action=AuditEvent.ALERTS_UPDATE,
            user=current_user,
            status="SUCCESS",
            request=request,
            meta_data=mapping,
        )
    except Exception:
        logger.debug("audit log write failed (ALERTS_UPDATE success)", exc_info=True)

    return await _load_subscription(current_user.id)


__all__ = ["router", "get_activity", "get_alert_subscription", "update_alert_subscription"]
