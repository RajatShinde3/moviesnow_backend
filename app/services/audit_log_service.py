# app/services/audit_log_service.py
from __future__ import annotations

"""
MoviesNow — Audit Log Service (async, production-grade)
======================================================

Purpose
-------
Persist structured audit trails for authentication, playback, download,
search, subscription, and account actions — with request metadata for
observability and traceability.

Highlights
----------
- Proxy-aware IP extraction (X-Forwarded-For / X-Real-IP fallback to client.host)
- Correlates with `request.state.request_id` (from RequestIDMiddleware)
- Strict, JSON-serializable `meta_data` with secret-key scrubbing
- Safe DB writes with `flush()` and optional `commit`
- Minimal domain: **no org/tenant dependencies**

Usage
-----
    await log_audit_event(
        db,
        user=current_user,
        action=AuditEvent.PLAYBACK_PLAY,
        status="SUCCESS",
        request=request,
        meta_data={"title_id": str(title_id), "profile_id": str(profile_id)},
    )
"""

from datetime import datetime, timezone
from enum import Enum
import json
import logging
from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import Request
from sqlalchemy.exc import InvalidRequestError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.audit_log import AuditLog
from app.db.models.user import User

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# 📋 Enum: Audit Event Types (MoviesNow domain)
# ─────────────────────────────────────────────────────────────
class AuditEvent(str, Enum):
    # 🎯 Auth
    LOGIN = "LOGIN"
    SIGNUP = "SIGNUP"
    LOGOUT = "LOGOUT"
    REFRESH_TOKEN = "REFRESH_TOKEN"
    MFA_LOGIN = "MFA_LOGIN"
    VERIFY_EMAIL = "VERIFY_EMAIL"
    RESEND_VERIFICATION = "RESEND_VERIFICATION"
    REQUEST_PASSWORD_RESET = "REQUEST_PASSWORD_RESET"
    RESET_PASSWORD = "RESET_PASSWORD"
    DEACTIVATE_USER = "DEACTIVATE_USER"
    REACTIVATE_USER = "REACTIVATE_USER"
    DELETE_USER = "DELETE_USER"

    # 🎬 Playback & Player
    PLAYBACK_PLAY = "PLAYBACK_PLAY"
    PLAYBACK_PAUSE = "PLAYBACK_PAUSE"
    PLAYBACK_RESUME = "PLAYBACK_RESUME"
    PLAYBACK_COMPLETE = "PLAYBACK_COMPLETE"
    PLAYBACK_STOP = "PLAYBACK_STOP"
    PLAYBACK_SEEK = "PLAYBACK_SEEK"
    STREAM_START = "STREAM_START"
    STREAM_BUFFERING_START = "STREAM_BUFFERING_START"
    STREAM_BUFFERING_END = "STREAM_BUFFERING_END"
    STREAM_ERROR = "STREAM_ERROR"
    BITRATE_SWITCH = "BITRATE_SWITCH"
    SUBTITLE_ON = "SUBTITLE_ON"
    SUBTITLE_OFF = "SUBTITLE_OFF"
    AUDIO_TRACK_SWITCH = "AUDIO_TRACK_SWITCH"
    QUALITY_CHANGE = "QUALITY_CHANGE"

    # ⬇️ Downloads
    DOWNLOAD_REQUESTED = "DOWNLOAD_REQUESTED"
    DOWNLOAD_STARTED = "DOWNLOAD_STARTED"
    DOWNLOAD_COMPLETED = "DOWNLOAD_COMPLETED"
    DOWNLOAD_FAILED = "DOWNLOAD_FAILED"
    DOWNLOAD_DELETED = "DOWNLOAD_DELETED"

    # 🔎 Discovery
    SEARCH = "SEARCH"
    TITLE_OPENED = "TITLE_OPENED"
    WATCHLIST_ADD = "WATCHLIST_ADD"
    WATCHLIST_REMOVE = "WATCHLIST_REMOVE"
    FAVORITE_ADD = "FAVORITE_ADD"
    FAVORITE_REMOVE = "FAVORITE_REMOVE"
    RATING_SET = "RATING_SET"
    REVIEW_CREATED = "REVIEW_CREATED"
    REVIEW_DELETED = "REVIEW_DELETED"

    # 💳 Subscription / Billing
    SUBSCRIPTION_PURCHASED = "SUBSCRIPTION_PURCHASED"
    SUBSCRIPTION_RENEWED = "SUBSCRIPTION_RENEWED"
    SUBSCRIPTION_CANCELED = "SUBSCRIPTION_CANCELED"
    PAYMENT_FAILED = "PAYMENT_FAILED"

    # 📱 Devices / Sessions
    DEVICE_LINKED = "DEVICE_LINKED"
    DEVICE_UNLINKED = "DEVICE_UNLINKED"
    SESSION_REVOKED = "SESSION_REVOKED"


# ─────────────────────────────────────────────────────────────
# 🔎 Helpers: request metadata & meta scrubbing
# ─────────────────────────────────────────────────────────────
_SENSITIVE_KEYS = {"authorization", "token", "access_token", "refresh_token", "password", "secret", "cookie", "set-cookie"}

def _client_ip(request: Optional[Request]) -> Optional[str]:
    if not request:
        return None
    hdrs = request.headers
    xff = hdrs.get("x-forwarded-for") or hdrs.get("X-Forwarded-For")
    if xff:
        # take the first IP in the list
        ip = xff.split(",")[0].strip()
        if ip:
            return ip
    xri = hdrs.get("x-real-ip") or hdrs.get("X-Real-IP")
    if xri:
        return xri.strip()
    return request.client.host if request and request.client else None

def _scrub(obj: Any) -> Any:
    """
    Recursively remove obvious secret keys from dicts/lists.
    Non-dict/list values are returned as-is.
    """
    try:
        if isinstance(obj, dict):
            clean: Dict[str, Any] = {}
            for k, v in obj.items():
                kl = str(k).lower()
                if kl in _SENSITIVE_KEYS:
                    continue
                clean[k] = _scrub(v)
            return clean
        if isinstance(obj, list):
            return [_scrub(v) for v in obj]
        return obj
    except Exception:
        return {"raw": str(obj)}

def _safe_metadata(meta_data: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if meta_data is None:
        return None
    if not isinstance(meta_data, dict):
        meta_data = {"raw": str(meta_data)}
    meta_data = _scrub(meta_data)
    # Ensure JSON-serializable
    try:
        json.dumps(meta_data)
        return meta_data
    except Exception:
        return {"raw": "non-serializable metadata"}

def _request_snapshot(request: Optional[Request]) -> Dict[str, Any]:
    if not request:
        return {}
    try:
        return {
            "method": request.method,
            "path": request.url.path,
            "referer": request.headers.get("referer") or request.headers.get("Referer"),
            "request_id": getattr(request.state, "request_id", None),
        }
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────
# 🧠 Audit Writer
# ─────────────────────────────────────────────────────────────
async def log_audit_event(
    db: AsyncSession,
    *,
    user: Optional[User] = None,
    action: AuditEvent,
    status: str,
    request: Optional[Request] = None,
    meta_data: Optional[Dict[str, Any]] = None,
    override_user_id: Optional[UUID] = None,
    commit: bool = True,
) -> None:
    """
    Persist an audit log row for the given action.

    Captures:
      - user_id (from `user` or `override_user_id`)
      - action (typed via `AuditEvent`)
      - status (normalized upper-case string, e.g., SUCCESS / FAILURE)
      - ip/user-agent/request_id (proxy-aware)
      - timestamp (UTC)
      - sanitized, JSON-serializable `meta_data`

    On DB errors:
      - Attempts rollback, raises `RuntimeError` with a generic message.
    """
    try:
        ip_address = _client_ip(request)
        user_agent = request.headers.get("user-agent") if request else None
        request_id = getattr(request.state, "request_id", None) if request else None
        user_id = override_user_id or (user.id if user else None)

        # Merge minimal request snapshot into metadata (without overriding caller-provided keys)
        base_meta = _request_snapshot(request)
        clean_meta = _safe_metadata(meta_data) or {}
        for k, v in base_meta.items():
            clean_meta.setdefault(k, v)

        entry = AuditLog(
            user_id=user_id,
            action=action,
            status=str(status or "").upper(),
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            timestamp=datetime.now(timezone.utc),
            meta_data=clean_meta if clean_meta else None,
        )

        db.add(entry)
        await db.flush()
        if commit:
            await db.commit()

    except InvalidRequestError as ire:
        logger.warning("[AUDIT] Flush failed: %s", ire)
        raise RuntimeError("Could not flush audit log") from ire

    except SQLAlchemyError as db_err:
        logger.exception("[AUDIT] Database error: %s", db_err)
        try:
            await db.rollback()
        except Exception as rollback_err:
            logger.warning("[AUDIT] Rollback failed after DB error: %s", rollback_err)
        raise RuntimeError("Could not write audit log to database") from db_err

    except Exception as e:
        logger.exception("[AUDIT] Unexpected failure: %s", e)
        try:
            await db.rollback()
        except Exception as rollback_err:
            logger.warning("[AUDIT] Rollback failed after unknown error: %s", rollback_err)
        raise RuntimeError("Audit logging failed unexpectedly") from e


__all__ = ["AuditEvent", "log_audit_event"]
