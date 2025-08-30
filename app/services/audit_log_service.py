# app/services/audit_log_service.py
from __future__ import annotations

"""
MoviesNow — Audit Log Service (async, production‑grade, org‑free)
================================================================

Purpose
-------
Persist structured audit trails for authentication, playback, download,
search, subscription, and account actions — with request metadata for
observability and traceability.

Design notes
------------
- **Proxy‑aware IP** extraction (`X-Forwarded-For`, `X-Real-IP`, Cloudflare headers).
- Correlates with `request.state.request_id` (see RequestID middleware).
- Strict, JSON‑serializable `meta_data` with secret‑key scrubbing.
- **DB column names** match the model: we write to `metadata_json` and *do not*
  set timestamps manually (DB default drives `occurred_at`).
- **Best‑effort** writes: failures are logged, the function swallows errors so
  business flows are never blocked by auditing.

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

from enum import Enum
import json
import logging
from typing import Any, Dict, Optional, Union
from uuid import UUID

from fastapi import Request
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
    MFA_RESET_REQUESTED = "MFA_RESET_REQUESTED"
    REVOKE_TOKEN = "REVOKE_TOKEN"
    REQUEST_DEACTIVATION_OTP = "REQUEST_DEACTIVATION_OTP"
    REACTIVATE_ACCOUNT = "REACTIVATE_ACCOUNT"
    REQUEST_REACTIVATION_OTP = "REQUEST_REACTIVATION_OTP"
    REQUEST_DELETION_OTP = "REQUEST_DELETION_OTP"
    ENABLE_MFA = "ENABLE_MFA"
    VERIFY_MFA = "VERIFY_MFA"
    DISABLE_MFA = "DISABLE_MFA"
    MFA_RESET_CONFIRMED = "MFA_RESET_CONFIRMED"

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
_SENSITIVE_KEYS = {
    "authorization",
    "token",
    "access_token",
    "refresh_token",
    "password",
    "secret",
    "cookie",
    "set-cookie",
}


def _client_ip(request: Optional[Request]) -> Optional[str]:
    if not request:
        return None
    hdrs = request.headers
    # Prefer standard proxy headers (left‑most IP is the client)
    xff = hdrs.get("x-forwarded-for") or hdrs.get("X-Forwarded-For")
    if xff:
        ip = xff.split(",")[0].strip()
        if ip:
            return ip
    xri = hdrs.get("x-real-ip") or hdrs.get("X-Real-IP")
    if xri:
        return xri.strip()
    ccip = hdrs.get("cf-connecting-ip") or hdrs.get("True-Client-IP")
    if ccip:
        return ccip.strip()
    return request.client.host if request and request.client else None


def _scrub(obj: Any) -> Any:
    """Recursively remove obvious secret keys from dicts/lists.
    Non‑dict/list values are returned as‑is.
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
    # Ensure JSON‑serializable
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
# 🧠 Audit Writer (best‑effort, never raises)
# ─────────────────────────────────────────────────────────────
async def log_audit_event(
    db: AsyncSession,
    *,
    user: Optional[User] = None,
    action: Union[str, AuditEvent],
    status: str,
    request: Optional[Request] = None,
    meta_data: Optional[Dict[str, Any]] = None,
    override_user_id: Optional[UUID] = None,
    commit: bool = True,
) -> None:
    """Persist an audit log row for the given action.

    Captures
    --------
    - `user_id` (from `user` or `override_user_id`)
    - `action` (enum/string)
    - `status` (normalized UPPER string, e.g., SUCCESS / FAILURE)
    - `ip_address`, `user_agent`, `request_id`
    - DB‑driven timestamp (`occurred_at` via default)
    - Sanitized, JSON‑serializable `meta_data` (stored as `metadata` column via `metadata_json` attr)

    Reliability
    -----------
    Any exception is **caught and logged**; the function returns without raising
    to avoid breaking business flows. Callers do not need try/except.
    """
    try:
        ip_address = _client_ip(request)
        user_agent = request.headers.get("user-agent") if request else None
        request_id = getattr(request.state, "request_id", None) if request else None
        user_id = override_user_id or (getattr(user, "id", None))

        # Merge minimal request snapshot into metadata (without overriding caller keys)
        base_meta = _request_snapshot(request)
        clean_meta = _safe_metadata(meta_data) or {}
        for k, v in base_meta.items():
            clean_meta.setdefault(k, v)

        entry = AuditLog(
            user_id=user_id,
            action=str(action),
            status=str(status or "").upper(),
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            metadata_json=clean_meta if clean_meta else None,
        )

        db.add(entry)
        await db.flush()
        if commit:
            await db.commit()
    except Exception as e:  # pragma: no cover — best‑effort path
        # Try to rollback and log; swallow errors
        try:
            await db.rollback()
        except Exception:
            pass
        logger.exception("[AUDIT] Failed to write audit log: %s", e)
        return None


__all__ = ["AuditEvent", "log_audit_event"]
