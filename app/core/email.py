# app/core/email.py
from __future__ import annotations

from datetime import datetime
import logging
from typing import Iterable
from urllib.parse import quote

from fastapi import HTTPException

from app.core.config import settings
from app.utils.email_utils import (
    send_email as _send_text_email,                    # sync SMTP sender (from your email_utils.py)
    send_verification_email as _send_verification_email,
    send_password_reset_otp as _send_password_reset_otp,
    send_reactivation_email as _send_reactivation_email,
    send_export_email as _send_export_email,
)

logger = logging.getLogger(__name__)

def _coerce_base_url(val: object, default: str = "http://localhost:8000") -> str:
    try:
        s = str(val) if val else default
    except Exception:
        s = default
    return s.rstrip("/")

_PRODUCT = str(getattr(settings, "EMAIL_FROM_NAME", None) or "MoviesNow")
_FRONTEND = _coerce_base_url(getattr(settings, "FRONTEND_URL", None))

# ─────────────────────────────────────────────────────────────
# ✉️  Basic senders (sync/async)
# ─────────────────────────────────────────────────────────────

def send_basic_email(to: str, subject: str, body: str) -> None:
    """Plain-text email via email_utils; raises HTTPException(500) on failure."""
    try:
        _send_text_email(to, subject, body)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Email send failed (to=%s, subject=%s)", to, subject)
        raise HTTPException(status_code=500, detail="Email sending failed") from e

def send_email(to: str, subject: str, body: str, html: str | None = None) -> None:
    """
    Back-compat façade expected by various services (incl. MFA reset).
    - Prefers rich HTML if your email_utils supports it.
    - Falls back to plain text transparently.
    """
    try:
        # Try calling email_utils with HTML support if available
        _send_text_email(to, subject, body, html=html)  # type: ignore[call-arg]
    except TypeError:
        # Older signature without `html` kwarg → send text only
        _send_text_email(to, subject, body)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Email send failed (to=%s, subject=%s)", to, subject)
        raise HTTPException(status_code=500, detail="Email sending failed") from e

# ─────────────────────────────────────────────────────────────
# 🔐 Account lifecycle (async) — delegates to email_utils
# ─────────────────────────────────────────────────────────────

async def send_verification(to_email: str, token: str) -> None:
    await _send_verification_email(to_email, token)

async def send_password_reset_code(to_email: str, otp: str) -> None:
    await _send_password_reset_otp(to_email, otp)

async def send_reactivation(to_email: str, token: str) -> None:
    await _send_reactivation_email(to_email, token)

async def send_access_logs_export(user, session_id: str, rows: Iterable[dict], *, as_zip: bool = False) -> None:
    await _send_export_email(user, session_id, rows, as_zip=as_zip)

# ─────────────────────────────────────────────────────────────
# 🧩 Compatibility wrappers (legacy org-style flows)
# ─────────────────────────────────────────────────────────────

def send_email_invitation(to: str, project_name: str, token: str) -> None:
    invite_link = f"{_FRONTEND}/accept-invite?token={quote(token)}"
    subject = f"You're invited to join {project_name} on {_PRODUCT}"
    body = (
        f"Hello,\n\n"
        f"You've been invited to join \"{project_name}\" on {_PRODUCT}.\n\n"
        f"Accept the invitation:\n{invite_link}\n\n"
        "This link expires in 7 days. If you didn't expect this, you can ignore the email.\n\n"
        f"— {_PRODUCT} Team"
    )
    send_basic_email(to, subject, body)

def send_org_creation_token_email(to_email: str, project_name: str, token: str, expires_at: datetime) -> None:
    subject = f"Your creation token for '{project_name}'"
    body = (
        "Hi,\n\n"
        f"You requested to create the project {project_name} on {_PRODUCT}.\n\n"
        f"Token: {token}\n"
        f"Expires: {expires_at.strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"
        "Use this token in the project creation screen.\n\n"
        f"— {_PRODUCT} Team"
    )
    send_basic_email(to_email, subject, body)

def send_superuser_token_confirmation_email(to_email: str, project_name: str, token: str, expires_at: datetime) -> None:
    subject = f"✅ Token ready for '{project_name}'"
    body = (
        "Hi,\n\n"
        "As a privileged user, your request to create a project was auto-approved.\n\n"
        f"Token: {token}\n"
        f"Expires: {expires_at.strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"
        "Use this token on the creation screen to finalize setup.\n\n"
        f"— {_PRODUCT} Team"
    )
    send_basic_email(to_email, subject, body)

def send_org_token_request_ack_email(to_email: str, project_name: str) -> None:
    subject = f"We received your project request for '{project_name}'"
    body = (
        "Hi,\n\n"
        f"We've received your request to create {project_name} on {_PRODUCT}.\n\n"
        "An admin will review it. You'll get a separate email with your token once approved.\n\n"
        f"— {_PRODUCT} Team"
    )
    send_basic_email(to_email, subject, body)
