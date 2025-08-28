# app/utils/email_utils.py

from __future__ import annotations

"""
Enterprise Email Utilities for Career OS
=======================================

This module provides **production-grade** primitives to send transactional
emails via either:

- Plain SMTP (sync, text-only): `send_email`
- FastAPI-Mail (async; HTML/text; attachments; templating): the rest

Highlights
----------
- Safe config access from settings/env; works when settings aren’t imported yet.
- Pydantic v1/v2 compatibility for FastAPI-Mail `ConnectionConfig` (filters extras).
- MJML/Jinja template **dual-mode**:
    1) Classic fastapi-mail Jinja folder (EMAIL_TEMPLATE_DIR)
    2) Compiled MJML HTML (EMAIL_BUILD_HTML_DIR) + optional TXT (EMAIL_BUILD_TXT_DIR)
- Background-safe: async senders **log** failures instead of raising.
- Strong docs, typed APIs, minimal recipient validation.
- Graceful fallbacks: HTML → TXT → plaintext dump of context.

Environment / settings knobs
----------------------------
SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD
EMAIL_FROM, EMAIL_FROM_NAME
EMAIL_VERIFY_BASE_URL (fallback: FRONTEND_URL)
EMAIL_TEMPLATE_DIR            # e.g., app/email/templates
EMAIL_BUILD_HTML_DIR          # e.g., emails/build/html
EMAIL_BUILD_TXT_DIR           # e.g., emails/build/txt
MAIL_DKIM_DOMAIN, MAIL_DKIM_SELECTOR, MAIL_DKIM_KEY (optional)
ENV / ENVIRONMENT             # 'production'|'staging'|'development'|...
EMAIL_STRICT_LOCAL            # when set to '0' → allow sending in dev (compat)

Public API
----------
- send_email(to_email, subject, body)                              # sync text
- send_verification_email(email, token)                            # async
- send_password_reset_otp(email, otp)                              # async
- send_reactivation_email(to_email, token)                         # async
- send_export_email(user, session_id, logs, as_zip: bool = False)  # async
"""

import csv
import io
import logging
import os
import smtplib
import ssl
import zipfile
from email.message import EmailMessage
from pathlib import Path
from typing import Iterable, List, Optional, TypedDict
from urllib.parse import quote

from fastapi import HTTPException
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from jinja2 import Environment, FileSystemLoader, TemplateNotFound, select_autoescape

# Prefer centralized settings when available; gracefully fall back to env
try:  # pragma: no cover - import guard for early bootstrap stages
    from app.core.config import settings as _settings  # type: ignore
except Exception:  # pragma: no cover
    _settings = None


# ──────────────────────────────────────────────────────────────────────────────
# 🔧 Configuration & Globals
# ──────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)

ENV: str = (
    getattr(_settings, "ENVIRONMENT", None)
    or os.getenv("ENVIRONMENT")
    or os.getenv("ENV", "local")
).lower()

# SMTP baseline (for sync text/plain)
SMTP_HOST: Optional[str] = getattr(_settings, "SMTP_HOST", None) or os.getenv("SMTP_HOST")
SMTP_PORT: int = int(getattr(_settings, "SMTP_PORT", None) or os.getenv("SMTP_PORT", 587))
SMTP_USERNAME: Optional[str] = getattr(_settings, "SMTP_USERNAME", None) or os.getenv("SMTP_USERNAME")
SMTP_PASSWORD: Optional[str] = getattr(_settings, "SMTP_PASSWORD", None) or os.getenv("SMTP_PASSWORD")
EMAIL_FROM: str = getattr(_settings, "EMAIL_FROM", None) or os.getenv("EMAIL_FROM", "no-reply@careeros.com")
EMAIL_FROM_NAME: str = getattr(_settings, "EMAIL_FROM_NAME", None) or os.getenv("EMAIL_FROM_NAME", "Career OS")

# Base used to construct verification links (frontend or API)
_EMAIL_BASE = (
    getattr(_settings, "EMAIL_VERIFY_BASE_URL", None)
    or getattr(_settings, "FRONTEND_URL", None)              # nice fallback
    or os.getenv("EMAIL_VERIFY_BASE_URL", "http://localhost:8000")
)
EMAIL_VERIFY_BASE_URL: str = str(_EMAIL_BASE).rstrip("/")

# Template roots (both are optional; module works even if none exist)
EMAIL_TEMPLATE_DIR = Path(getattr(_settings, "EMAIL_TEMPLATE_DIR", "app/email/templates")).resolve()
EMAIL_BUILD_HTML_DIR = Path(getattr(_settings, "EMAIL_BUILD_HTML_DIR", "emails/build/html")).resolve()
EMAIL_BUILD_TXT_DIR = Path(getattr(_settings, "EMAIL_BUILD_TXT_DIR", "emails/build/txt")).resolve()

# For fastapi-mail template_name mode, it needs a single folder path
TEMPLATE_FOLDER: Optional[str] = str(EMAIL_TEMPLATE_DIR) if EMAIL_TEMPLATE_DIR.is_dir() else (
    str(EMAIL_BUILD_HTML_DIR) if EMAIL_BUILD_HTML_DIR.is_dir() else None
)
if TEMPLATE_FOLDER is None:
    logger.warning("No email template folders found (HTML templates may be skipped).")

# Optional DKIM (recommended in production to reduce spam classification)
MAIL_DKIM_DOMAIN = getattr(_settings, "MAIL_DKIM_DOMAIN", None) or os.getenv("MAIL_DKIM_DOMAIN")
MAIL_DKIM_SELECTOR = getattr(_settings, "MAIL_DKIM_SELECTOR", None) or os.getenv("MAIL_DKIM_SELECTOR")
MAIL_DKIM_KEY = getattr(_settings, "MAIL_DKIM_KEY", None) or os.getenv("MAIL_DKIM_KEY")  # PEM private key
MAIL_DKIM = bool(MAIL_DKIM_DOMAIN and MAIL_DKIM_SELECTOR and MAIL_DKIM_KEY)

# In local/test, log instead of sending (unless forced strict)
# NOTE: legacy compat — EMAIL_STRICT_LOCAL='0' means "allow sending"
EMAIL_STRICT_LOCAL = os.getenv("EMAIL_STRICT_LOCAL", "1") == "0"

# For SMTPS (implicit TLS) use port 465; otherwise use STARTTLS (587 default)
_USE_SSL = SMTP_PORT == 465

# Lazy singletons for FastAPI-Mail + Jinja2
_fastmail_conf: Optional[ConnectionConfig] = None
_fastmail: Optional[FastMail] = None
_jinja_env: Optional[Environment] = None


# ──────────────────────────────────────────────────────────────────────────────
# 🧰 Jinja environment (works for both classic Jinja and compiled MJML HTML)
# ──────────────────────────────────────────────────────────────────────────────

def _jinja() -> Environment:
    """
    Create a Jinja2 environment that can load templates from both:
    - EMAIL_TEMPLATE_DIR (classic fastapi-mail Jinja)
    - EMAIL_BUILD_HTML_DIR (compiled MJML HTML with {{ ... }} placeholders)
    """
    global _jinja_env
    if _jinja_env is not None:
        return _jinja_env

    search_paths: list[str] = []
    if EMAIL_TEMPLATE_DIR.is_dir():
        search_paths.append(str(EMAIL_TEMPLATE_DIR))
    if EMAIL_BUILD_HTML_DIR.is_dir():
        search_paths.append(str(EMAIL_BUILD_HTML_DIR))
    if not search_paths:
        # Jinja env still created to allow string rendering if needed
        search_paths.append(".")

    _jinja_env = Environment(
        loader=FileSystemLoader(search_paths),
        autoescape=select_autoescape(enabled_extensions=("html", "xml")),
    )
    return _jinja_env


# ──────────────────────────────────────────────────────────────────────────────
# 📮 FastAPI-Mail configuration (pydantic v1/v2 compatible)
# ──────────────────────────────────────────────────────────────────────────────

def _conn_config() -> ConnectionConfig:
    """
    Build and cache a FastAPI-Mail ConnectionConfig.

    - Works across fastapi-mail versions (Pydantic v1/v2).
    - Silently drops unsupported fields (e.g., DKIM) if the installed
      package doesn't expose those fields.
    """
    global _fastmail_conf
    if _fastmail_conf:
        return _fastmail_conf

    if not SMTP_HOST:
        logger.warning("SMTP_HOST is not set – emails will be logged (ENV=%s)", ENV)

    conf_kwargs = {
        "MAIL_USERNAME": SMTP_USERNAME or "",
        "MAIL_PASSWORD": SMTP_PASSWORD or "",
        "MAIL_FROM": EMAIL_FROM,
        "MAIL_PORT": SMTP_PORT,
        "MAIL_SERVER": SMTP_HOST or "localhost",
        "MAIL_FROM_NAME": EMAIL_FROM_NAME,
        "MAIL_STARTTLS": not _USE_SSL,
        "MAIL_SSL_TLS": _USE_SSL,
        "USE_CREDENTIALS": bool(SMTP_USERNAME and SMTP_PASSWORD),
        "TEMPLATE_FOLDER": TEMPLATE_FOLDER,  # optional
        # DKIM (optional; only if supported by the installed fastapi-mail)
        "MAIL_DKIM": MAIL_DKIM,
        "MAIL_DKIM_DOMAIN": MAIL_DKIM_DOMAIN or "",
        "MAIL_DKIM_SELECTOR": MAIL_DKIM_SELECTOR or "",
        "MAIL_DKIM_PRIVATE_KEY": MAIL_DKIM_KEY or "",
        # Prefer explicit logging toggles over SUPPRESS_SEND=True
        "SUPPRESS_SEND": False,
    }

    # Determine which keys the installed ConnectionConfig actually supports
    try:
        fields = getattr(ConnectionConfig, "model_fields", None)  # pydantic v2
        if isinstance(fields, dict):
            allowed = set(fields.keys())
        else:  # pydantic v1 fallback
            fields_v1 = getattr(ConnectionConfig, "__fields__", None)
            allowed = set(fields_v1.keys()) if isinstance(fields_v1, dict) else set()
    except Exception:  # extremely defensive
        allowed = set()

    if allowed:
        filtered = {k: v for k, v in conf_kwargs.items() if k in allowed}
        dropped = [k for k in conf_kwargs if k not in allowed]
        if dropped:
            logger.debug("FastMail.ConnectionConfig dropping unsupported keys: %s", ", ".join(dropped))
    else:
        # Could not introspect; pass all and let the library validate
        filtered = conf_kwargs

    _fastmail_conf = ConnectionConfig(**filtered)
    return _fastmail_conf


def _fastmail_client() -> FastMail:
    """Lazily instantiate and cache FastMail client."""
    global _fastmail
    if _fastmail is None:
        _fastmail = FastMail(_conn_config())
    return _fastmail


# ──────────────────────────────────────────────────────────────────────────────
# 🧭 Behavior toggles & utilities
# ──────────────────────────────────────────────────────────────────────────────

def _should_send_real_email() -> bool:
    """
    Determine whether to actually send out emails.

    Returns
    -------
    bool
        True when SMTP is configured **and** we're in a production-ish env
        (prod/staging), or when EMAIL_STRICT_LOCAL=1 (legacy compat: we treat
        EMAIL_STRICT_LOCAL='0' as "send in dev").
    """
    if not SMTP_HOST:
        return False
    if ENV in ("prod", "production", "staging"):
        return True
    return EMAIL_STRICT_LOCAL


def _mailto(to_email: str) -> str:
    """
    Minimal recipient validation for headers; upstream code should perform
    full validation. Raises ValueError if clearly malformed.
    """
    addr = (to_email or "").strip()
    if not addr or "@" not in addr:
        raise ValueError("Invalid recipient email")
    return addr


def _verification_link(token: str) -> str:
    """Construct the verification URL using the configured base URL."""
    return f"{EMAIL_VERIFY_BASE_URL}/api/v1/auth/verify-email?token={quote(token)}"


# ──────────────────────────────────────────────────────────────────────────────
# ✉️  SYNC SMTP: Simple text email
# ──────────────────────────────────────────────────────────────────────────────

def send_email(to_email: str, subject: str, body: str) -> None:
    """
    Send a **plain text** email via Python's `smtplib` (synchronous).

    Behavior
    --------
    - In local/test or when SMTP is missing, logs the message instead of sending.
    - In production, uses TLS (SMTPS 465 or STARTTLS 587) and authenticates
      when credentials are provided.

    Raises
    ------
    HTTPException(500)
        Only in strict/production mode if sending fails.
    """
    recipient = _mailto(to_email)
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = recipient
    msg.set_content(body or "")

    if not _should_send_real_email():
        logger.info("📨 [DRY-RUN] Email to=%s subject=%s\n%s", recipient, subject, body)
        return

    try:
        if _USE_SSL:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx, timeout=20) as server:
                if SMTP_USERNAME and SMTP_PASSWORD:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                if SMTP_USERNAME and SMTP_PASSWORD:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)

        logger.info("📨 Email sent to %s (subject=%s)", recipient, subject)
    except Exception:
        logger.exception("❌ SMTP send failed (to=%s subject=%s)", recipient, subject)
        raise HTTPException(status_code=500, detail="Email sending failed")


# ──────────────────────────────────────────────────────────────────────────────
# 📮  ASYNC: HTML/TXT via FastAPI-Mail (background-safe)
# ──────────────────────────────────────────────────────────────────────────────

class _AttachmentDict(TypedDict):
    file: bytes
    filename: str
    mime_type: str


async def _send_fastmail_plain(
    to_email: str,
    subject: str,
    body: str,
    *,
    attachments: Optional[List[_AttachmentDict]] = None,
) -> None:
    """
    Internal helper: send a **plain text** email via FastAPI-Mail (async).

    Falls back to logging in non-production or when SMTP is not configured.
    Never raises from background tasks.
    """
    recipient = _mailto(to_email)
    message = MessageSchema(
        subject=subject,
        recipients=[recipient],
        body=body or "",
        attachments=attachments or [],
        subtype=MessageType.plain,
    )

    if not _should_send_real_email():
        logger.info("📨 [DRY-RUN] (async) Email to=%s subject=%s\n%s", recipient, subject, body)
        return

    try:
        fm = _fastmail_client()
        await fm.send_message(message)
        logger.info("📨 (async) Email sent to %s (subject=%s)", recipient, subject)
    except Exception:
        logger.exception("❌ FastMail send failed (to=%s subject=%s) [non-fatal]", recipient, subject)
        return


async def _send_fastmail_html(
    to_email: str,
    subject: str,
    html: str,
    *,
    attachments: Optional[List[_AttachmentDict]] = None,
) -> None:
    """
    Internal helper: send a **rendered HTML string** via FastAPI-Mail (async).

    Use this when you render templates yourself (Jinja env here). Never raises
    from background tasks.
    """
    recipient = _mailto(to_email)
    message = MessageSchema(
        subject=subject,
        recipients=[recipient],
        body=html or "",
        attachments=attachments or [],
        subtype=MessageType.html,
    )

    if not _should_send_real_email():
        logger.info("📨 [DRY-RUN] (async-HTML) Email to=%s subject=%s\n[HTML body omitted]", recipient, subject)
        return

    try:
        fm = _fastmail_client()
        await fm.send_message(message)
        logger.info("📨 (async-HTML) Email sent to %s (subject=%s)", recipient, subject)
    except Exception:
        logger.exception("❌ FastMail HTML send failed (to=%s subject=%s) [non-fatal]", recipient, subject)
        return


def _render_html_template(template_name: str, context: dict) -> Optional[str]:
    """
    Try to render an HTML template from either EMAIL_TEMPLATE_DIR or
    EMAIL_BUILD_HTML_DIR. Returns None if not found or render fails.
    """
    try:
        tpl = _jinja().get_template(template_name)
        return tpl.render(**(context or {}))
    except TemplateNotFound:
        return None
    except Exception:
        logger.exception("Template render failed: %s", template_name)
        return None


def _render_text_template(template_name: str, context: dict) -> Optional[str]:
    """
    Try to render a TXT template from EMAIL_BUILD_TXT_DIR if present.
    Returns None on any failure.
    """
    txt_path = EMAIL_BUILD_TXT_DIR / template_name
    if not txt_path.exists():
        return None
    try:
        tpl = _jinja().from_string(txt_path.read_text(encoding="utf-8"))
        return tpl.render(**(context or {}))
    except Exception:
        logger.exception("TXT template render failed: %s", template_name)
        return None


# ──────────────────────────────────────────────────────────────────────────────
# 📫  Public async APIs for common account flows
# ──────────────────────────────────────────────────────────────────────────────

async def send_verification_email(email: str, token: str) -> None:
    """
    Send an **account verification** email that contains a signed token link.

    Steps
    -----
    1) Build a canonical verification link using `EMAIL_VERIFY_BASE_URL`.
    2) Prefer rich HTML (Jinja or compiled MJML); fallback to plaintext.
    """
    link = _verification_link(token)
    subject = "Verify your Career OS account"

    # Try HTML via our template engine first (works for both classic Jinja & compiled MJML)
    # Convention: compiled slug lives at emails/build/html/auth-verify.html
    template_name = "auth-verify.html"
    context = {
        "verification_link": link,
        "product_name": EMAIL_FROM_NAME,
        "expires_minutes": 15,  # keep in sync with ACCESS_TOKEN_EXPIRE_MINUTES if desired
    }

    html = _render_html_template(template_name, context)
    if html:
        await _send_fastmail_html(email, subject, html)
        return

    # Fallback: classic fastapi-mail template_name mode (if TEMPLATE_FOLDER configured)
    if TEMPLATE_FOLDER:
        try:
            fm = _fastmail_client()
            message = MessageSchema(
                subject=subject,
                recipients=[_mailto(email)],
                template_body=context,
                subtype=MessageType.html,
            )
            await fm.send_message(message, template_name=template_name)
            logger.info("📨 (async-template) Email sent to %s (subject=%s)", email, subject)
            return
        except Exception:
            logger.exception("❌ Verification email (fastapi-mail template) failed [non-fatal]")

    # Final fallback: plaintext
    body = f"Welcome to Career OS!\n\nClick the link to verify your account:\n{link}"
    await _send_fastmail_plain(email, subject, body)


async def send_password_reset_otp(email: str, otp: str) -> None:
    """
    Send a **one-time code (OTP)** for password reset (≈10 min validity).
    The body is intentionally plaintext for accessibility and parity with SMS.
    """
    subject = "Your CareerOS Account Verification Code"

    # Prefer compiled TXT if present, else simple plaintext
    txt = _render_text_template("auth-reset.txt", {"otp": otp, "expires_minutes": 10})
    body = txt or (
        f"Here is your one-time code: {otp}\n\n"
        "It expires in 10 minutes. If you didn't request this, you can ignore this email."
    )
    await _send_fastmail_plain(email, subject, body)


async def send_reactivation_email(to_email: str, token: str) -> None:
    """
    Send an **account reactivation** email for soft-deleted accounts.

    Failures are **non-fatal** by design (we log and continue the caller flow).
    """
    subject = "Reactivate your CareerOS account"

    # Try HTML template (optional)
    html = _render_html_template("account-reactivate.html", {"token": token})
    if html:
        await _send_fastmail_html(to_email, subject, html)
        return

    # Plaintext fallback
    body = (
        "Your account was scheduled for deletion. If this was you, you can reactivate it within 30 days.\n\n"
        f"Reactivation token: {token}\n"
        "If you did not request this, please contact support immediately."
    )
    await _send_fastmail_plain(to_email, subject, body)


class _AccessLogRow(TypedDict, total=False):
    """Minimal structure for log export rows (CSV)."""
    accessed_at: str
    user_id: str
    result: str
    ip_address: str
    user_agent: str
    reason: str
    fingerprint: str
    geo_location: str


async def send_export_email(
    user,
    session_id: str,
    logs: Iterable[_AccessLogRow],
    as_zip: bool = False,
) -> None:
    """
    Email an **access logs export** as CSV or ZIP attachment.

    Parameters
    ----------
    user : Any
        Object exposing `.email` and optionally `.full_name`/`.name`.
    session_id : str
        Identifier included in subject and filenames.
    logs : Iterable[_AccessLogRow]
        Rows with keys: [accessed_at, user_id, result, ip_address,
        user_agent, reason, fingerprint, geo_location]
    as_zip : bool, default False
        When True, compress the CSV into a ZIP before sending.
    """
    # 1) CSV into memory
    csv_buf = io.StringIO()
    writer = csv.writer(csv_buf)
    writer.writerow(["Timestamp", "User ID", "Result", "IP", "Agent", "Reason", "Fingerprint", "Geo"])
    for row in logs or []:
        writer.writerow([
            row.get("accessed_at", ""),
            row.get("user_id", ""),
            row.get("result", ""),
            row.get("ip_address", ""),
            row.get("user_agent", ""),
            row.get("reason", ""),
            row.get("fingerprint", ""),
            str(row.get("geo_location", "")),
        ])
    csv_buf.seek(0)

    # 2) Build attachments
    attachments: List[_AttachmentDict] = []
    if as_zip:
        zip_io = io.BytesIO()
        with zipfile.ZipFile(zip_io, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("access_logs.csv", csv_buf.read())
        zip_io.seek(0)
        attachments.append({
            "file": zip_io.read(),
            "filename": f"access_logs_{session_id}.zip",
            "mime_type": "application/zip",
        })
    else:
        attachments.append({
            "file": csv_buf.getvalue().encode("utf-8"),
            "filename": f"access_logs_{session_id}.csv",
            "mime_type": "text/csv",
        })

    # 3) Compose + send (plaintext body; attachments carry the data)
    subject = f"Access Logs Export — Session {session_id}"
    display = getattr(user, "full_name", None) or getattr(user, "name", None) or getattr(user, "email", "")
    body = (
        f"Hello {display},\n\n"
        f"Attached are the access logs for session {session_id}.\n\n"
        "Regards,\nCareer OS Team"
    )
    await _send_fastmail_plain(getattr(user, "email"), subject, body, attachments=attachments)


__all__ = [
    "send_email",
    "send_verification_email",
    "send_password_reset_otp",
    "send_reactivation_email",
    "send_export_email",
]
