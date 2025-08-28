# app/services/auth/resend_service.py
"""
Resend verification service — hardened, production‑grade (compat shim)
=====================================================================

This module is a **thin, stable wrapper** around the canonical implementation in
`app.services.auth.email_verification_service`. It also exposes a public
`send_verification_email` symbol for **backward‑compatibility with tests and
legacy imports** that monkey‑patch this module path.

Why this shim exists
--------------------
- Keeps legacy import path (`app.services.auth.resend_service`) working.
- Reuses the hardened resend flow: neutral responses (no account enumeration),
  Redis rate‑limits, peppered HMAC digests at rest, and non‑blocking audit/email.
- Provides `send_verification_email(...)` here so test fixtures that patch
  this symbol don’t raise `AttributeError` during setup.

Public API
----------
- `resend_verification_email(email, db, request=None, background_tasks=None)`
  → delegates to the canonical implementation.
- `send_verification_email(email, token)` → forwards to
  `app.utils.email_utils.send_verification_email` and gracefully supports both
  sync and async implementations (and async test doubles).
"""
from __future__ import annotations

from typing import Optional, Any
import inspect

from fastapi import BackgroundTasks, Request
from sqlalchemy.ext.asyncio import AsyncSession

# Canonical (hardened) implementation re‑used here
from app.services.auth.email_verification_service import (
    resend_verification_email as _resend_impl,
)
# Real email sender used by production code; we forward to this
from app.utils.email_utils import (
    send_verification_email as _send_verification_email_real,
)


async def _maybe_await(result: Any) -> None:
    """Await *result* if it is awaitable; otherwise do nothing.

    This allows compatibility whether the underlying sender (or a test double)
    is sync or async.
    """
    if inspect.isawaitable(result):
        await result  # type: ignore[misc]


# ─────────────────────────────────────────────────────────────
# 📧 Public shim: expose `send_verification_email` for monkey‑patching
# ─────────────────────────────────────────────────────────────
async def send_verification_email(email: str, token: str) -> None:
    """Send a verification email (compat wrapper).

    Forwards to `app.utils.email_utils.send_verification_email`. Implemented as
    `async def` so it plays nicely with async test fixtures that patch this
    symbol. If the real implementation is synchronous, this wrapper handles it
    transparently.
    """
    await _maybe_await(_send_verification_email_real(email=email, token=token))


# ─────────────────────────────────────────────────────────────
# 🔁 Resend Email Verification (compat wrapper)
# ─────────────────────────────────────────────────────────────
async def resend_verification_email(
    email: str,
    db: AsyncSession,
    request: Optional[Request] = None,
    background_tasks: Optional[BackgroundTasks] = None,
) -> dict:
    """Resend a verification link if the account isn’t verified.

    Delegates to the canonical hardened implementation in
    `email_verification_service` to ensure a single source of truth.

    Parameters
    ----------
    email:
        User's email address (will be normalized downstream).
    db:
        Async SQLAlchemy session.
    request:
        Optional FastAPI request used for audit context and rate limiting.
    background_tasks:
        Optional `BackgroundTasks` to queue email and audit logging.

    Returns
    -------
    dict
        Generic confirmation message (no account enumeration). If the email is
        already verified, the canonical implementation returns a specific
        message stating that fact (safe to disclose).
    """
    return await _resend_impl(
        email=email, db=db, request=request, background_tasks=background_tasks
    )


__all__ = [
    "resend_verification_email",
    "send_verification_email",
]
