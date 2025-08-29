# app/core/dependencies.py
from __future__ import annotations

"""
Production‑grade request dependencies — MoviesNow (org‑free)
===========================================================

Auth dependencies with defensive checks, clear errors, and consistent typing.
This MoviesNow variant **removes all organization/tenant context**, reusing the
centralized security/JWT helpers to avoid duplication and drift.

Highlights
----------
- Delegates **Bearer parsing** and **JWT decoding** to `app.core.jwt` helpers.
- Rich docstrings and step comments for maintainability.
- Consistent UUID parsing with actionable error messages.
- Minimal surface area: only user‑centric dependencies; no org models or claims.

Duplication Policy
------------------
Token decoding and Bearer parsing live in `app.core.jwt`. This module only
*uses* them — never re‑implements them.
"""

from typing import Optional, Union, Tuple
from uuid import UUID
import logging

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.jwt import decode_token, get_bearer_token  # centralized helpers
from app.db.session import get_async_db
from app.db.models.user import User
from app.schemas.auth import TokenPayload
from app.core.security import get_current_user  # exported elsewhere; reused by routes

logger = logging.getLogger(__name__)

__all__ = [
    "parse_uuid",
    "get_bearer_token_from_request",
    "get_current_user_with_mfa",
    "get_current_user_with_token_payload",
    "get_current_user_with_mfa_enforced",
    "get_current_user_allow_inactive",
]


# ──────────────────────────────────────────────────────────────
# 🔧 Utility: UUID parsing with clear error mapping
# ──────────────────────────────────────────────────────────────
def parse_uuid(value: Union[str, UUID], field_name: str) -> UUID:
    """Parse a UUID from string and raise **401 Unauthorized** if invalid.

    Parameters
    ----------
    value : str | UUID
        The candidate value to coerce into a UUID.
    field_name : str
        Human‑readable field name used in the error message.

    Returns
    -------
    UUID
        Parsed UUID.

    Raises
    ------
    HTTPException
        401 if the value cannot be parsed into a UUID.
    """
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid {field_name} in token",
        )


# ──────────────────────────────────────────────────────────────
# 🔐 Utility: Bearer token extraction (delegates to app.core.jwt)
# ──────────────────────────────────────────────────────────────
def get_bearer_token_from_request(request: Request) -> str:
    """Compatibility wrapper that delegates to `app.core.jwt.get_bearer_token`.

    Keeps the public function name stable across the codebase while avoiding
    logic duplication.
    """
    return get_bearer_token(request)


# ──────────────────────────────────────────────────────────────
# 👥 Dependency: get_current_user_with_mfa
# Enforce MFA and return the active user (org‑free)
# ──────────────────────────────────────────────────────────────
async def get_current_user_with_mfa(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> User:
    """Authenticate user via JWT and enforce `mfa_authenticated == True`.

    Steps
    -----
    1) Extract & decode token (centralized helper)
    2) Enforce `mfa_authenticated` claim
    3) Load and validate user (exists **and** active)

    Returns
    -------
    User
        The authenticated and active user ORM object.
    """
    # [Step 1] Decode token
    token = get_bearer_token_from_request(request)
    payload = await decode_token(token)

    # [Step 2] Enforce MFA flag
    if not bool(payload.get("mfa_authenticated")):
        logger.warning(
            "[MFA] Token missing 'mfa_authenticated'",
            extra={"request_id": getattr(request.state, "request_id", None)},
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MFA authentication required")

    # [Step 3] Resolve and validate user
    user_id = payload.get("sub") or payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing user_id in token")

    user_uuid = parse_uuid(user_id, "user_id")
    result = await db.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if not getattr(user, "is_active", True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")

    logger.debug(
        "[MFA] Authenticated user",
        extra={"user_id": str(user.id), "request_id": getattr(request.state, "request_id", None)},
    )
    return user


# ──────────────────────────────────────────────────────────────
# 🔎 Dependency: get_current_user_with_token_payload
# Return the authenticated user + decoded token payload
# ──────────────────────────────────────────────────────────────
async def get_current_user_with_token_payload(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> Tuple[User, TokenPayload]:
    """Return the authenticated `User` and the parsed `TokenPayload` model.

    Steps
    -----
    1) Extract & decode token (centralized helper)
    2) Validate user exists and is active
    3) Wrap payload into `TokenPayload`
    """
    # [Step 1] Extract & decode
    token = get_bearer_token_from_request(request)
    payload_dict = await decode_token(token)

    # [Step 2] Load user
    user_id = payload_dict.get("sub") or payload_dict.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing user_id in token")

    stmt = select(User).where(User.id == parse_uuid(user_id, "user_id"))
    res = await db.execute(stmt)
    user = res.scalar_one_or_none()

    if not user or not getattr(user, "is_active", True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive or unknown user")

    # [Step 3] Return user + typed payload
    return user, TokenPayload(**payload_dict)


# ──────────────────────────────────────────────────────────────
# 👥 Dependency: get_current_user_with_mfa_enforced (alias)
# ──────────────────────────────────────────────────────────────
async def get_current_user_with_mfa_enforced(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> User:
    """Alias of `get_current_user_with_mfa` kept for explicit naming in routes."""
    return await get_current_user_with_mfa(request, db)


# ──────────────────────────────────────────────────────────────
# 👤 Dependency: get_current_user_allow_inactive
# Authenticate user but do **not** enforce `is_active`
# ──────────────────────────────────────────────────────────────
async def get_current_user_allow_inactive(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> User:
    """Return the authenticated user from the Bearer access token **without**
    enforcing `is_active`.

    Useful for flows that must respond gracefully when an account has already
    been deactivated (e.g., showing a final state or instructions).

    Raises
    ------
    HTTPException
        401: missing/invalid token
        403: user not found
    """
    token = get_bearer_token_from_request(request)
    payload = await decode_token(token)

    sub = payload.get("sub") or payload.get("user_id")
    if not sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    user = (
        await db.execute(select(User).where(User.id == parse_uuid(sub, "user_id")))
    ).scalar_one_or_none()

    if not user:
        # Keep message consistent with other dependencies
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive or missing user")

    return user
