from __future__ import annotations

"""
Admin guards and helpers (org-free)
-----------------------------------
Centralized helpers to avoid duplicating the same admin/MFA checks across
routers. Keep logic consistent and testable in one place.

Exports
- is_admin(user): best-effort admin role check across possible schemas
- ensure_admin(user): raise 403 if not admin
- ensure_mfa(request): raise if access token missing or not MFA-authenticated
- admin_user: FastAPI dependency returning the authenticated admin user
- admin_user_mfa: same as above, but enforces `mfa_authenticated` claim
"""

from typing import Optional, Any

from fastapi import Depends, HTTPException, Request, status

from app.core.jwt import decode_token, get_bearer_token
from app.core.security import get_current_user
from app.core.dependencies import get_current_user_with_mfa
from app.db.models.user import User


def is_admin(user: User) -> bool:
    """Return True if the user has an admin-level role.

    Supports multiple shapes to remain portable across schema variants.
    """
    try:
        # Prefer explicit role enums when available
        from app.schemas.enums import OrgRole  # imported lazily to avoid cycles

        return getattr(user, "role", None) in {OrgRole.ADMIN, OrgRole.SUPERUSER}
    except Exception:
        # Fallbacks commonly seen in simple schemas
        return bool(
            getattr(user, "is_admin", False)
            or getattr(user, "is_superuser", False)
            or ("admin" in (getattr(user, "roles", []) or []))
        )


async def ensure_admin(user: Any = Depends(get_current_user)) -> None:
    if not is_admin(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")


async def ensure_mfa(request: Request) -> None:
    """Require a valid access token with `mfa_authenticated=True`.

    Uses centralized JWT decoding; does not hit the DB.
    """
    token: Optional[str] = get_bearer_token(request)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing access token")

    try:
        claims = await decode_token(token, expected_types=["access"], verify_revocation=True)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    if not bool(claims.get("mfa_authenticated")):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MFA required")


# Dependencies returning the admin user (for use in endpoint signatures)
async def admin_user(current_user: User = Depends(get_current_user)) -> User:
    await ensure_admin(current_user)
    return current_user


async def admin_user_mfa(user: User = Depends(get_current_user_with_mfa)) -> User:
    await ensure_admin(user)
    return user


__all__ = [
    "is_admin",
    "ensure_admin",
    "ensure_mfa",
    "admin_user",
    "admin_user_mfa",
]
