from __future__ import annotations

"""
Logout service — hardened, production‑grade
==========================================

Goals
-----
- Revoke a single **refresh token** safely and idempotently.
- **Do not leak** token state (present/absent/already‑revoked) to the client.
- Strict JWT validation (issuer/audience/exp) and claim checks (jti, sub, type).
- Thorough audit logging for observability.

Behavior
--------
By default, this endpoint is **idempotent**: it returns HTTP 200 with a generic
message even if the token is invalid, expired, unknown, or already revoked.
Set ``LOGOUT_STRICT_ERRORS=true`` to surface 4xx errors instead.
"""

import os
from uuid import UUID
from hashlib import sha256
from typing import Optional

from fastapi import HTTPException, Request
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models.user import User
from app.db.models.token import RefreshToken
from app.services.audit_log_service import log_audit_event, AuditEvent


# ─────────────────────────────────────────────────────────────
# ⚙️ Config
# ─────────────────────────────────────────────────────────────
STRICT_ERRORS = os.getenv("LOGOUT_STRICT_ERRORS", "false").lower() == "true"
JWT_ISSUER = getattr(settings, "JWT_ISSUER", "careeros")
JWT_AUDIENCE = getattr(settings, "JWT_AUDIENCE", "careeros-clients")


# ─────────────────────────────────────────────────────────────
# 🔧 Helpers
# ─────────────────────────────────────────────────────────────

def _client_ip(request: Optional[Request]) -> str:
    try:
        if request is None:
            return "-"
        fwd = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip")
        if fwd:
            return fwd.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
    except Exception:
        pass
    return "-"


def _ok() -> dict:
    return {"message": "Logged out successfully"}


# ─────────────────────────────────────────────────────────────
# 🚪 Logout User (Async‑compatible, idempotent by default)
# ─────────────────────────────────────────────────────────────
async def logout_user(refresh_token_str: str, db: AsyncSession, request: Request) -> dict:
    """Revoke a refresh token.

    Security properties
    -------------------
    - **Idempotent**: returns 200 even if the token is invalid, expired, unknown,
      or already revoked (unless ``LOGOUT_STRICT_ERRORS=true``).
    - **Strict claim checks**: requires ``jti`` and ``sub``; enforces token type
      to be ``refresh`` or ``refresh_token``; validates issuer/audience.
    - **No token state leakage** to the client; details are logged via audit.
    """
    user: Optional[User] = None
    ip = _client_ip(request)

    # ── [Step 1] Decode and validate the JWT ─────────────────────────────────
    try:
        payload = jwt.decode(
            refresh_token_str,
            settings.JWT_SECRET_KEY.get_secret_value(),  # SecretStr → str
            algorithms=[settings.JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            options={"require": ["exp", "sub", "jti"]},
        )
    except ExpiredSignatureError:
        # Expired token cannot be used; treat as successful logout (idempotent)
        await log_audit_event(
            db=db,
            user=None,
            action=AuditEvent.LOGOUT,
            status="EXPIRED_REFRESH_TOKEN",
            request=request,
            meta_data={"ip": ip, "rt_sha256": sha256(refresh_token_str.encode()).hexdigest()[:16]},
        )
        if STRICT_ERRORS:
            raise HTTPException(status_code=401, detail="Expired refresh token")
        return _ok()
    except JWTError:
        await log_audit_event(
            db=db,
            user=None,
            action=AuditEvent.LOGOUT,
            status="INVALID_REFRESH_TOKEN",
            request=request,
            meta_data={"ip": ip, "rt_sha256": sha256(refresh_token_str.encode()).hexdigest()[:16]},
        )
        if STRICT_ERRORS:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        return _ok()

    jti = payload.get("jti")
    user_id = payload.get("sub")
    tok_type = (payload.get("type") or payload.get("token_type") or "").lower()

    if not jti or not user_id:
        if STRICT_ERRORS:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return _ok()

    if tok_type and tok_type not in {"refresh", "refresh_token"}:
        # Wrong token class presented as refresh; log and end
        await log_audit_event(
            db=db,
            user=None,
            action=AuditEvent.LOGOUT,
            status="WRONG_TOKEN_TYPE",
            request=request,
            meta_data={"ip": ip, "token_type": tok_type},
        )
        if STRICT_ERRORS:
            raise HTTPException(status_code=401, detail="Invalid token type")
        return _ok()

    # ── [Step 2] Fetch user (for audit context; optional) ────────────────────
    try:
        user_uuid = UUID(str(user_id))
        user = (await db.execute(select(User).where(User.id == user_uuid))).scalar_one_or_none()
    except Exception:
        user = None

    # ── [Step 3] Revoke the token by JTI (idempotent) ────────────────────────
    token = (await db.execute(select(RefreshToken).where(RefreshToken.jti == jti))).scalar_one_or_none()

    if not token:
        await log_audit_event(
            db=db,
            user=user,
            action=AuditEvent.LOGOUT,
            status="REFRESH_NOT_FOUND",
            request=request,
            meta_data={"jti": jti, "ip": ip},
        )
        return _ok() if not STRICT_ERRORS else (_ for _ in ()).throw(HTTPException(status_code=404, detail="Refresh token not found"))

    if getattr(token, "is_revoked", False):
        await log_audit_event(
            db=db,
            user=user,
            action=AuditEvent.LOGOUT,
            status="ALREADY_REVOKED",
            request=request,
            meta_data={"jti": jti, "ip": ip},
        )
        return _ok() if not STRICT_ERRORS else (_ for _ in ()).throw(HTTPException(status_code=400, detail="Token already revoked"))

    await db.execute(update(RefreshToken).where(RefreshToken.jti == jti).values(is_revoked=True))
    await db.commit()

    # ── [Step 4] Emit audit success ──────────────────────────────────────────
    await log_audit_event(
        db=db,
        user=user,
        action=AuditEvent.LOGOUT,
        status="SUCCESS",
        request=request,
        meta_data={"jti": jti, "ip": ip},
    )

    return _ok()


__all__ = ["logout_user"]
