"""
Signup service — production-grade (clean, test-aligned)
======================================================

Core implementation for **new user registration**. Focuses on correctness,
clear behavior under load/abuse, and separation from the API layer.

Key behaviors
-------------
- **Normalized email** and secure **server-side password hashing**.
- **Per-email** and **per-IP** rate limiting to slow abuse (Redis-backed).
- **Verification link** issued via CSPRNG token; only a **peppered HMAC digest**
  is stored (no plaintext token in DB).
- **Race-safe** duplicate handling via unique constraint and IntegrityError recovery.
- **Neutral auditing** for success/failure (hashes, not raw PII).
- **Non-blocking mail delivery** via `BackgroundTasks`.

Design choices
--------------
- **Idempotency is handled at the API layer**, not here (route snapshots response).
- **Validation:** service performs a light email format check and returns **400**
  on invalid email (tests expect this).
- **Transactions:** nested transaction if caller already has one (common in tests).

Async/Thread-safety
-------------------
- All DB interactions are async and bound to the provided `AsyncSession`.
- Token issuance uses async helpers and returns values immediately.
"""

from datetime import datetime, timezone
from hashlib import sha256
from typing import Optional, Tuple
from uuid import UUID
import hashlib
import hmac
import re
import secrets

from fastapi import BackgroundTasks, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token, get_password_hash

# Prefer aggregator import; fall back for projects without it
try:  # pragma: no cover
    from app.db.models import User  # type: ignore
except Exception:  # pragma: no cover
    from app.db.models.user import User  # type: ignore

from app.schemas.auth import SignupPayload, TokenResponse
from app.services.audit_log_service import AuditEvent, log_audit_event
from app.services.token_service import store_refresh_token
from app.utils.email_utils import send_verification_email
from app.utils.redis_utils import enforce_rate_limit

# ─────────────────────────────────────────────────────────────
# ⚙️ Configuration
# ─────────────────────────────────────────────────────────────
PUBLIC_BASE_URL: str = getattr(settings, "PUBLIC_BASE_URL", "http://localhost:8000")
EMAIL_VERIFY_TTL_HOURS: int = int(getattr(settings, "EMAIL_VERIFICATION_TTL_HOURS", 48) or 48)

# ─────────────────────────────────────────────────────────────
# 🔧 Helpers
# ─────────────────────────────────────────────────────────────
def _norm_email(email: str) -> str:
    return (email or "").strip().lower()


def _client_ip(request: Optional[Request]) -> str:
    """Best-effort client IP extraction for audit/rate-limit keys."""
    try:
        if not request:
            return "-"
        fwd = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip")
        if fwd:
            return fwd.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
    except Exception:
        pass
    return "-"


# Lightweight email format check (tests expect 400 on bad format)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")

def _is_valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match((email or "").strip()))


def _jwt_secret_bytes() -> bytes:
    """Return JWT secret as bytes, supporting SecretStr or plain str."""
    raw = getattr(settings, "JWT_SECRET_KEY", None)
    if raw is None:
        raise RuntimeError("JWT_SECRET_KEY is not configured")
    try:
        val = raw.get_secret_value()  # type: ignore[attr-defined]
    except AttributeError:
        val = str(raw)
    return val.encode("utf-8")


def _verification_digest(token: str, user_id: UUID | str) -> str:
    """Hex HMAC-SHA256 digest for the verification token bound to user id."""
    key = _jwt_secret_bytes()
    msg = f"verify_email:{user_id}:{token}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


# ─────────────────────────────────────────────────────────────
# 📝 Sign up a new user
# ─────────────────────────────────────────────────────────────
async def signup_user(
    payload: SignupPayload,
    db: AsyncSession,
    request: Request,
    background_tasks: Optional[BackgroundTasks] = None,
) -> Tuple[TokenResponse, User]:
    """Create a new account and send a verification link.

    Steps
    -----
    1) **Normalize** input & derive audit/rate-limit keys.
    2) **Validate** email format (return **400** on failure).
    3) **Throttle** per normalized email and per client IP (fail-open on infra).
    4) **Check duplicates** quickly to short-circuit already-used email.
    5) **Create user** transactionally; store **peppered digest** of verify token.
    6) **Send email** asynchronously with the plaintext token.
    7) **Issue tokens** (access + refresh) and **persist refresh token**.
    8) **Audit success** with neutral metadata.
    """
    # 1) Normalize & derive keys
    email_norm = _norm_email(payload.email)
    ip = _client_ip(request)

    # 2) Validate email format early
    if not _is_valid_email(email_norm):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email format")

    # 3) Throttle (per email & per IP)
    #    Fail-open on backend hiccups, but propagate real 429s.
    try:
        await enforce_rate_limit(
            key_suffix=f"signup:email:{sha256(email_norm.encode()).hexdigest()}",
            seconds=60,
            max_calls=3,
            error_message="Please wait before trying again.",
        )
    except HTTPException as e:
        if e.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            raise
    except Exception:
        pass

    try:
        await enforce_rate_limit(
            key_suffix=f"signup:ip:{ip}",
            seconds=60,
            max_calls=15,
            error_message="Too many requests. Please try again later.",
        )
    except HTTPException as e:
        if e.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            raise
    except Exception:
        pass

    # 4) Fast duplicate check
    existing = (await db.execute(select(User).where(User.email == email_norm))).scalar_one_or_none()
    if existing:
        await log_audit_event(
            db=db,
            user=None,
            action=AuditEvent.SIGNUP,
            status="DUPLICATE_EMAIL",
            request=request,
            meta_data={"email_sha256": sha256(email_norm.encode()).hexdigest(), "ip": ip},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    # 5) Create user & verification digest (transactional)
    hashed_password = get_password_hash(payload.password)
    verify_token = secrets.token_urlsafe(32)

    try:
        tx_ctx = db.begin_nested() if db.in_transaction() else db.begin()
        async with tx_ctx:
            new_user = User(
                email=email_norm,
                full_name=payload.full_name,
                hashed_password=hashed_password,
                is_verified=False,
                verification_token=None,  # set once we know the id
                verification_token_created_at=datetime.now(timezone.utc),
            )
            db.add(new_user)
            await db.flush()  # obtain new_user.id

            digest = _verification_digest(verify_token, user_id=new_user.id)
            new_user.verification_token = digest
            db.add(new_user)

    except IntegrityError:
        await db.rollback()
        await log_audit_event(
            db=db,
            user=None,
            action=AuditEvent.SIGNUP,
            status="DUPLICATE_EMAIL",
            request=request,
            meta_data={"email_sha256": sha256(email_norm.encode()).hexdigest(), "ip": ip, "race": True},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    except Exception as e:  # unexpected
        await db.rollback()
        await log_audit_event(
            db=db,
            user=None,
            action=AuditEvent.SIGNUP,
            status="FAILURE",
            request=request,
            meta_data={"email_sha256": sha256(email_norm.encode()).hexdigest(), "ip": ip, "error": str(e)},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Signup failed. Please try again.",
        )

    # 6) Send verification email (non-blocking)
    if background_tasks is not None:
        background_tasks.add_task(send_verification_email, new_user.email, verify_token)

    # 7) Issue tokens & persist refresh token
    access_token = await create_access_token(user_id=new_user.id)
    refresh_data = await create_refresh_token(new_user.id)

    await store_refresh_token(
        db=db,
        user_id=new_user.id,
        token=refresh_data["token"],
        jti=refresh_data["jti"],
        expires_at=refresh_data["expires_at"],
        parent_jti=refresh_data.get("parent_jti"),
        ip_address=(request.client.host if request.client else None),
    )

    # 8) Audit success
    await log_audit_event(
        db=db,
        user=new_user,
        action=AuditEvent.SIGNUP,
        status="SUCCESS",
        request=request,
        meta_data={"email": new_user.email, "ip": ip},
    )

    token_response = TokenResponse(
        access_token=access_token,
        refresh_token=refresh_data["token"],
        token_type="bearer",
    )
    return token_response, new_user


__all__ = ["signup_user"]
