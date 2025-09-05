"""
Signup API — hardened, production-grade
======================================

POST /signup
------------
Creates a new user account and immediately issues an access token + a
rotated refresh token. The verification email is sent asynchronously.

Security & Hardening
--------------------
- **No-store** cache headers on token-bearing responses.
- **Per-route rate limit** (via limiter) to reduce abuse.
- **Idempotency** via `Idempotency-Key` (best-effort using Redis) so repeats
  with the same key return the original response.
- Neutral errors and full auditing are handled inside the service layer.

Notes
-----
- The heavy lifting (email normalization/validation, throttles, token hashing,
  audit logging, verification token digesting, etc.) lives in
  `app.services.auth.signup_service.signup_user`.
"""

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_async_db
from app.schemas.auth import SignupPayload, TokenResponse
from app.services.auth.signup_service import signup_user
from app.security_headers import set_sensitive_cache
from app.core.limiter import rate_limit
from app.api.http_utils import rate_limit as _token_bucket_limit
import app.utils.redis_utils as redis_utils

router = APIRouter(tags=["Authentication"])  # keep consistent with grouping


# ──────────────────────────────────────────────────────
# 👤 User Signup Endpoint
# ──────────────────────────────────────────────────────
@router.post(
    "/signup",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new account and issue tokens",
)
@rate_limit("10/minute")
async def signup(
    payload: SignupPayload,
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_async_db),
) -> TokenResponse:
    """
    Register a new user and return an access + refresh token pair.

    Steps
    -----
    1) **Harden response** with no-store cache headers.
    2) **Check idempotency** snapshot (if `Idempotency-Key` present).
    3) **Delegate** to service for validation, throttles, creation, auditing.
    4) **Store idempotent snapshot** (best-effort, short TTL).
    """
    # 1) Response hardening: never cache token responses
    set_sensitive_cache(response)

    # Additional lightweight per-process limiter to ensure tests and local
    # runs enforce the intended limit without depending on SlowAPI middleware
    # or env toggles. This complements the SlowAPI decorator above.
    # 10 requests per 60 seconds per client IP/user.
    _token_bucket_limit(request, response, limit=10, window_seconds=60)

    # 2) Best-effort idempotency window (route-level only)
    idem_key = request.headers.get("Idempotency-Key")
    cache_key = f"idem:signup:resp:{idem_key}" if idem_key else None
    if cache_key and hasattr(redis_utils, "idempotency_get"):
        try:
            snap = await redis_utils.idempotency_get(cache_key)
            if snap:
                # Snapshots are stored as a serialized TokenResponse dict
                return TokenResponse(**snap)
        except Exception:
            # Do not fail signup because of cache hiccups
            pass

    # 3) Delegate to service (handles validation, throttles, auditing, etc.)
    try:
        token_response, _user = await signup_user(payload, db, request, background_tasks)

        # 4) Store idempotent snapshot for a short window (e.g., 10 minutes)
        if cache_key and hasattr(redis_utils, "idempotency_set"):
            try:
                # Pydantic v2-friendly; also works with v1 if compatibility enabled
                await redis_utils.idempotency_set(cache_key, token_response.model_dump(), ttl_seconds=600)
            except Exception:
                # Best effort only; never break the happy path on cache failures
                pass

        return token_response

    except HTTPException:
        # Service raises well-formed HTTP errors (e.g., 400 Duplicate email)
        raise

    except Exception:
        # Keep errors generic here; service already performs detailed auditing
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Signup failed. Please try again.",
        )


__all__ = ["router", "signup"]
