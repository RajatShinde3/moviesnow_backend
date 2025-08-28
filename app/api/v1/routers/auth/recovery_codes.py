
"""
Enterprise-grade **MFA Recovery Codes** Router
=============================================

This module implements **production-ready** recovery codes for MFA fallback and
step‑up flows. Users can generate a one‑time **batch** of single‑use codes,
preview masked metadata, and **redeem** a code to satisfy MFA for sensitive
operations (step‑up) when TOTP is unavailable.

Endpoints
---------
- `POST /mfa/recovery-codes/generate` — (MFA‑gated) rotate and issue a new batch; return raw codes **once**
- `GET  /mfa/recovery-codes`          — masked preview of current batch + remaining count
- `POST /mfa/recovery-codes/redeem`   — consume one code and **mint a short‑lived reauth token**

Design goals
------------
- **Zero plaintext at rest**: only store SHA‑256 digests, never raw codes
- **Single-view**: raw codes are returned **only** at generation time
- **Rotation**: generating a new batch invalidates all previous codes
- **Org‑aware**: step‑up token includes active org context
- **Rate‑limited + anti‑bruteforce**: Redis counters (atomic INCR+EXPIRE via Lua)
- **Cache hardening**: responses are marked **no‑store**

Storage model (Redis)
---------------------
This implementation uses Redis for durability/speed. (You can later move it to
PostgreSQL using a `recovery_codes` table; the hashing/formatting stays the same.)

Per user keys:
- `recov:{user_id}:batch`  — Hash with metadata: `batch_id`, `created_at`, `preview_json`
- `recov:{user_id}:codes`  — **SET** of SHA‑256 digests (remaining, unused)
- `recov:{user_id}:used`   — **SET** of SHA‑256 digests (consumed)

Security
--------
- Codes are 10‑character, high‑entropy, upper‑alphanumeric, with hyphen grouping
- Digests are `sha256(f"{user_id}:{code}:{batch_id}:{pepper}")`
- Pepper comes from `settings.RECOVERY_CODE_PEPPER` (fallback: JWT secret)
- Redeem is rate‑limited and has anti‑bruteforce counters per user/IP

How to use
----------
1) Include this router in `register_routes.py`:

   ```py
   from . import recovery_codes
   router.include_router(recovery_codes.router, responses=common_responses)
   ```

2) In sensitive endpoints, require a fresh **reauth** token (from `/reauth/*` or
   from `/mfa/recovery-codes/redeem`) via a `require_step_up()` dependency.
"""


import json
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.redis_client import redis_wrapper
from app.core.limiter import rate_limit
from app.db.session import get_async_db
from app.core.dependencies import (
    get_current_user,
    get_current_user_with_mfa,
)
from app.security_headers import set_sensitive_cache
from app.db.models.user import User
from app.db.models.user_organization import UserOrganization
from app.schemas.auth import (
    RecoveryCodesGenerateResponse,
    RecoveryCodesPreview,
    RecoveryCodeRedeemRequest,
    RecoveryCodeRedeemResponse,
)
from app.utils.step_up import active_org_for_user, mint_reauth_token
from app.services.audit_log_service import log_audit_event

router = APIRouter()

# ──────────────────────────────────────────────────────────────
# Constants & helpers
# ──────────────────────────────────────────────────────────────
BATCH_SIZE = 10
CODE_LEN = 10               # raw characters before hyphenation
GROUP = 5                   # XXXXX-XXXXX layout
REDEEM_WINDOW_SECONDS = 900  # 15 minutes window for bruteforce counters
MAX_REDEEM_FAILS_USER = 10
MAX_REDEEM_FAILS_IP = 20
REAUTH_TTL_SECONDS = int(getattr(settings, "REAUTH_TOKEN_EXPIRE_MINUTES", 5)) * 60
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I

# Optional max age for a batch (0/None = never expire)
RECOVERY_CODES_MAX_AGE_DAYS = int(getattr(settings, "RECOVERY_CODES_MAX_AGE_DAYS", 0) or 0)


def _pepper() -> str:
    return getattr(settings, "RECOVERY_CODE_PEPPER", None) or settings.JWT_SECRET_KEY.get_secret_value()


def _k_batch(user_id: UUID) -> str:
    return f"recov:{user_id}:batch"


def _k_codes(user_id: UUID) -> str:
    return f"recov:{user_id}:codes"


def _k_used(user_id: UUID) -> str:
    return f"recov:{user_id}:used"


def _k_redeem_ip(ip: str) -> str:
    return f"recov:redeem:ip:{ip or 'unknown'}"


def _k_redeem_user(user_id: UUID) -> str:
    return f"recov:redeem:user:{user_id}"


# ──────────────────────────────────────────────────────────────
# 🧩 Small Lua snippets (atomic counter + TTL on first increment)
# ──────────────────────────────────────────────────────────────
INCR_EXPIRE_LUA = """
local v = redis.call('incr', KEYS[1])
if v == 1 then redis.call('expire', KEYS[1], ARGV[1]) end
return v
"""


async def _incr_with_ttl(key: str, ttl_seconds: int) -> int:
    """Atomically INCR and set TTL on first increment via Redis Lua."""
    try:
        return int(await redis_wrapper.client.eval(INCR_EXPIRE_LUA, keys=[key], args=[ttl_seconds]))
    except Exception:
        # Fallback: non-atomic but acceptable in practice
        v = await redis_wrapper.client.incr(key)
        if v == 1:
            await redis_wrapper.client.expire(key, ttl_seconds)
        return int(v)


# ──────────────────────────────────────────────────────────────
# Utilities (format, hash, generate, normalize)
# ──────────────────────────────────────────────────────────────

def _format_code(raw: str) -> str:
    return f"{raw[:GROUP]}-{raw[GROUP:GROUP*2]}" if len(raw) >= GROUP * 2 else raw


def _gen_code() -> str:
    return _format_code("".join(secrets.choice(ALPHABET) for _ in range(CODE_LEN)))


def _hash_code(user_id: UUID, code: str, batch_id: str) -> str:
    # Normalize to uppercase without hyphen before hashing
    normalized = code.replace("-", "").upper()
    h = hashlib.sha256()
    h.update(f"{user_id}:{normalized}:{batch_id}:{_pepper()}".encode("utf-8"))
    return h.hexdigest()


def _normalize_user_code(code: str) -> str:
    c = (code or "").replace(" ", "").replace("-", "").upper()
    if not c or any(ch not in ALPHABET for ch in c):
        # Keep error neutral; detailed format checks can leak patterns
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid recovery code format")
    return _format_code(c)  # return re-hyphenated for consistent hashing/view


# ──────────────────────────────────────────────────────────────
# 🧠 POST /mfa/recovery-codes/generate — rotate batch and return raw codes once
# ──────────────────────────────────────────────────────────────
@router.post(
    "/mfa/recovery-codes/generate",
    response_model=RecoveryCodesGenerateResponse,
    summary="Generate a new batch of MFA recovery codes (displayed once)",
)
@rate_limit("3/hour")
async def generate_recovery_codes(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user_with_mfa),
) -> RecoveryCodesGenerateResponse:
    """
    Generate **BATCH_SIZE** single‑use recovery codes. The **raw codes are
    returned only once** and will never be retrievable later. Generating a new
    batch **invalidates** any previously issued codes.

    Security
    --------
    - Requires an MFA‑authenticated user (`get_current_user_with_mfa`).
    - Stores only **SHA‑256 digests**; raw codes are not persisted.
    - Marks responses **no‑store** to avoid leaks.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Create batch + codes (ensure uniqueness) ────────────────────
    user_id = current_user.id
    batch_id = str(uuid4())
    created_at = datetime.now(timezone.utc)

    raw_set = set()
    while len(raw_set) < BATCH_SIZE:
        raw_set.add(_gen_code())
    raw_codes = list(raw_set)
    digests = [_hash_code(user_id, c, batch_id) for c in raw_codes]

    # Masked preview (last 2 chars shown)
    def _mask(c: str) -> str:
        flat = c.replace("-", "")
        return f"{'*' * (len(flat) - 2)}{flat[-2:]}"

    preview = [f"{m[:GROUP]}-{m[GROUP:]}" for m in map(_mask, raw_codes)]

    # ── [Step 2] Store in Redis atomically (rotate previous batch) ───────────
    r = redis_wrapper.client
    meta = {"batch_id": batch_id, "created_at": created_at.isoformat(), "preview_json": json.dumps(preview)}

    async def _sequential_write():
        await r.delete(_k_codes(user_id))
        await r.delete(_k_used(user_id))
        if digests:
            await r.sadd(_k_codes(user_id), *digests)
        await r.hset(_k_batch(user_id), mapping=meta)
        if RECOVERY_CODES_MAX_AGE_DAYS > 0:
            ttl = RECOVERY_CODES_MAX_AGE_DAYS * 86400
            await r.expire(_k_codes(user_id), ttl)
            await r.expire(_k_used(user_id), ttl)
            await r.expire(_k_batch(user_id), ttl)

    try:
        pipe = getattr(r, "pipeline", None)
        if callable(pipe):
            p = pipe()
            await p.delete(_k_codes(user_id))
            await p.delete(_k_used(user_id))
            if digests:
                await p.sadd(_k_codes(user_id), *digests)
            await p.hset(_k_batch(user_id), mapping=meta)
            if RECOVERY_CODES_MAX_AGE_DAYS > 0:
                ttl = RECOVERY_CODES_MAX_AGE_DAYS * 86400
                await p.expire(_k_codes(user_id), ttl)
                await p.expire(_k_used(user_id), ttl)
                await p.expire(_k_batch(user_id), ttl)
            await p.execute()
        else:
            await _sequential_write()
    except Exception:
        # Fallback path if pipeline isn't supported by the mock/driver
        await _sequential_write()

    # ── [Step 3] Audit & respond ─────────────────────────────────────────────
    await log_audit_event(db, action="MFA_RECOVERY_GENERATE", user=current_user, status="SUCCESS", request=request)

    return RecoveryCodesGenerateResponse(
        batch_id=batch_id,
        created_at=created_at,
        total=BATCH_SIZE,
        codes=raw_codes,
    )


# ──────────────────────────────────────────────────────────────
# 🔎 GET /mfa/recovery-codes — masked preview and remaining count
# ──────────────────────────────────────────────────────────────
@router.get(
    "/mfa/recovery-codes",
    response_model=RecoveryCodesPreview,
    summary="Get masked preview of current recovery codes and remaining count",
)
@rate_limit("30/minute")
async def list_recovery_codes(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> RecoveryCodesPreview:
    """
    Return the **masked** preview of the active batch and remaining code count.
    Raw codes are **never** returned here; users must download/store them at
    generation time.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Fetch metadata and counts ───────────────────────────────────
    r = redis_wrapper.client
    meta = await r.hgetall(_k_batch(current_user.id))
    created_at = None
    batch_id = None
    preview: List[str] = []
    if meta:
        batch_id = (meta.get(b"batch_id") or meta.get("batch_id"))
        created_raw = (meta.get(b"created_at") or meta.get("created_at"))
        preview_json = (meta.get(b"preview_json") or meta.get("preview_json"))
        if batch_id:
            batch_id = batch_id.decode() if isinstance(batch_id, (bytes, bytearray)) else str(batch_id)
        if created_raw:
            created_raw = created_raw.decode() if isinstance(created_raw, (bytes, bytearray)) else str(created_raw)
            try:
                created_at = datetime.fromisoformat(created_raw)
            except Exception:
                created_at = None
        if preview_json:
            preview_json = preview_json.decode() if isinstance(preview_json, (bytes, bytearray)) else str(preview_json)
            try:
                preview = json.loads(preview_json)
            except Exception:
                preview = []

    remaining = int(await r.scard(_k_codes(current_user.id)) or 0)

    # ── [Step 2] Audit (read) & respond ──────────────────────────────────────
    await log_audit_event(db, action="MFA_RECOVERY_VIEW", user=current_user, status="SUCCESS", request=request)
    return RecoveryCodesPreview(batch_id=batch_id, created_at=created_at, remaining=remaining, preview=preview)


# ──────────────────────────────────────────────────────────────
# ✅ POST /mfa/recovery-codes/redeem — consume one code and mint reauth token
# ──────────────────────────────────────────────────────────────
@router.post(
    "/mfa/recovery-codes/redeem",
    response_model=RecoveryCodeRedeemResponse,
    summary="Redeem a recovery code and receive a short‑lived reauth token",
)
@rate_limit("30/hour")
async def redeem_recovery_code(
    payload: RecoveryCodeRedeemRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> RecoveryCodeRedeemResponse:
    """
    Consume a valid recovery code as a **step‑up factor** and mint a short‑lived
    **reauth** token. This allows the user to proceed with sensitive operations
    even if TOTP is temporarily unavailable.

    Security
    --------
    - Rate‑limited with Redis **anti‑bruteforce** counters (per user & per IP)
    - Codes are single‑use; successful redemption removes them from the active set
    - Responses are **no‑store**
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Anti‑bruteforce budget check ────────────────────────────────
    ip = getattr(request.client, "host", None) or ""
    user_key = _k_redeem_user(current_user.id)
    ip_key = _k_redeem_ip(ip)
    user_tries = await _incr_with_ttl(user_key, REDEEM_WINDOW_SECONDS)
    ip_tries = await _incr_with_ttl(ip_key, REDEEM_WINDOW_SECONDS)
    if user_tries > MAX_REDEEM_FAILS_USER or ip_tries > MAX_REDEEM_FAILS_IP:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many attempts")

    # ── [Step 2] Resolve batch and hash input code ───────────────────────────
    r = redis_wrapper.client
    meta = await r.hget(_k_batch(current_user.id), "batch_id")
    if not meta:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No recovery codes available")
    batch_id = meta.decode() if isinstance(meta, (bytes, bytearray)) else str(meta)

    # Normalize (strip spaces/hyphens, enforce charset), then hash
    try:
        normalized_display = _normalize_user_code(payload.code)
    except HTTPException:
        # Still count towards the IP/user budget; propagate
        await log_audit_event(db, action="MFA_RECOVERY_REDEEM", user=current_user, status="FAILURE", request=request)
        raise

    digest = _hash_code(current_user.id, normalized_display, batch_id)

    # ── [Step 3] Verify membership and consume atomically ────────────────────
    # Use SREM to ensure single‑use; only when present we consider it a success.
    removed = await r.srem(_k_codes(current_user.id), digest)
    if removed != 1:
        await log_audit_event(db, action="MFA_RECOVERY_REDEEM", user=current_user, status="FAILURE", request=request)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid recovery code")

    await r.sadd(_k_used(current_user.id), digest)

    # Reset per‑user failure counter on success (keep IP counter for network‑level abuse)
    try:
        await redis_wrapper.client.delete(user_key)
    except Exception:
        pass

    # ── [Step 4] Mint a reauth token bound to this session ───────────────────
    # Extract caller access claims to preserve session lineage (best‑effort)
    authz = request.headers.get("authorization") or request.headers.get("Authorization")
    session_id = ""
    if authz and authz.lower().startswith("bearer "):
        try:
            from jose import jwt as _jwt
            claims = _jwt.decode(
                authz.split(" ", 1)[1].strip(),
                settings.JWT_SECRET_KEY.get_secret_value(),
                algorithms=[settings.JWT_ALGORITHM],
                options={"require": ["sub", "exp"]},
            )
            session_id = str(claims.get("session_id") or claims.get("jti") or "")
        except Exception:
            session_id = ""
    active_org = await active_org_for_user(db, current_user.id)
    reauth_token, ttl = mint_reauth_token(current_user.id, session_id=session_id, active_org=active_org, mfa_authenticated=True)

    # ── [Step 5] Audit & respond ─────────────────────────────────────────────
    await log_audit_event(db, action="MFA_RECOVERY_REDEEM", user=current_user, status="SUCCESS", request=request)

    return RecoveryCodeRedeemResponse(reauth_token=reauth_token, expires_in=ttl)


__all__ = [
    "router",
    "generate_recovery_codes",
    "list_recovery_codes",
    "redeem_recovery_code",
]
