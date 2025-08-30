# app/api/v1/auth/recovery_codes.py

"""
Enterprise‑grade **MFA Recovery Codes** Router — MoviesNow
=========================================================

Production‑ready recovery codes for MFA fallback and **step‑up** flows.
Users can generate a one‑time **batch** of single‑use codes, preview masked
metadata, and **redeem** a code to satisfy MFA for sensitive operations when
TOTP is unavailable.

MoviesNow variant
-----------------
- **Org‑free**: no tenant/org claims are minted or stored.
- **Session‑bound reauth**: redeeming a code mints a short‑lived **reauth** JWT
  (`token_type="reauth"`) tied to the caller's session.
- **Hardened**: `Cache‑Control: no-store`, per‑route rate limits, Redis
  brute‑force counters, and neutral error messages.

Endpoints
---------
- **POST** `/mfa/recovery-codes/generate` — (MFA‑gated) rotate and issue a new batch; return raw codes **once**
- **GET**  `/mfa/recovery-codes`          — masked preview of current batch + remaining count
- **POST** `/mfa/recovery-codes/redeem`   — consume one code and **mint a short‑lived reauth token**

Security & Design
-----------------
- **Zero plaintext at rest**: only SHA‑256 digests are stored; raw codes are never persisted.
- **Single‑view**: raw codes are returned **only** at generation time.
- **Rotation**: generating a new batch invalidates all previous codes.
- **Rate‑limited + anti‑bruteforce**: Redis counters (atomic `INCR+EXPIRE` via Lua) per user/IP.
- **Cache hardening**: responses are marked **no‑store**.

Storage model (Redis)
---------------------
Per user keys:
- `recov:{user_id}:batch`  — Hash with metadata: `batch_id`, `created_at`, `preview_json`
- `recov:{user_id}:codes`  — **SET** of SHA‑256 digests (remaining, unused)
- `recov:{user_id}:used`   — **SET** of SHA‑256 digests (consumed)

Integration notes
-----------------
- Protect high‑risk routes with a **fresh step‑up** dependency that accepts a
  `token_type="reauth"` JWT (e.g., `require_step_up()`).
- This router relies on Redis; if Redis is unavailable, anti‑abuse counters
  degrade **open** (do not block the user) to favor availability.
"""

import json
import secrets
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple, Dict
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from jose import jwt, JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.redis_client import redis_wrapper
from app.core.limiter import rate_limit
from app.db.session import get_async_db
from app.core.security import get_current_user
from app.core.dependencies import get_current_user_with_mfa
from app.security_headers import set_sensitive_cache
from app.db.models.user import User
from app.schemas.auth import (
    RecoveryCodesGenerateResponse,
    RecoveryCodesPreview,
    RecoveryCodeRedeemRequest,
    RecoveryCodeRedeemResponse,
)

logger = logging.getLogger("moviesnow.auth.recovery_codes")
router = APIRouter(tags=["MFA Recovery Codes"])  # grouped under MFA


# ──────────────────────────────────────────────────────────────────────────────
# ⚙️ Constants & helpers
# ──────────────────────────────────────────────────────────────────────────────
BATCH_SIZE = 10
CODE_LEN = 10                # raw characters before hyphenation
GROUP = 5                    # XXXXX-XXXXX layout
REDEEM_WINDOW_SECONDS = 900  # 15‑minute window for brute‑force counters
MAX_REDEEM_FAILS_USER = 10
MAX_REDEEM_FAILS_IP = 20
REAUTH_TTL_SECONDS = int(getattr(settings, "REAUTH_TOKEN_EXPIRE_MINUTES", 5)) * 60
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I

# Optional maximum age for a batch (0/None = never expire)
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


# ──────────────────────────────────────────────────────────────────────────────
# 🔐 Token helper (mint short‑lived **reauth** JWT)
# ──────────────────────────────────────────────────────────────────────────────

def _mint_reauth_token(*, user_id: UUID, session_id: Optional[str], mfa_authenticated: bool) -> Tuple[str, int]:
    """Create a signed **reauth** token with a short TTL.

    Claims
    ------
    - `sub`: user id
    - `token_type`: `"reauth"`
    - `mfa_authenticated`: whether the step‑up used MFA (true for recovery code)
    - `session_id`: session lineage (if known)
    - Standard JWT dates: `iat`, `nbf`, `exp`, plus `jti` for traceability

    Returns
    -------
    (token, ttl_seconds)
    """
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=REAUTH_TTL_SECONDS)

    payload: Dict[str, object] = {
        "sub": str(user_id),
        "token_type": "reauth",
        "mfa_authenticated": bool(mfa_authenticated),
        "iat": now,
        "nbf": now,
        "exp": exp,
        "jti": str(uuid4()),
    }
    if session_id:
        payload["session_id"] = str(session_id)
    iss = getattr(settings, "JWT_ISSUER", None)
    aud = getattr(settings, "JWT_AUDIENCE", None)
    if iss:
        payload["iss"] = iss
    if aud:
        payload["aud"] = aud

    token = jwt.encode(payload, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=settings.JWT_ALGORITHM)
    return token, REAUTH_TTL_SECONDS


# ──────────────────────────────────────────────────────────────────────────────
# 🧩 Small Lua snippet (atomic counter + TTL on first increment)
# ──────────────────────────────────────────────────────────────────────────────
INCR_EXPIRE_LUA = """
local v = redis.call('incr', KEYS[1])
if v == 1 then redis.call('expire', KEYS[1], ARGV[1]) end
return v
"""


async def _incr_with_ttl(key: str, ttl_seconds: int) -> int:
    """Atomically `INCR` and set TTL on first increment via Redis Lua.

    Falls back to non‑atomic behavior if scripting is unavailable.
    """
    r = getattr(redis_wrapper, "client", None)
    if r is None:
        return 1  # degrade open
    try:
        return int(await r.eval(INCR_EXPIRE_LUA, keys=[key], args=[ttl_seconds]))
    except Exception:
        try:
            v = await r.incr(key)
            if v == 1:
                await r.expire(key, ttl_seconds)
            return int(v)
        except Exception:
            return 1


# ──────────────────────────────────────────────────────────────────────────────
# Utilities (format, hash, generate, normalize)
# ──────────────────────────────────────────────────────────────────────────────

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
    return _format_code(c)  # return re‑hyphenated for consistent hashing/view


def _client_ip(request: Optional[Request]) -> str:
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


# ──────────────────────────────────────────────────────────────────────────────
# 🧠 POST /mfa/recovery-codes/generate — rotate batch and return raw codes once
# ──────────────────────────────────────────────────────────────────────────────
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
    """Generate **BATCH_SIZE** single‑use recovery codes.

    The **raw codes are returned only once** and will never be retrievable later.
    Generating a new batch **invalidates** any previously issued codes.

    Security
    --------
    - Requires an MFA‑authenticated user (`get_current_user_with_mfa`).
    - Stores only **SHA‑256 digests**; raw codes are not persisted.
    - Marks responses **no‑store** to avoid leaks.
    """
    # [Step 0] Cache hardening
    set_sensitive_cache(response)

    # [Step 1] Create batch + codes (ensure uniqueness)
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

    # [Step 2] Store in Redis atomically (rotate previous batch)
    r = getattr(redis_wrapper, "client", None)
    if r is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Recovery storage unavailable")

    meta = {"batch_id": batch_id, "created_at": created_at.isoformat(), "preview_json": json.dumps(preview)}

    async def _sequential_write() -> None:
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

    # [Step 3] Respond
    return RecoveryCodesGenerateResponse(
        batch_id=batch_id,
        created_at=created_at,
        total=BATCH_SIZE,
        codes=raw_codes,
    )


# ──────────────────────────────────────────────────────────────────────────────
# 🔎 GET /mfa/recovery-codes — masked preview and remaining count
# ──────────────────────────────────────────────────────────────────────────────
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
    """Return the **masked** preview of the active batch and remaining code count.

    Raw codes are **never** returned here; users must download/store them at
    generation time.
    """
    # [Step 0] Cache hardening
    set_sensitive_cache(response)

    r = getattr(redis_wrapper, "client", None)
    if r is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Recovery storage unavailable")

    # [Step 1] Fetch metadata and counts
    meta = await r.hgetall(_k_batch(current_user.id))
    created_at: Optional[datetime] = None
    batch_id: Optional[str] = None
    preview: List[str] = []
    if meta:
        batch_id_raw = meta.get(b"batch_id") or meta.get("batch_id")
        created_raw = meta.get(b"created_at") or meta.get("created_at")
        preview_json = meta.get(b"preview_json") or meta.get("preview_json")
        if batch_id_raw:
            batch_id = batch_id_raw.decode() if isinstance(batch_id_raw, (bytes, bytearray)) else str(batch_id_raw)
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

    remaining = 0
    try:
        remaining = int(await r.scard(_k_codes(current_user.id)) or 0)
    except Exception:
        remaining = 0

    # [Step 2] Respond
    return RecoveryCodesPreview(batch_id=batch_id, created_at=created_at, remaining=remaining, preview=preview)


# ──────────────────────────────────────────────────────────────────────────────
# ✅ POST /mfa/recovery-codes/redeem — consume one code and mint reauth token
# ──────────────────────────────────────────────────────────────────────────────
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
    """Consume a valid recovery code as a **step‑up factor** and mint a short‑lived
    **reauth** token.

    This allows the user to proceed with sensitive operations even if TOTP is
    temporarily unavailable.

    Security
    --------
    - Rate‑limited with Redis **anti‑bruteforce** counters (per user & per IP).
    - Codes are single‑use; successful redemption removes them from the active set.
    - Responses are **no‑store**.
    """
    # [Step 0] Cache hardening
    set_sensitive_cache(response)

    r = getattr(redis_wrapper, "client", None)
    if r is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Recovery storage unavailable")

    # [Step 1] Anti‑bruteforce budget check
    ip = _client_ip(request)
    user_key = _k_redeem_user(current_user.id)
    ip_key = _k_redeem_ip(ip)
    user_tries = await _incr_with_ttl(user_key, REDEEM_WINDOW_SECONDS)
    ip_tries = await _incr_with_ttl(ip_key, REDEEM_WINDOW_SECONDS)
    if user_tries > MAX_REDEEM_FAILS_USER or ip_tries > MAX_REDEEM_FAILS_IP:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many attempts")

    # [Step 2] Resolve batch and hash input code
    meta = await r.hget(_k_batch(current_user.id), "batch_id")
    if not meta:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No recovery codes available")
    batch_id = meta.decode() if isinstance(meta, (bytes, bytearray)) else str(meta)

    try:
        normalized_display = _normalize_user_code(payload.code)
    except HTTPException:
        # Count towards the budget; propagate
        raise

    digest = _hash_code(current_user.id, normalized_display, batch_id)

    # [Step 3] Verify membership and consume atomically
    removed = await r.srem(_k_codes(current_user.id), digest)
    if removed != 1:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid recovery code")
    try:
        await r.sadd(_k_used(current_user.id), digest)
    except Exception:
        pass

    # Reset per‑user failure counter on success (keep IP counter for network‑level abuse)
    try:
        await r.delete(user_key)
    except Exception:
        pass

    # [Step 4] Extract session_id from the current bearer (best‑effort)
    session_id: Optional[str] = None
    authz = request.headers.get("authorization") or request.headers.get("Authorization")
    if authz and authz.lower().startswith("bearer "):
        token = authz.split(" ", 1)[1].strip()
        try:
            claims = jwt.decode(
                token,
                settings.JWT_SECRET_KEY.get_secret_value(),
                algorithms=[settings.JWT_ALGORITHM],
                options={"require": ["sub", "exp"]},
            )
            # Accept any bearer type here; step‑up itself will be minted as reauth
            session_id = str(claims.get("session_id") or claims.get("jti") or "") or None
        except JWTError:
            session_id = None

    # [Step 5] Mint a **reauth** token bound to this session
    reauth_token, ttl = _mint_reauth_token(user_id=current_user.id, session_id=session_id, mfa_authenticated=True)

    # [Step 6] Respond
    return RecoveryCodeRedeemResponse(reauth_token=reauth_token, expires_in=ttl)


__all__ = [
    "router",
    "generate_recovery_codes",
    "list_recovery_codes",
    "redeem_recovery_code",
]
