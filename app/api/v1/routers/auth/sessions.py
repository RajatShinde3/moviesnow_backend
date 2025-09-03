# app/api/v1/auth/sessions.py

"""
MoviesNow — Session Inventory & Revocation Router (prod-ready)
=============================================================

Purpose
-------
Expose **self-service session management** for end users:

- GET    /sessions            — list active sessions (refresh handles) for current user
- DELETE /sessions/{jti}      — revoke a specific session (device sign-out)
- DELETE /sessions            — revoke **all** sessions (global sign-out)
- DELETE /sessions/others     — revoke all sessions **except current** (best-effort)

Design Highlights
-----------------
- **Authoritative**: Redis set `session:{user_id}` intersected with DB `RefreshToken`
- **Privacy-safe**: never returns raw tokens; replies with metadata (IP/UA/timestamps)
- **No-store**: responses hardened with `Cache-Control: no-store`
- **Rate-limited**: per-route limits (user/IP keying; see `app.core.limiter`)
- **Current session detection**:
  1) Prefer `sessionmeta:{jti}.session_id` vs access token claim `session_id`
  2) Fallback: if no metadata but JTI equals access bearer’s `session_id` **or** `jti`,
     treat as **current**
- **Idempotent** destructive ops; **reuse sentinel** `revoked:jti:{jti}` set in Redis
- **Resilient**: DB/Redis best-effort, failures don’t leak cross-account data
- **Audit**: structured events recorded via `log_audit_event(...)`

Integration Notes
-----------------
When you mint/rotate refresh tokens, also write metadata:

    HSET sessionmeta:{jti} session_id <sid> ip <ip> ua <ua> created_at <iso> last_seen <iso>
    EXPIRE sessionmeta:{jti} <seconds_until_refresh_expiry>
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.limiter import rate_limit
from app.core.redis_client import redis_wrapper
from app.core.security import get_current_user
from app.db.models.token import RefreshToken
from app.db.models.user import User
from app.db.session import get_async_db
from app.schemas.auth import RevokeResult, SessionItem, SessionsListResponse
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import AuditEvent, log_audit_event

router = APIRouter()

# ──────────────────────────────────────────────────────────────
# 🔑 Redis key builders
# ──────────────────────────────────────────────────────────────
SESSION_KEY = lambda user_id: f"session:{user_id}"      # Set of refresh JTIs for a user
SESSION_META_KEY = lambda jti: f"sessionmeta:{jti}"     # Hash: session_id, ip, ua, created_at, last_seen
REVOKED_KEY = lambda jti: f"revoked:jti:{jti}"          # String sentinel (TTL = time left until expiry)

# ──────────────────────────────────────────────────────────────
# 🧩 Small helpers
# ──────────────────────────────────────────────────────────────
def _b2s(v):
    return v.decode() if isinstance(v, (bytes, bytearray)) else v


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _as_str_or_none(value) -> Optional[str]:
    """
    Normalize possibly typed IP/UA fields (IPv4Address / IPv6Address / bytes / str) to plain str.
    Returns None when not representable (keeps Pydantic happy).
    """
    if value is None:
        return None
    try:
        return str(_b2s(value))
    except Exception:
        return None


async def _decode_access_claims(request: Request) -> Dict:
    """
    Decode the Authorization bearer and return claims.

    Security
    --------
    - Requires `sub` and `exp` claims.
    - Uses HS* per settings (no audience or issuer checks here; add if you enforce them upstream).

    Raises
    ------
    HTTPException(401) for missing/invalid token.
    """
    authz = request.headers.get("authorization") or request.headers.get("Authorization")
    if not authz or not authz.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")
    token = authz.split(" ", 1)[1].strip()
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["sub", "exp"]},
        )
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


async def _read_session_meta(jti: str) -> Dict:
    """
    Read optional Redis metadata for a JTI; normalize time fields and return {} when absent.

    Keys
    ----
    - session_id, ip, ua, created_at, last_seen
    """
    r = redis_wrapper.client
    try:
        meta = await r.hgetall(SESSION_META_KEY(jti))
    except Exception:
        meta = None
    if not meta:
        return {}
    out = {(_b2s(k) if isinstance(k, (bytes, bytearray)) else k): _b2s(v) for k, v in meta.items()}
    for ts_key in ("created_at", "last_seen"):
        if out.get(ts_key):
            try:
                out[ts_key] = datetime.fromisoformat(out[ts_key])
            except Exception:
                out[ts_key] = None
    return out


async def _list_active_jtis(user_id: UUID) -> List[str]:
    """Read the Redis set of active JTIs for a user (best-effort, not authoritative)."""
    r = redis_wrapper.client
    try:
        members = await r.smembers(SESSION_KEY(user_id))
    except Exception:
        members = set()
    return sorted({_b2s(m) for m in (members or set())})


async def _delete_sessionmeta_safe(jti: str) -> None:
    """Best-effort removal of per-JTI metadata on revocation (never raises)."""
    try:
        await redis_wrapper.client.delete(SESSION_META_KEY(jti))
    except Exception:
        pass


async def _set_reuse_sentinel(jti: str, ttl_seconds: int) -> None:
    """Write a reuse-detection sentinel with a sane TTL floor (never raises)."""
    try:
        ttl = max(1, int(ttl_seconds))
        await redis_wrapper.client.setex(REVOKED_KEY(jti), ttl, "revoked")
    except Exception:
        # Availability-first: don't throw from router
        pass


# ──────────────────────────────────────────────────────────────
# 🔎 GET /sessions — list active sessions
# ──────────────────────────────────────────────────────────────
@router.get(
    "/sessions",
    response_model=SessionsListResponse,
    summary="List active sessions for the current user",
)
@rate_limit("30/minute")
async def list_sessions(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> SessionsListResponse:
    """
    Return the set of **active sessions** (refresh token handles) for the caller.

    Behavior
    --------
    - Reads Redis `session:{user_id}` and intersects with DB `RefreshToken` rows
      that are **not revoked** and **not expired**.
    - Augments with optional Redis metadata (`sessionmeta:{jti}`).
    - Marks which entry is **current** by comparing access token `session_id`
      with metadata `session_id`; if metadata is absent but the access token’s
      `session_id`/`jti` equals the JTI, treat as current.
    """
    set_sensitive_cache(response)

    claims = await _decode_access_claims(request)
    user_id = current_user.id
    current_sid = claims.get("session_id") or claims.get("jti")

    jtis = await _list_active_jtis(user_id)
    now = _now_utc()

    # Load active rows either by JTIs from Redis, or fall back to recent DB rows
    tokens_by_jti: Dict[str, RefreshToken] = {}
    if jtis:
        q = select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.jti.in_(jtis),
            RefreshToken.is_revoked.is_(False),
            RefreshToken.expires_at > now,
        )
        results = (await db.execute(q)).scalars().all()
        tokens_by_jti = {t.jti: t for t in results}
    else:
        q = (
            select(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked.is_(False),
                RefreshToken.expires_at > now,
            )
            .order_by(RefreshToken.created_at.desc())
            .limit(20)
        )
        results = (await db.execute(q)).scalars().all()
        tokens_by_jti = {t.jti: t for t in results}
        jtis = list(tokens_by_jti.keys())

    items: List[SessionItem] = []
    for jti in jtis:
        t = tokens_by_jti.get(jti)
        if not t:
            # Stale Redis member; ignore silently
            continue

        meta = await _read_session_meta(jti)
        is_current = False
        if meta.get("session_id"):
            is_current = (meta.get("session_id") == current_sid)
        else:
            if current_sid and str(current_sid) == jti:
                is_current = True

        items.append(
            SessionItem(
                jti=jti,
                created_at=t.created_at,
                expires_at=t.expires_at,
                ip_address=_as_str_or_none(meta.get("ip")) or _as_str_or_none(getattr(t, "ip_address", None)),
                user_agent=_as_str_or_none(meta.get("ua")),
                last_seen=meta.get("last_seen"),
                session_id=meta.get("session_id"),
                current=is_current,
            )
        )

    await log_audit_event(
        db,
        action=AuditEvent.SESSIONS_LIST,
        status="SUCCESS",
        user=current_user,
        request=request,
        meta_data={"returned": len(items)},
    )
    return SessionsListResponse(total=len(items), sessions=items)


# ──────────────────────────────────────────────────────────────
# ❌ DELETE /sessions/{jti} — revoke a specific session
# ──────────────────────────────────────────────────────────────
@router.delete(
    "/sessions/{jti}",
    response_model=RevokeResult,
    summary="Revoke a specific session (device sign-out)",
)
@rate_limit("20/minute")
async def revoke_session(
    request: Request,
    response: Response,
    jti: str = Path(..., description="Refresh token JTI to revoke"),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> RevokeResult:
    """
    Revoke a specific **refresh token session** by JTI.

    Idempotency
    -----------
    - If the JTI is unknown, already revoked, or expired, we still clean up Redis
      (remove from `session:{user_id}`, delete `sessionmeta:{jti}`) and return `{revoked: 0}`.

    Side-effects
    ------------
    - Sets Redis sentinel `revoked:jti:{jti}` (TTL = time remaining).
    - Removes JTI from the user's Redis set; deletes metadata hash.
    """
    set_sensitive_cache(response)

    now = _now_utc()
    token = (
        await db.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == current_user.id,
                RefreshToken.jti == jti,
            )
        )
    ).scalar_one_or_none()

    if not token or token.is_revoked or token.expires_at <= now:
        # Best-effort Redis cleanup without leaking non-caller info
        try:
            r = redis_wrapper.client
            await r.srem(SESSION_KEY(current_user.id), jti)
            await _delete_sessionmeta_safe(jti)
        except Exception:
            pass
        await log_audit_event(
            db, action=AuditEvent.SESSION_REVOKE, status="SKIP", user=current_user, request=request, meta_data={"jti": jti}
        )
        return RevokeResult(revoked=0)

    # Flip DB state
    token.is_revoked = True
    await db.commit()

    # Write sentinel + cleanup
    ttl = max(1, int((token.expires_at - now).total_seconds()))
    r = redis_wrapper.client
    await _set_reuse_sentinel(jti, ttl)
    await r.srem(SESSION_KEY(current_user.id), jti)
    await _delete_sessionmeta_safe(jti)

    await log_audit_event(
        db, action=AuditEvent.SESSION_REVOKE, status="SUCCESS", user=current_user, request=request, meta_data={"jti": jti}
    )
    return RevokeResult(revoked=1)


# ──────────────────────────────────────────────────────────────
# 🔥 DELETE /sessions — revoke ALL sessions (global sign-out)
# ──────────────────────────────────────────────────────────────
@router.delete(
    "/sessions",
    response_model=RevokeResult,
    summary="Revoke ALL sessions for the current user (global sign-out)",
)
@rate_limit("5/minute")
async def revoke_all_sessions(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> RevokeResult:
    """
    Revoke **all** active refresh sessions for the current user.

    Implementation
    --------------
    - Flip DB rows `is_revoked=True` (idempotent).
    - For each Redis JTI, write a reuse sentinel and delete metadata.
    - Clear the Redis set `session:{user_id}`.
    """
    set_sensitive_cache(response)

    rows = (
        await db.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == current_user.id,
                RefreshToken.is_revoked.is_(False),
            )
        )
    ).scalars().all()

    now = _now_utc()
    count = 0
    for t in rows:
        t.is_revoked = True
        count += 1
    if count:
        await db.commit()

    # Redis cleanup & sentinels
    try:
        r = redis_wrapper.client
        jtis = await r.smembers(SESSION_KEY(current_user.id))
        # Fallback TTL if the row isn't found
        ttl_default = int(getattr(settings, "REFRESH_TOKEN_EXPIRE_DAYS", 7)) * 86400
        for j in (jtis or []):
            j_s = _b2s(j)
            row = next((t for t in rows if t.jti == j_s), None)
            ttl = max(1, int((row.expires_at - now).total_seconds())) if row else ttl_default
            await _set_reuse_sentinel(j_s, ttl)
            await _delete_sessionmeta_safe(j_s)
        await r.delete(SESSION_KEY(current_user.id))
    except Exception:
        pass

    await log_audit_event(
        db,
        action=AuditEvent.SESSIONS_REVOKE_ALL,
        status="SUCCESS",
        user=current_user,
        request=request,
        meta_data={"revoked": count},
    )
    return RevokeResult(revoked=count)


# ──────────────────────────────────────────────────────────────
# 🚪 DELETE /sessions/others — revoke all EXCEPT current (best-effort)
# ──────────────────────────────────────────────────────────────
@router.delete(
    "/sessions/others",
    response_model=RevokeResult,
    summary="Revoke all sessions except the current one (best-effort)",
)
@rate_limit("5/minute")
async def revoke_other_sessions(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> RevokeResult:
    """
    Revoke all sessions **except the caller's current** session.

    Current detection
    -----------------
    - Prefer `sessionmeta:{jti}.session_id == <access session_id>`.
    - If *no* metadata exists for any JTI, we **fall back to global sign-out**
      to avoid side-channel leaks about which device is current.

    Return value
    ------------
    - `revoked` counts DB rows toggled **plus** stale Redis JTIs removed.
    """
    set_sensitive_cache(response)

    claims = await _decode_access_claims(request)
    current_sid = claims.get("session_id") or claims.get("jti")
    user_id = current_user.id

    jtis = await _list_active_jtis(user_id)
    if not jtis:
        await log_audit_event(
            db, action=AuditEvent.SESSIONS_REVOKE_OTHERS, status="SKIP",
            user=current_user, request=request, meta_data={"reason": "no_jtis"}
        )
        return RevokeResult(revoked=0)

    # Load active rows for these JTIs
    now = _now_utc()
    rows = (
        await db.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.jti.in_(jtis),
                RefreshToken.expires_at > now,
            )
        )
    ).scalars().all()
    rows_by_jti = {t.jti: t for t in rows if not t.is_revoked}

    keep: List[str] = []
    to_revoke: List[str] = []
    saw_any_meta = False

    # Classify using metadata first; fall back to "access jti equals JTI"
    for j in jtis:
        meta = await _read_session_meta(j)
        sid = meta.get("session_id")
        if sid:
            saw_any_meta = True
        if sid and current_sid and sid == current_sid:
            keep.append(j)
        elif not sid and current_sid and str(current_sid) == j:
            keep.append(j)
        else:
            to_revoke.append(j)

    # If **no** sessions have metadata, safest is to revoke all (no side channels)
    if not saw_any_meta:
        # Use the same DB session & user; this path must revoke & set sentinels.
        result = await revoke_all_sessions(request, response, db, current_user)
        await log_audit_event(
            db,
            action=AuditEvent.SESSIONS_REVOKE_OTHERS,
            status="SUCCESS",
            user=current_user,
            request=request,
            meta_data={"fallback": "revoke_all", "revoked": result.revoked},
        )
        return result

    # If everything is kept, short-circuit (nothing to revoke)
    if not to_revoke:
        await log_audit_event(
            db,
            action=AuditEvent.SESSIONS_REVOKE_OTHERS,
            status="SUCCESS",
            user=current_user,
            request=request,
            meta_data={"revoked": 0, "kept": len(keep), "note": "nothing_to_revoke"},
        )
        return RevokeResult(revoked=0)

    # Flip DB rows where present
    revoked_db = 0
    for j in to_revoke:
        t = rows_by_jti.get(j)
        if t and not t.is_revoked and t.expires_at > now:
            t.is_revoked = True
            revoked_db += 1
    if revoked_db:
        await db.commit()

    # Redis cleanup + reuse sentinels for both DB-backed and stale JTIs
    r = redis_wrapper.client
    ttl_default = int(getattr(settings, "REFRESH_TOKEN_EXPIRE_DAYS", 7)) * 86400
    revoked_redis_only = 0
    for j in to_revoke:
        t = rows_by_jti.get(j)
        ttl = max(1, int((t.expires_at - now).total_seconds())) if t else ttl_default
        await _set_reuse_sentinel(j, ttl)
        try:
            await r.srem(SESSION_KEY(user_id), j)
        except Exception:
            # best effort; we still set the sentinel above
            pass
        await _delete_sessionmeta_safe(j)
        if not t:
            revoked_redis_only += 1

    total_revoked = revoked_db + revoked_redis_only

    await log_audit_event(
        db,
        action=AuditEvent.SESSIONS_REVOKE_OTHERS,
        status="SUCCESS",
        user=current_user,
        request=request,
        meta_data={
            "current_sid": _as_str_or_none(current_sid),
            "jtis": jtis,
            "keep": keep,
            "to_revoke": to_revoke,
            "revoked_db": revoked_db,
            "revoked_redis_only": revoked_redis_only,
            "revoked": total_revoked,
        },
    )
    return RevokeResult(revoked=total_revoked)
