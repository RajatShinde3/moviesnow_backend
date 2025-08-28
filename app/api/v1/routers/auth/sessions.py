# app/api/v1/auth/sessions.py

"""
Enterprise-grade **Session Inventory & Revocation** Router
=========================================================

This router exposes **self-service session management** for users:

Endpoints
---------
- GET    /sessions            — list active sessions for the current user
- DELETE /sessions/{jti}      — revoke a specific session (device sign-out)
- DELETE /sessions            — revoke **all** sessions (global sign-out)
- DELETE /sessions/others     — revoke all sessions **except current** (best-effort)

Design goals
------------
- **Authoritative**: intersect Redis `session:{user_id}` with DB `RefreshToken`
- **Privacy-safe**: never return raw tokens; use metadata (IP/UA/created)
- **No-store**: responses marked with cache-control hardening
- **Rate-limited**: per-route limits with IP+user keying (from your limiter)
- **Best-effort current session detection**:
  - Prefer comparing access token `session_id` with `sessionmeta:{jti}.session_id`
  - Fallback: if metadata is missing for a JTI but its value equals the access
    token’s `session_id` or `jti`, treat it as **current** and keep it

Integration notes
-----------------
When rotating refresh tokens, also record session metadata in Redis:
`HSET sessionmeta:{jti} session_id <sid> ip <ip> ua <ua> created_at <iso> last_seen <iso>`
and optionally `EXPIRE sessionmeta:{jti} <seconds_until_refresh_expiry>`.

Security
--------
- All destructive operations are auditable and **idempotent**
- Revocation also sets a Redis sentinel `revoked:jti:{jti}` for reuse detection
- `DELETE /sessions/others` falls back to `DELETE /sessions` if we cannot
  confidently keep the current session without leaking side-channel info
"""

from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status
from jose import jwt, JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.redis_client import redis_wrapper
from app.core.limiter import rate_limit
from app.core.dependencies import get_current_user
from app.db.session import get_async_db
from app.security_headers import set_sensitive_cache
from app.db.models.user import User
from app.db.models.token import RefreshToken
from app.schemas.auth import SessionItem, SessionsListResponse, RevokeResult
from app.services.audit_log_service import log_audit_event

router = APIRouter()

# ──────────────────────────────────────────────────────────────────────────────
# 🔑 Redis keys
# ──────────────────────────────────────────────────────────────────────────────
SESSION_KEY = lambda user_id: f"session:{user_id}"           # Set of refresh JTIs for a user
SESSION_META_KEY = lambda jti: f"sessionmeta:{jti}"          # Hash: session_id, ip, ua, created_at, last_seen
REVOKED_KEY = lambda jti: f"revoked:jti:{jti}"               # String sentinel (TTL = time left until expiry)

# ──────────────────────────────────────────────────────────────────────────────
# 🧩 Small helpers
# ──────────────────────────────────────────────────────────────────────────────
def _b2s(v):
    return v.decode() if isinstance(v, (bytes, bytearray)) else v

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

async def _decode_access_claims(request: Request) -> dict:
    """Decode Authorization bearer and return claims; 401 on failure."""
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

async def _read_session_meta(jti: str) -> dict:
    """Read optional session metadata for a JTI; normalize types."""
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
    """Read the Redis set of active JTIs for a user (best-effort)."""
    r = redis_wrapper.client
    try:
        members = await r.smembers(SESSION_KEY(user_id))
    except Exception:
        members = set()
    return sorted({_b2s(m) for m in (members or set())})

async def _delete_sessionmeta_safe(jti: str) -> None:
    """Best-effort removal of per-JTI metadata on revocation."""
    try:
        await redis_wrapper.client.delete(SESSION_META_KEY(jti))
    except Exception:
        pass

# ──────────────────────────────────────────────────────────────────────────────
# 🔎 GET /sessions — list active sessions
# ──────────────────────────────────────────────────────────────────────────────
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
    - Reads Redis `session:{user_id}`; intersects with DB `RefreshToken` rows
      that are not revoked and not expired.
    - Enriches each item with optional Redis metadata (`sessionmeta:{jti}`) when present.
    - Attempts to mark which entry is the **current** by comparing the access token
      `session_id` with metadata `session_id`; also treats a JTI that equals the
      access bearer’s `session_id`/`jti` as current if metadata is missing.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Identify caller + current access session lineage ────────────
    claims = await _decode_access_claims(request)
    user_id = current_user.id
    current_sid = claims.get("session_id") or claims.get("jti")

    # ── [Step 2] Load candidate JTIs; fallback to DB when empty ──────────────
    jtis = await _list_active_jtis(user_id)
    now = _now_utc()

    tokens_by_jti: dict[str, RefreshToken] = {}
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
        # Fallback: recent active tokens from DB (no leakage of other users)
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

    # ── [Step 3] Build response list (augment with sessionmeta) ──────────────
    items: List[SessionItem] = []
    for jti in jtis:
        t = tokens_by_jti.get(jti)
        if not t:
            # Not in DB or inactive — stale Redis; skip silently
            continue
        meta = await _read_session_meta(jti)
        # Best-effort "current" detection:
        is_current = False
        if meta.get("session_id"):
            is_current = (meta.get("session_id") == current_sid)
        else:
            # Fallback: if access token's session_id/jti equals this JTI, treat as current
            if current_sid and str(current_sid) == jti:
                is_current = True

        items.append(
            SessionItem(
                jti=jti,
                created_at=t.created_at,
                expires_at=t.expires_at,
                ip_address=meta.get("ip") or getattr(t, "ip_address", None),
                user_agent=meta.get("ua"),
                last_seen=meta.get("last_seen"),
                session_id=meta.get("session_id"),
                current=is_current,
            )
        )

    # ── [Step 4] Audit read & respond ────────────────────────────────────────
    await log_audit_event(db, action="SESSIONS_LIST", user=current_user, status="SUCCESS", request=request)
    return SessionsListResponse(total=len(items), sessions=items)

# ──────────────────────────────────────────────────────────────────────────────
# ❌ DELETE /sessions/{jti} — revoke a specific session
# ──────────────────────────────────────────────────────────────────────────────
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

    Behavior
    --------
    - Idempotent: revoking an already revoked/nonexistent JTI returns `{revoked: 0}`.
    - Only affects the **caller’s** sessions.
    - Sets Redis sentinel `revoked:jti:{jti}` (with TTL until original expiry),
      removes the JTI from `session:{user_id}`, and deletes `sessionmeta:{jti}`.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Resolve token row for this user ─────────────────────────────
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
        # Best-effort cleanup; no leakage beyond caller
        try:
            r = redis_wrapper.client
            await r.srem(SESSION_KEY(current_user.id), jti)
            await _delete_sessionmeta_safe(jti)
        except Exception:
            pass
        await log_audit_event(db, action="SESSION_REVOKE", user=current_user, status="SKIP", request=request, meta_data={"jti": jti})
        return RevokeResult(revoked=0)

    # ── [Step 2] Mark revoked in DB and set reuse sentinel ───────────────────
    token.is_revoked = True
    await db.commit()

    ttl = max(0, int((token.expires_at - now).total_seconds()))
    r = redis_wrapper.client
    await r.setex(REVOKED_KEY(jti), ttl, "revoked")
    await r.srem(SESSION_KEY(current_user.id), jti)
    await _delete_sessionmeta_safe(jti)

    # ── [Step 3] Audit & respond ─────────────────────────────────────────────
    await log_audit_event(db, action="SESSION_REVOKE", user=current_user, status="SUCCESS", request=request, meta_data={"jti": jti})
    return RevokeResult(revoked=1)

# ──────────────────────────────────────────────────────────────────────────────
# 🔥 DELETE /sessions — revoke ALL sessions (global sign-out)
# ──────────────────────────────────────────────────────────────────────────────
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
    Revoke **all** active refresh token sessions for the current user.

    Behavior
    --------
    - Marks all DB rows `is_revoked=True` and clears `session:{user_id}` in Redis.
    - Also writes `revoked:jti:{jti}` sentinels so token reuse is blocked.
    - Deletes `sessionmeta:{jti}` entries for cleanliness.
    - Idempotent; returns the number of rows flipped to revoked.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] DB mass update ──────────────────────────────────────────────
    rows = (
        await db.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == current_user.id,
                RefreshToken.is_revoked.is_(False),
            )
        )
    ).scalars().all()
    count = 0
    now = _now_utc()
    for t in rows:
        t.is_revoked = True
        count += 1
    if count:
        await db.commit()

    # ── [Step 2] Redis cleanup & reuse sentinels ─────────────────────────────
    try:
        r = redis_wrapper.client
        jtis = await r.smembers(SESSION_KEY(current_user.id))
        ttl_default = int(getattr(settings, "REFRESH_TOKEN_EXPIRE_DAYS", 7)) * 86400
        for j in (jtis or []):
            j_s = _b2s(j)
            # Prefer exact TTL if we still have the row, else default
            row = next((t for t in rows if t.jti == j_s), None)
            ttl = max(0, int((row.expires_at - now).total_seconds())) if row else ttl_default
            await r.setex(REVOKED_KEY(j_s), ttl, "revoked")
            await _delete_sessionmeta_safe(j_s)
        await r.delete(SESSION_KEY(current_user.id))
    except Exception:
        pass

    # ── [Step 3] Audit & respond ─────────────────────────────────────────────
    await log_audit_event(
        db,
        action="SESSIONS_REVOKE_ALL",
        user=current_user,
        status="SUCCESS",
        request=request,
        meta_data={"count": count},
    )
    return RevokeResult(revoked=count)

# ──────────────────────────────────────────────────────────────────────────────
# 🚪 DELETE /sessions/others — revoke all EXCEPT current (best-effort)
# ──────────────────────────────────────────────────────────────────────────────
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

    Behavior
    --------
    - Detects current session by reading the access token's `session_id` (or `jti`).
    - Keeps JTIs whose `sessionmeta:{jti}.session_id` matches the current session.
    - If metadata is missing for a JTI **but** that JTI equals the access token’s
      `session_id`/`jti`, treat it as **current** and keep it.
    - If metadata is missing for *all* JTIs, falls back to global sign-out to
      avoid providing side-channel information.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Determine current session lineage ───────────────────────────
    claims = await _decode_access_claims(request)
    current_sid = claims.get("session_id") or claims.get("jti")

    # ── [Step 2] Load active JTIs and classify ───────────────────────────────
    user_id = current_user.id
    jtis = await _list_active_jtis(user_id)
    if not jtis:
        await log_audit_event(db, action="SESSIONS_REVOKE_OTHERS", user=current_user, status="SKIP", request=request)
        return RevokeResult(revoked=0)

    keep: List[str] = []
    to_revoke: List[str] = []
    saw_any_meta = False

    for j in jtis:
        meta = await _read_session_meta(j)
        sid = meta.get("session_id")
        if sid:
            saw_any_meta = True
        # Keep if explicit session_id matches current
        if sid and current_sid and sid == current_sid:
            keep.append(j)
            continue
        # Fallback: if this JTI equals the access token’s session_id/jti, consider it current
        if not sid and current_sid and str(current_sid) == j:
            keep.append(j)
            continue
        # Otherwise, candidate for revocation
        to_revoke.append(j)

    if not saw_any_meta:
        # Without any metadata, safest path is revoke all (no side-channel leaks)
        return await revoke_all_sessions(request, response, db, current_user)

    # If everything is kept, short-circuit
    if not to_revoke:
        await log_audit_event(
            db, action="SESSIONS_REVOKE_OTHERS", user=current_user, status="SUCCESS", request=request, meta_data={"revoked": 0, "kept": len(keep)}
        )
        return RevokeResult(revoked=0)

    # ── [Step 3] Revoke selected JTIs in DB + Redis ──────────────────────────
    now = _now_utc()
    rows: List[RefreshToken] = []
    if to_revoke:
        rows = (
            await db.execute(
                select(RefreshToken).where(
                    RefreshToken.user_id == user_id,
                    RefreshToken.jti.in_(to_revoke),
                )
            )
        ).scalars().all()

    count = 0
    for t in rows:
        if not t.is_revoked and t.expires_at > now:
            t.is_revoked = True
            count += 1
    if rows:
        await db.commit()

    r = redis_wrapper.client
    ttl_default = int(getattr(settings, "REFRESH_TOKEN_EXPIRE_DAYS", 7)) * 86400
    for j in to_revoke:
        row = next((t for t in rows if t.jti == j), None)
        ttl = max(0, int((row.expires_at - now).total_seconds())) if row else ttl_default
        await r.setex(REVOKED_KEY(j), ttl, "revoked")
        await r.srem(SESSION_KEY(user_id), j)
        await _delete_sessionmeta_safe(j)

    # ── [Step 4] Audit & respond ─────────────────────────────────────────────
    await log_audit_event(
        db,
        action="SESSIONS_REVOKE_OTHERS",
        user=current_user,
        status="SUCCESS",
        request=request,
        meta_data={"revoked": count, "kept": len(keep)},
    )
    return RevokeResult(revoked=count)
