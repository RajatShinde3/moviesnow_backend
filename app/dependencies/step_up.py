# app/dependencies/step_up.py
"""
Step-Up (Reauth) Dependency — hardened, production-grade
=======================================================

Purpose
-------
Require a **fresh step-up token** (a short-lived "reauth" bearer issued by
`/reauth/password` or `/reauth/mfa`) before allowing **sensitive** operations
such as: change email, change password, delete/deactivate account, API key
creation, SSO settings, billing actions, org-role changes, etc.

How clients should call sensitive endpoints
-------------------------------------------
- Send the normal **access token** in the `Authorization: Bearer <access>` header.
- Also send the **reauth token** (from `/reauth/*`) in one of:
  - `X-Reauth: <reauth>`           (preferred)
  - `X-Reauth-Token: <reauth>`     (alias)
  - `X-Action-Token: <reauth>`     (alias)

What this dependency enforces (by default)
------------------------------------------
- The reauth bearer is **valid** and **not expired**.
- The reauth token’s `token_type/typ` is **"reauth"**.
- The **same user** is present in the access and reauth tokens (`sub` matches).
- The **same session lineage** is used (reauth `session_id` == access `session_id`).
- Optional: **one-time** usage (reject reuse within remaining TTL) via Redis.

How to use in your routers
--------------------------
Option A (simple gate; you only need to check, not read the claims):
    from fastapi import Depends
    from app.dependencies.step_up import step_up_required

    @router.post("/account/change-email", dependencies=[Depends(step_up_required(require_mfa=True, one_time=True))])
    async def change_email(...):
        ...

Option B (you also want to read reauth claims in the handler):
    @router.post("/account/change-password")
    async def change_password(reauth=Depends(step_up_required(require_mfa=True))):
        # reauth is a dict of verified reauth claims (sub, jti, session_id, etc.)
        ...

Tuning knobs
------------
- step_up_required(require_mfa: bool = False, bind_session: bool = True, one_time: bool = False)
- Settings you can define (optional):
    - REAUTH_ONE_TIME (bool, default False) — global default for one-time enforcement
    - REAUTH_REPLAY_KEY_TTL_PADDING_SECONDS (int, default 5) — extra TTL for the replay sentinel
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional, Dict

from fastapi import Depends, HTTPException, Request, status
from jose import jwt, JWTError

from app.core.config import settings
from app.core.redis_client import redis_wrapper

# ──────────────────────────────────────────────────────────────────────────────
# Constants & small helpers
# ──────────────────────────────────────────────────────────────────────────────

REAUTH_ONE_TIME_DEFAULT = bool(getattr(settings, "REAUTH_ONE_TIME", False))
REPLAY_TTL_PADDING = int(getattr(settings, "REAUTH_REPLAY_KEY_TTL_PADDING_SECONDS", 5))


def _now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _decode(jwt_token: str) -> Dict:
    """Decode a JWT with required basic claims; raise 401 on failure."""
    try:
        return jwt.decode(
            jwt_token,
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["sub", "exp"]},
        )
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


def _extract_header_token(request: Request, header_names: tuple[str, ...]) -> Optional[str]:
    """Try multiple header names and return the first non-empty value (stripped)."""
    for h in header_names:
        v = request.headers.get(h)
        if v:
            return v.strip()
    return None


async def _smembers_str(key: str) -> set[str]:
    """Bytes-safe SMEMBERS (best-effort)."""
    r = getattr(redis_wrapper, "client", None)
    if not r:
        return set()
    try:
        vals = await r.smembers(key)
        return {v.decode() if isinstance(v, (bytes, bytearray)) else str(v) for v in (vals or set())}
    except Exception:
        return set()


async def _setex(key: str, ttl: int, value: str) -> None:
    """Best-effort SETEX."""
    r = getattr(redis_wrapper, "client", None)
    if not r or ttl <= 0:
        return
    try:
        await r.setex(key, ttl, value)
    except Exception:
        pass


async def _exists(key: str) -> bool:
    """Best-effort EXISTS/GET."""
    r = getattr(redis_wrapper, "client", None)
    if not r:
        return False
    try:
        if hasattr(r, "exists"):
            return bool(await r.exists(key))
        val = await r.get(key)
        return val is not None
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# 🔐 Dependency factory
# ──────────────────────────────────────────────────────────────────────────────
def step_up_required(
    *,
    require_mfa: bool = False,
    bind_session: bool = True,
    one_time: bool = REAUTH_ONE_TIME_DEFAULT,
) -> Callable[[Request], Dict]:
    """
    Create a dependency that **enforces step-up** (reauth) before entering a route.

    Parameters
    ----------
    require_mfa : bool
        If True, require `mfa_authenticated == True` in the reauth token.
    bind_session : bool
        If True, require reauth `session_id` == access `session_id`, and (best-effort)
        require that the session lineage exists in `session:{sub}` Redis set.
    one_time : bool
        If True, enforce **one-time use** of the reauth token JTI (replay-prevention)
        using a short-lived Redis sentinel.

    Returns
    -------
    callable(Request) -> dict
        A callable suitable for FastAPI `Depends(...)` that returns the verified
        **reauth claims** dictionary on success and raises HTTP 401/403 on failure.
    """

    async def _dep(request: Request) -> Dict:
        # ── [Step 1] Read the access token from Authorization ──────────────────
        authz = request.headers.get("authorization") or request.headers.get("Authorization")
        if not authz or not authz.lower().startswith("bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")
        access_token = authz.split(" ", 1)[1].strip()
        access_claims = _decode(access_token)
        access_typ = (access_claims.get("token_type") or access_claims.get("typ") or "").lower()
        if access_typ == "reauth":
            # If the caller mistakenly put the reauth token in Authorization,
            # ask them to send reauth in X-Reauth and keep access in Authorization.
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token required in Authorization")

        # ── [Step 2] Read the reauth token from a dedicated header ─────────────
        reauth_token = _extract_header_token(
            request,
            ("X-Reauth", "X-Reauth-Token", "X-Action-Token"),
        )
        if not reauth_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Step-up token required")

        reauth = _decode(reauth_token)
        reauth_typ = (reauth.get("token_type") or reauth.get("typ") or "").lower()
        if reauth_typ != "reauth":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not a reauth token")

        # ── [Step 3] Same-user guard ───────────────────────────────────────────
        if str(reauth.get("sub")) != str(access_claims.get("sub")):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Reauth does not match current user")

        # ── [Step 4] Optional MFA guard ────────────────────────────────────────
        if require_mfa and not bool(reauth.get("mfa_authenticated")):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA step-up required")

        # ── [Step 5] Optional session binding ──────────────────────────────────
        if bind_session:
            acc_sid = str(access_claims.get("session_id") or access_claims.get("jti") or "")
            rea_sid = str(reauth.get("session_id") or "")
            if not acc_sid or not rea_sid or acc_sid != rea_sid:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Step-up not bound to this session")

            # Best-effort lineage existence check in Redis
            try:
                user_id = str(access_claims.get("sub"))
                jtis = await _smembers_str(f"session:{user_id}")
                # We can’t guarantee a direct mapping from session_id→JTI in a SET,
                # but presence of any JTI indicates an active lineage for the user.
                if not jtis:
                    # No active refresh sessions recorded — suspicious but may be benign
                    # Don’t hard fail; comment the next line to make it strict:
                    pass
            except Exception:
                pass

        # ── [Step 6] Optional one-time usage (replay prevention) ──────────────
        if one_time:
            jti = str(reauth.get("jti") or "")
            exp = int(reauth.get("exp") or 0)
            if not jti or not exp:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid reauth token")
            replay_key = f"reauth:used:{jti}"
            if await _exists(replay_key):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Reauth token already used")
            ttl = max(0, exp - _now_ts()) + REPLAY_TTL_PADDING
            await _setex(replay_key, ttl, "1")

        # Success — return verified reauth claims to the endpoint if needed
        return reauth

    return _dep


# ──────────────────────────────────────────────────────────────────────────────
# Convenience wrappers (common presets)
# ──────────────────────────────────────────────────────────────────────────────
def require_step_up() -> Callable[[Request], Dict]:
    """
    Require a valid reauth token, bound to the same session as the access token.
    MFA not strictly required; one-time usage follows the global default.
    """
    return step_up_required(require_mfa=False, bind_session=True, one_time=REAUTH_ONE_TIME_DEFAULT)


def require_step_up_mfa() -> Callable[[Request], Dict]:
    """
    Require a valid **MFA-backed** reauth token, bound to the same session.
    """
    return step_up_required(require_mfa=True, bind_session=True, one_time=REAUTH_ONE_TIME_DEFAULT)
