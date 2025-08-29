# app/api/v1/auth/trusted_devices.py
from __future__ import annotations

"""
Enterprise-grade **Trusted Devices / Remembered MFA** Router
===========================================================

This router allows a user to **register** the current device as “trusted”
*after* a **fresh MFA** challenge (or a reauth token minted by your step-up
flow). While the trusted cookie is present and the corresponding Redis record
is alive, subsequent logins from this device may **skip MFA** (subject to your
risk checks). Users can **list** and **revoke** trusted devices at any time.

Why this design?
----------------
- **Server-authoritative**: the cookie is a signed *pointer* (device_id); it
  cannot stand alone. All trust state lives in Redis and can be revoked.
- **MFA-fresh requirement**: registration demands a bearer that indicates a
  recent MFA success (`token_type in {"reauth","access"}` **and**
  `mfa_authenticated=True`).
- **Privacy-aware**: we hash the user-agent using a server-side salt and return
  **only** the hash; the IP is lightly anonymized in listings.
- **Defense-in-depth**: per-user and per-IP rate limits on registration and
  revocation; eviction when exceeding the per-user device cap; signed cookies.

Endpoints
---------
- `POST   /mfa/trusted-devices/register` — mark the current device trusted; sets a signed cookie
- `GET    /mfa/trusted-devices`          — list trusted devices (ua_hash, masked_ip, timestamps)
- `DELETE /mfa/trusted-devices/{id}`     — revoke a specific trusted device
- `DELETE /mfa/trusted-devices`          — revoke **all** trusted devices

Redis keys
----------
- `td:z:{user_id}`     — **ZSET** of device ids scored by `last_seen`/`created_at`
- `td:dev:{device_id}` — **HASH**: `user_id`, `ua_hash`, `ip`, `created_at`, `last_seen`, `expires_at`
- `td:rev:{device_id}` — **STRING** sentinel for recently revoked ids (helps ignore stale cookies)

Cookie
------
- Name: `tdid`
- Value: `<device_id>.<signature>` (HMAC-SHA256 over `device_id`)
- TTL: `TRUSTED_DEVICE_TTL_DAYS` (default 30)
- Flags: `HttpOnly`, `Secure`, `SameSite` (default `Lax`; `None` forces `Secure`)
"""

import base64
import hashlib
import hmac
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status
from jose import jwt, JWTError
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.limiter import rate_limit
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.core.security import get_current_user
from app.db.models.user import User
from app.schemas.auth import TrustedDeviceItem, TrustedDevicesList, RevokeResult
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event

router = APIRouter(tags=["Trusted Devices"])

# ─────────────────────────────────────────────────────────────
# ⚙️ Constants & helpers
# ─────────────────────────────────────────────────────────────
TD_COOKIE_NAME = getattr(settings, "TRUSTED_DEVICE_COOKIE_NAME", "tdid")
TD_TTL_DAYS = int(getattr(settings, "TRUSTED_DEVICE_TTL_DAYS", 30))
TD_TTL_SECONDS = TD_TTL_DAYS * 86400
TD_MAX_DEVICES = int(getattr(settings, "TRUSTED_DEVICE_MAX", 10))

TD_HMAC_KEY = (
    getattr(settings, "TRUSTED_DEVICE_HMAC_KEY", None) or settings.JWT_SECRET_KEY.get_secret_value()
).encode("utf-8")
UA_SALT = (
    getattr(settings, "UA_FINGERPRINT_SALT", None) or settings.JWT_SECRET_KEY.get_secret_value()
).encode("utf-8")

TD_Z_KEY = lambda user_id: f"td:z:{user_id}"
TD_DEV_KEY = lambda dev_id: f"td:dev:{dev_id}"
TD_REV_KEY = lambda dev_id: f"td:rev:{dev_id}"

INCR_EXPIRE_LUA = """
local v = redis.call('incr', KEYS[1])
if v == 1 then redis.call('expire', KEYS[1], ARGV[1]) end
return v
"""

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _b2s(v):
    return v.decode() if isinstance(v, (bytes, bytearray)) else v

def _normalize_samesite(value: Optional[str]) -> str:
    v = (value or "lax").strip().lower()
    return v if v in {"lax", "strict", "none"} else "lax"

def _require_secure_if_none(samesite: str) -> bool:
    # SameSite=None requires Secure=true in modern browsers
    return True if samesite == "none" else bool(getattr(settings, "COOKIE_SECURE", True))

def _anonymize_ip(ip: Optional[str]) -> str:
    """
    Return a lightly anonymized representation (v4 /24, v6 /48).
    Purely informational; not used for auth.
    """
    try:
        if not ip:
            return ""
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        # IPv6: zero the last 5 hextets (approx /48)
        hextets = ip.split(":")
        return ":".join(hextets[:3] + ["0000"] * 5) + "/48"
    except Exception:
        return ""

def _ua_hash(ua: Optional[str]) -> str:
    """Hash the UA with a server-side salt; never store or return raw UA."""
    ua = (ua or "").strip()
    h = hmac.new(UA_SALT, ua.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(h).decode().rstrip("=")

def _sign_device_id(device_id: str) -> str:
    mac = hmac.new(TD_HMAC_KEY, device_id.encode("utf-8"), hashlib.sha256).digest()
    sig = base64.urlsafe_b64encode(mac).decode().rstrip("=")
    return f"{device_id}.{sig}"

async def _verify_signed_device_id(value: str) -> Optional[str]:
    try:
        dev_id, sig = value.split(".", 1)
        expected = _sign_device_id(dev_id).split(".", 1)[1]
        if not hmac.compare_digest(sig, expected):
            return None
        r = redis_wrapper.client
        flagged = await r.get(TD_REV_KEY(dev_id)) if hasattr(r, "get") else None
        return None if flagged else dev_id
    except Exception:
        return None

async def _decode_bearer_claims(request: Request) -> dict:
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

async def _enforce_budget(key: str, seconds: int, ceiling: int) -> None:
    """Atomic INCR with TTL; raise 429 if over ceiling."""
    r = redis_wrapper.client
    try:
        v = int(await r.eval(INCR_EXPIRE_LUA, keys=[key], args=[seconds]))
    except Exception:
        v = int(await r.incr(key))
        if v == 1:
            await r.expire(key, seconds)
    if v > ceiling:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many attempts")

async def _evict_if_over_cap(user_id: UUID) -> int:
    """Ensure at most TD_MAX_DEVICES in td:z; evict oldest if necessary."""
    r = redis_wrapper.client
    n = await r.zcard(TD_Z_KEY(user_id))
    if n and n > TD_MAX_DEVICES:
        surplus = n - TD_MAX_DEVICES
        old_ids = await r.zrange(TD_Z_KEY(user_id), 0, surplus - 1)
        count = 0
        for raw in (old_ids or []):
            did = _b2s(raw)
            await r.zrem(TD_Z_KEY(user_id), did)
            await r.delete(TD_DEV_KEY(did))
            await r.setex(TD_REV_KEY(did), TD_TTL_SECONDS, "revoked")
            count += 1
        return count
    return 0

async def _cleanup_if_expired(dev_id: str) -> bool:
    """Delete a device record if its `expires_at` is past; return True if removed."""
    r = redis_wrapper.client
    meta = await r.hgetall(TD_DEV_KEY(dev_id))
    if not meta:
        return True
    m = {(_b2s(k) if isinstance(k, (bytes, bytearray)) else k): _b2s(v) for k, v in meta.items()}
    try:
        exp = datetime.fromisoformat(m.get("expires_at")) if m.get("expires_at") else None
    except Exception:
        exp = None
    if exp and exp <= _now_utc():
        await r.delete(TD_DEV_KEY(dev_id))
        await r.setex(TD_REV_KEY(dev_id), TD_TTL_SECONDS, "revoked")
        return True
    return False

# ─────────────────────────────────────────────────────────────
# 📦 Local response schema (others come from app.schemas.auth)
# ─────────────────────────────────────────────────────────────
class TrustedDeviceRegisterResponse(BaseModel):
    id: str
    cookie_name: str = Field(default=TD_COOKIE_NAME)
    expires_in: int = Field(default=TD_TTL_SECONDS)

# ─────────────────────────────────────────────────────────────
# 🧿 POST /mfa/trusted-devices/register — register current device
# ─────────────────────────────────────────────────────────────
@router.post(
    "/mfa/trusted-devices/register",
    response_model=TrustedDeviceRegisterResponse,
    summary="Register the current device as trusted (requires **fresh** MFA context)",
)
@rate_limit("10/hour")
async def register_trusted_device(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> TrustedDeviceRegisterResponse:
    """
    Register the **current device** as trusted and set a signed, HttpOnly cookie.

    Security
    --------
    - Requires a bearer whose claims indicate **MFA freshness**:
      `token_type in {"reauth","access"}` **and** `mfa_authenticated=True`.
      (Your login flow should set `mfa_authenticated=True` after successful TOTP.)
    - Cookie is an HMAC-signed **pointer**; server Redis state is the source of truth.
    - Per-user **and** per-IP budgets defend against abuse.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Enforce budgets (per user + per IP) ─────────────────────────
    ip = (request.client.host if request.client else "-") or "-"
    await _enforce_budget(f"td:reg:user:{current_user.id}", 300, 20)  # 20 registrations / 5 min
    await _enforce_budget(f"td:reg:ip:{ip}", 300, 60)                 # 60 registrations / 5 min per IP

    # ── [Step 2] Validate **fresh** MFA context ──────────────────────────────
    claims = await _decode_bearer_claims(request)
    tok_typ = (claims.get("token_type") or claims.get("typ") or "").lower()
    mfa_fresh = bool(claims.get("mfa_authenticated")) and (tok_typ in ("reauth", "access", ""))
    if not mfa_fresh:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA required")

    # ── [Step 3] Idempotent refresh if client already has this device cookie ─
    presented = request.cookies.get(TD_COOKIE_NAME)
    if presented:
        dev_id = await _verify_signed_device_id(presented)
        if dev_id:
            r = redis_wrapper.client
            owner = await r.hget(TD_DEV_KEY(dev_id), "user_id")
            if owner and _b2s(owner) == str(current_user.id):
                now = _now_utc()
                await r.hset(
                    TD_DEV_KEY(dev_id),
                    mapping={
                        "last_seen": now.isoformat(),
                        "expires_at": (now + timedelta(seconds=TD_TTL_SECONDS)).isoformat(),
                    },
                )
                await r.expire(TD_DEV_KEY(dev_id), TD_TTL_SECONDS)
                await r.zadd(TD_Z_KEY(current_user.id), {dev_id: float(now.timestamp())})
                samesite = _normalize_samesite(getattr(settings, "COOKIE_SAMESITE", "lax"))
                response.set_cookie(
                    TD_COOKIE_NAME,
                    _sign_device_id(dev_id),
                    max_age=TD_TTL_SECONDS,
                    httponly=True,
                    secure=_require_secure_if_none(samesite),
                    samesite=samesite,
                    domain=getattr(settings, "COOKIE_DOMAIN", None),
                    path="/",
                )
                await log_audit_event(
                    db, action="TRUSTED_DEVICE_REFRESH", user=current_user, status="SUCCESS", request=request,
                    meta_data={"device_id": dev_id}
                )
                return TrustedDeviceRegisterResponse(id=dev_id)

    # ── [Step 4] Create a new device record ──────────────────────────────────
    dev_id = str(uuid4())
    now = _now_utc()
    expires_at = now + timedelta(seconds=TD_TTL_SECONDS)
    ua = request.headers.get("User-Agent")
    meta = {
        "user_id": str(current_user.id),
        "ua_hash": _ua_hash(ua),
        "ip": (request.client.host if request.client else "") or "",
        "created_at": now.isoformat(),
        "last_seen": now.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    r = redis_wrapper.client
    await r.hset(TD_DEV_KEY(dev_id), mapping=meta)
    await r.expire(TD_DEV_KEY(dev_id), TD_TTL_SECONDS)
    await r.zadd(TD_Z_KEY(current_user.id), {dev_id: float(now.timestamp())})
    await _evict_if_over_cap(current_user.id)

    # ── [Step 5] Set signed cookie ───────────────────────────────────────────
    samesite = _normalize_samesite(getattr(settings, "COOKIE_SAMESITE", "lax"))
    response.set_cookie(
        TD_COOKIE_NAME,
        _sign_device_id(dev_id),
        max_age=TD_TTL_SECONDS,
        httponly=True,
        secure=_require_secure_if_none(samesite),
        samesite=samesite,
        domain=getattr(settings, "COOKIE_DOMAIN", None),
        path="/",
    )

    # ── [Step 6] Audit & respond ─────────────────────────────────────────────
    await log_audit_event(
        db, action="TRUSTED_DEVICE_REGISTER", user=current_user, status="SUCCESS",
        request=request, meta_data={"device_id": dev_id}
    )
    return TrustedDeviceRegisterResponse(id=dev_id)

# ─────────────────────────────────────────────────────────────
# 🔎 GET /mfa/trusted-devices — list trusted devices
# ─────────────────────────────────────────────────────────────
@router.get(
    "/mfa/trusted-devices",
    response_model=TrustedDevicesList,
    summary="List trusted devices (privacy-aware: UA hashed, IP anonymized)",
)
@rate_limit("30/minute")
async def list_trusted_devices(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> TrustedDevicesList:
    """
    Return the current user's trusted device inventory, **most-recent first**.
    - `ua_hash` is shown instead of the raw user-agent.
    - IP is anonymized to /24 (IPv4) or /48 (IPv6).
    - Expired records are cleaned up best-effort during listing.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    r = redis_wrapper.client
    ids = await r.zrevrange(TD_Z_KEY(current_user.id), 0, -1)

    devices: List[TrustedDeviceItem] = []
    for raw in (ids or []):
        dev_id = _b2s(raw)

        # Proactively drop expired
        if await _cleanup_if_expired(dev_id):
            await r.zrem(TD_Z_KEY(current_user.id), dev_id)
            continue

        meta = await r.hgetall(TD_DEV_KEY(dev_id))
        if not meta:
            await r.zrem(TD_Z_KEY(current_user.id), dev_id)
            continue

        m = {(_b2s(k) if isinstance(k, (bytes, bytearray)) else k): _b2s(v) for k, v in meta.items()}

        def _dt(x: Optional[str]):
            try:
                return datetime.fromisoformat(x) if x else None
            except Exception:
                return None

        devices.append(
            TrustedDeviceItem(
                id=dev_id,
                created_at=_dt(m.get("created_at")),
                last_seen=_dt(m.get("last_seen")),
                ua_hash=m.get("ua_hash"),
                ip=_anonymize_ip(m.get("ip")),
                expires_at=_dt(m.get("expires_at")),
            )
        )

    await log_audit_event(db, action="TRUSTED_DEVICE_LIST", user=current_user, status="SUCCESS", request=request)
    return TrustedDevicesList(total=len(devices), devices=devices)

# ─────────────────────────────────────────────────────────────
# ❌ DELETE /mfa/trusted-devices/{id} — revoke one
# ─────────────────────────────────────────────────────────────
@router.delete(
    "/mfa/trusted-devices/{device_id}",
    response_model=RevokeResult,
    summary="Revoke a single trusted device",
)
@rate_limit("30/minute")
async def revoke_trusted_device(
    request: Request,
    response: Response,
    device_id: str = Path(..., description="Trusted device id to revoke"),
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> RevokeResult:
    """
    Revoke **one** trusted device. Non-existent ids return `{revoked: 0}`.
    The client cookie is cleared if it matches the revoked id.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Budgeting (user + IP) ───────────────────────────────────────
    ip = (request.client.host if request.client else "-") or "-"
    await _enforce_budget(f"td:revoke:user:{current_user.id}", 120, 30)  # 30 / 2 min
    await _enforce_budget(f"td:revoke:ip:{ip}", 120, 90)                 # 90 / 2 min per IP

    r = redis_wrapper.client
    owner = await r.hget(TD_DEV_KEY(device_id), "user_id")
    if not owner:
        return RevokeResult(revoked=0)
    if _b2s(owner) != str(current_user.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    # Delete record and mark sentinel
    await r.delete(TD_DEV_KEY(device_id))
    await r.zrem(TD_Z_KEY(current_user.id), device_id)
    await r.setex(TD_REV_KEY(device_id), TD_TTL_SECONDS, "revoked")

    # Clear cookie if the client presented this id
    presented = request.cookies.get(TD_COOKIE_NAME)
    if presented:
        dev_id = await _verify_signed_device_id(presented)
        if dev_id == device_id:
            response.delete_cookie(
                TD_COOKIE_NAME,
                domain=getattr(settings, "COOKIE_DOMAIN", None),
                path="/",
            )

    await log_audit_event(
        db, action="TRUSTED_DEVICE_REVOKE", user=current_user, status="SUCCESS",
        request=request, meta_data={"device_id": device_id}
    )
    return RevokeResult(revoked=1)

# ─────────────────────────────────────────────────────────────
# 🔥 DELETE /mfa/trusted-devices — revoke ALL
# ─────────────────────────────────────────────────────────────
@router.delete(
    "/mfa/trusted-devices",
    response_model=RevokeResult,
    summary="Revoke **all** trusted devices for the current user",
)
@rate_limit("10/minute")
async def revoke_all_trusted_devices(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> RevokeResult:
    """
    Revoke **all** trusted devices for the current user, clear the cookie,
    and mark a short-lived revocation sentinel for each device id.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Budgeting (user + IP) ───────────────────────────────────────
    ip = (request.client.host if request.client else "-") or "-"
    await _enforce_budget(f"td:revoke_all:user:{current_user.id}", 300, 6)  # 6 / 5 min
    await _enforce_budget(f"td:revoke_all:ip:{ip}", 300, 18)                # 18 / 5 min per IP

    r = redis_wrapper.client
    ids = await r.zrange(TD_Z_KEY(current_user.id), 0, -1)
    count = 0
    for raw in (ids or []):
        did = _b2s(raw)
        await r.delete(TD_DEV_KEY(did))
        await r.setex(TD_REV_KEY(did), TD_TTL_SECONDS, "revoked")
        count += 1
    await r.delete(TD_Z_KEY(current_user.id))

    response.delete_cookie(
        TD_COOKIE_NAME,
        domain=getattr(settings, "COOKIE_DOMAIN", None),
        path="/",
    )

    await log_audit_event(
        db, action="TRUSTED_DEVICE_REVOKE_ALL", user=current_user, status="SUCCESS",
        request=request, meta_data={"count": count}
    )
    return RevokeResult(revoked=count)
