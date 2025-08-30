# app/api/v1/auth/webauthn.py
from __future__ import annotations

"""
MoviesNow — WebAuthn (Passkeys) API
===================================

Endpoints
---------
- POST   /auth/webauthn/registration/options   → begin passkey registration
- POST   /auth/webauthn/registration/verify    → finish/verify registration
- POST   /auth/webauthn/assertion/options      → begin passkey assertion (login/step-up)
- POST   /auth/webauthn/assertion/verify       → finish/verify assertion
- GET    /auth/webauthn/credentials            → list current user's passkeys
- DELETE /auth/webauthn/credentials/{id}       → delete a passkey (step-up required)

Design goals
------------
- **Security-first**:
  - Registration requires **step-up** (recent auth) and session binding by default.
  - Challenges stored server-side (Redis) and must match during verify.
  - Audit logs for all operations (best-effort / non-blocking).
- **Privacy**: never return credential public keys; show only safe metadata.
- **Resilience**: Redis unavailability degrades gracefully with clear errors.
- **No-store**: all responses set Cache-Control: no-store.
- **Rate-limited**: per-route limits complement global throttles.

Settings (optional; sensible defaults used if absent)
-----------------------------------------------------
- WEBAUTHN_RP_ID: str               (fallback: request host)
- WEBAUTHN_ORIGIN: str              (e.g., "https://app.moviesnow.example")
- WEBAUTHN_RP_NAME: str             (fallback: settings.PROJECT_NAME or "MoviesNow")
- WEBAUTHN_CHALLENGE_TTL_SECONDS: int (default 300)
- WEBAUTHN_REQUIRE_STEP_UP: bool    (default True for registration/credential mgmt)

DB model expected
-----------------
`app.db.models.webauthn.WebAuthnCredential` with at least:
  - id (pk), user_id (UUID), credential_id (str, base64url), public_key (bytes or str),
    sign_count (int), transports (JSON/list[str]), aaguid (str|None),
    nickname (str|None), created_at (datetime), last_used_at (datetime|None)

If your model differs, adapt the tiny mapping parts below.
"""

import base64
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status, Body, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.redis_client import redis_wrapper
from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.db.session import get_async_db
from app.db.models.user import User
from app.security_headers import set_sensitive_cache
from app.dependencies.step_up import require_step_up
from app.services.audit_log_service import log_audit_event
from app.schemas.auth import (
    RegistrationOptionsResponse,
    RegistrationVerifyRequest,
    AssertionOptionsRequest,
    RegistrationVerifyResponse,
    AssertionOptionsResponse,
    AssertionVerifyRequest,
    CredentialsListResponse,
    CredentialItem
)
# Optional: enum of audit actions if you have one; otherwise use plain strings.
try:
    from app.services.audit_log_service import AuditEvent
    AE = AuditEvent
except Exception:  # pragma: no cover
    class AE:
        WEBAUTHN_REG_OPTIONS = "WEBAUTHN_REG_OPTIONS"
        WEBAUTHN_REG_VERIFY = "WEBAUTHN_REG_VERIFY"
        WEBAUTHN_ASSERTION_OPTIONS = "WEBAUTHN_ASSERTION_OPTIONS"
        WEBAUTHN_ASSERTION_VERIFY = "WEBAUTHN_ASSERTION_VERIFY"
        WEBAUTHN_CREDENTIALS_LIST = "WEBAUTHN_CREDENTIALS_LIST"
        WEBAUTHN_CREDENTIAL_DELETE = "WEBAUTHN_CREDENTIAL_DELETE"

# Service adapter (wraps python-fido2 / py_webauthn under the hood)
from app.services.auth.webauthn_service import (
    begin_registration,
    finish_registration,
    begin_assertion,
    finish_assertion,
    b64url,
    extract_challenge_from_client_data,
)

router = APIRouter(tags=["Passkeys / WebAuthn"])

# ──────────────────────────────────────────────────────────────
# Config & Redis keys
# ──────────────────────────────────────────────────────────────

CHALLENGE_TTL = int(getattr(settings, "WEBAUTHN_CHALLENGE_TTL_SECONDS", 300))
REQUIRE_STEP_UP = bool(getattr(settings, "WEBAUTHN_REQUIRE_STEP_UP", True))

REG_CHAL_KEY = lambda chall: f"webauthn:reg:chall:{chall}"
AUTH_CHAL_KEY = lambda chall: f"webauthn:auth:chall:{chall}"

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _rp_tuple(request: Request) -> tuple[str, str, str]:
    """Resolve (rp_id, origin, rp_name)."""
    rp_id = getattr(settings, "WEBAUTHN_RP_ID", None)
    origin = getattr(settings, "WEBAUTHN_ORIGIN", None)
    rp_name = getattr(settings, "WEBAUTHN_RP_NAME", None) or getattr(settings, "PROJECT_NAME", None) or "MoviesNow"

    # Safe fallbacks
    if not rp_id:
        # Derive from host; WebAuthn libs typically require a domain + no port.
        host = request.url.hostname or "localhost"
        rp_id = host
    if not origin:
        scheme = "https" if (request.url.scheme == "https") else "http"
        origin = f"{scheme}://{request.url.netloc}"
    return (rp_id, origin, rp_name)

async def _redis_setex(key: str, ttl: int, value: str) -> None:
    """SETEX with best-effort discipline."""
    r = getattr(redis_wrapper, "client", None)
    if not r:
        raise HTTPException(status_code=503, detail="KV unavailable")
    try:
        await r.setex(key, ttl, value)
    except Exception:
        raise HTTPException(status_code=503, detail="KV unavailable")

async def _redis_getdel(key: str) -> Optional[str]:
    """GET then DEL (best effort)."""
    r = getattr(redis_wrapper, "client", None)
    if not r:
        return None
    try:
        val = await r.get(key)
        # Remove regardless; a one-time challenge
        try:
            await r.delete(key)
        finally:
            pass
        return val.decode() if isinstance(val, (bytes, bytearray)) else val
    except Exception:
        return None
    
# ──────────────────────────────────────────────────────────────
# DB helpers (minimal impedance to your model)
# ──────────────────────────────────────────────────────────────

def _model():
    """Import once; fail loud if missing so you notice at boot."""
    from app.db.models.webauthn import WebAuthnCredential  # type: ignore
    return WebAuthnCredential

async def _list_user_credentials(db: AsyncSession, user_id) -> List[Any]:
    M = _model()
    q = select(M).where(M.user_id == user_id)
    return (await db.execute(q)).scalars().all()

async def _get_credential_by_credential_id(db: AsyncSession, credential_id: str) -> Optional[Any]:
    M = _model()
    q = select(M).where(M.credential_id == credential_id)
    return (await db.execute(q)).scalar_one_or_none()

# ──────────────────────────────────────────────────────────────
# POST /webauthn/registration/options
# ──────────────────────────────────────────────────────────────

@router.post(
    "/webauthn/registration/options",
    response_model=RegistrationOptionsResponse,
    summary="Begin WebAuthn registration (passkey add) — step-up required",
)
@rate_limit("20/minute")
async def webauthn_registration_options(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    _reauth=Depends(require_step_up()),  # require recent auth
) -> RegistrationOptionsResponse:
    """
    Begin a **passkey registration** ceremony.

    Security
    --------
    - Requires a **step-up** token and binds challenge to the current session lineage.
    - Excludes already-registered credential IDs for this user.
    - Saves a one-time challenge in Redis (TTL ~= 5 min).
    """
    set_sensitive_cache(response)
    rp_id, origin, rp_name = _rp_tuple(request)

    existing = await _list_user_credentials(db, current_user.id)
    exclude_ids = [c.credential_id for c in existing] if existing else []

    opts = begin_registration(
        user_id=str(current_user.id),
        username=current_user.email,  # or another stable handle
        rp_id=rp_id,
        rp_name=rp_name,
        origin=origin,
        exclude_credential_ids=exclude_ids,
    )
    # Persist challenge keyed by the exact challenge value for one-time retrieval
    chall = opts["challenge"]
    payload = json.dumps({"uid": str(current_user.id), "sid": _reauth.get("session_id")})
    await _redis_setex(REG_CHAL_KEY(chall), CHALLENGE_TTL, payload)

    try:
        await log_audit_event(db, action=getattr(AE, "WEBAUTHN_REG_OPTIONS", "WEBAUTHN_REG_OPTIONS"),
                              user=current_user, status="SUCCESS", request=request)
    except Exception:
        pass
    return RegistrationOptionsResponse(publicKey=opts)

# ──────────────────────────────────────────────────────────────
# POST /webauthn/registration/verify
# ──────────────────────────────────────────────────────────────

@router.post(
    "/webauthn/registration/verify",
    response_model=RegistrationVerifyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Finish WebAuthn registration (verify attestation) — step-up required",
)
@rate_limit("20/minute")
async def webauthn_registration_verify(
    payload: RegistrationVerifyRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    _reauth=Depends(require_step_up()),
) -> RegistrationVerifyResponse:
    """
    Finish a **passkey registration** ceremony.

    Validation
    ----------
    - Extract challenge from `clientDataJSON`, fetch + consume expected challenge from Redis.
    - Require the Redis record user_id = current_user and session binding match.
    - Verify attestation with the WebAuthn library and store credential on success.
    """
    set_sensitive_cache(response)
    rp_id, origin, _ = _rp_tuple(request)

    challenge = extract_challenge_from_client_data(payload.credential.response)
    if not challenge:
        raise HTTPException(status_code=400, detail="Invalid client data")

    chall_blob = await _redis_getdel(REG_CHAL_KEY(challenge))
    if not chall_blob:
        raise HTTPException(status_code=400, detail="Registration challenge not found or expired")
    try:
        record = json.loads(chall_blob)
    except Exception:
        raise HTTPException(status_code=400, detail="Challenge state invalid")

    if str(record.get("uid")) != str(current_user.id):
        raise HTTPException(status_code=403, detail="Challenge does not belong to this user")
    if str(record.get("sid") or "") != str(_reauth.get("session_id") or ""):
        raise HTTPException(status_code=401, detail="Step-up/session mismatch")

    # Verify and produce canonical credential fields
    verified = finish_registration(
        credential=payload.credential.model_dump(mode="json"),
        rp_id=rp_id,
        origin=origin,
    )
    # Persist in DB
    M = _model()
    obj = M(
        user_id=current_user.id,
        credential_id=verified["credential_id"],
        public_key=verified["public_key"],  # bytes or JWK per your model
        sign_count=verified["sign_count"],
        transports=verified.get("transports") or [],
        aaguid=verified.get("aaguid"),
        nickname=payload.nickname,
        created_at=_now_utc(),
        last_used_at=None,
    )
    db.add(obj)
    await db.commit()

    try:
        await log_audit_event(db, action=getattr(AE, "WEBAUTHN_REG_VERIFY", "WEBAUTHN_REG_VERIFY"),
                              user=current_user, status="SUCCESS", request=request,
                              meta_data={"credential_id": verified["credential_id"], "aaguid": verified.get("aaguid")})
    except Exception:
        pass

    return RegistrationVerifyResponse(
        id=verified["credential_id"],
        nickname=payload.nickname,
        aaguid=verified.get("aaguid"),
        transports=verified.get("transports"),
        sign_count=verified["sign_count"],
        created_at=obj.created_at,
    )

# ──────────────────────────────────────────────────────────────
# POST /webauthn/assertion/options
# ──────────────────────────────────────────────────────────────

@router.post(
    "/webauthn/assertion/options",
    response_model=AssertionOptionsResponse,
    summary="Begin WebAuthn assertion (sign-in / step-up)",
)
@rate_limit("30/minute")
async def webauthn_assertion_options(
    request: Request,
    response: Response,
    body: AssertionOptionsRequest = Body(default_factory=AssertionOptionsRequest),
    db: AsyncSession = Depends(get_async_db),
) -> AssertionOptionsResponse:
    """
    Begin a **passkey assertion** ceremony for sign-in or step-up.

    Behavior
    --------
    - If `username` is provided, we add `allowCredentials` for that user’s passkeys.
      Otherwise, we return discoverable options (empty allowCredentials).
    - Challenge saved in Redis by its value (single-use; TTL ≈ 5 min).
    """
    set_sensitive_cache(response)
    rp_id, origin, _ = _rp_tuple(request)

    allow_ids: List[str] = []
    user_id_for_log: Optional[str] = None

    if body.username:
        # Look up user and allow only their credential IDs (safer UX)
        from app.db.models.user import User  # reuse your model
        q = select(User).where(
            (User.email == body.username) | (getattr(User, "username", None) == body.username)  # email or username
        )
        user = (await db.execute(q)).scalars().first()
        if user:
            user_id_for_log = str(user.id)
            creds = await _list_user_credentials(db, user.id)
            allow_ids = [c.credential_id for c in creds] if creds else []

    opts = begin_assertion(
        rp_id=rp_id,
        origin=origin,
        allow_credential_ids=None if body.discoverable else allow_ids,
        user_verification=body.user_verification,
    )
    chall = opts["challenge"]
    payload = json.dumps({"user_hint": body.username, "uid": user_id_for_log})
    await _redis_setex(AUTH_CHAL_KEY(chall), CHALLENGE_TTL, payload)

    try:
        await log_audit_event(db, action=getattr(AE, "WEBAUTHN_ASSERTION_OPTIONS", "WEBAUTHN_ASSERTION_OPTIONS"),
                              user=None, status="SUCCESS", request=request,
                              meta_data={"user_hint": body.username, "has_allow": bool(allow_ids)})
    except Exception:
        pass
    return AssertionOptionsResponse(publicKey=opts)

# ──────────────────────────────────────────────────────────────
# POST /webauthn/assertion/verify
# ──────────────────────────────────────────────────────────────

@router.post(
    "/webauthn/assertion/verify",
    summary="Finish WebAuthn assertion (verify authentication)",
)
@rate_limit("30/minute")
async def webauthn_assertion_verify(
    payload: AssertionVerifyRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
) -> Dict[str, Any]:
    """
    Finish a **passkey assertion** ceremony.

    Output contract
    ---------------
    - Returns `{ "ok": true, "user_id": "<uuid>", "credential_id": "<id>" }` on success.
      Your login/step-up flow should create session tokens (access/refresh) or
      reauth tokens based on this.
    """
    set_sensitive_cache(response)
    rp_id, origin, _ = _rp_tuple(request)

    challenge = extract_challenge_from_client_data(payload.credential.response)
    if not challenge:
        raise HTTPException(status_code=400, detail="Invalid client data")

    chall_blob = await _redis_getdel(AUTH_CHAL_KEY(challenge))
    if not chall_blob:
        raise HTTPException(status_code=400, detail="Assertion challenge not found or expired")
    try:
        meta = json.loads(chall_blob)
    except Exception:
        meta = {}

    # We need the stored credential (public key, sign count, etc.)
    cred_id = payload.credential.id
    cred_row = await _get_credential_by_credential_id(db, cred_id)
    if not cred_row:
        raise HTTPException(status_code=400, detail="Unknown credential")

    verified = finish_assertion(
        credential=payload.credential.model_dump(mode="json"),
        rp_id=rp_id,
        origin=origin,
        stored_public_key=cred_row.public_key,
        stored_sign_count=int(cred_row.sign_count or 0),
    )

    # Update sign count + last_used_at
    cred_row.sign_count = verified["new_sign_count"]
    cred_row.last_used_at = _now_utc()
    await db.commit()

    try:
        await log_audit_event(db, action=getattr(AE, "WEBAUTHN_ASSERTION_VERIFY", "WEBAUTHN_ASSERTION_VERIFY"),
                              user=None, status="SUCCESS", request=request,
                              meta_data={"credential_id": cred_id, "uid": str(cred_row.user_id)})
    except Exception:
        pass

    # Return a neutral payload that your auth layer can consume to mint tokens.
    return {"ok": True, "user_id": str(cred_row.user_id), "credential_id": cred_id}

# ──────────────────────────────────────────────────────────────
# GET /webauthn/credentials — list current user's passkeys
# ──────────────────────────────────────────────────────────────

@router.get(
    "/webauthn/credentials",
    response_model=CredentialsListResponse,
    summary="List current user's passkeys",
)
@rate_limit("30/minute")
async def list_webauthn_credentials(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> CredentialsListResponse:
    """Return a safe inventory of the caller’s passkeys (no public keys)."""
    set_sensitive_cache(response)
    rows = await _list_user_credentials(db, current_user.id)
    items = [
        CredentialItem(
            id=r.credential_id,
            nickname=getattr(r, "nickname", None),
            aaguid=getattr(r, "aaguid", None),
            transports=list(getattr(r, "transports", []) or []),
            sign_count=int(getattr(r, "sign_count", 0) or 0),
            created_at=getattr(r, "created_at", _now_utc()),
            last_used_at=getattr(r, "last_used_at", None),
        )
        for r in rows
    ]
    try:
        await log_audit_event(db, action=getattr(AE, "WEBAUTHN_CREDENTIALS_LIST", "WEBAUTHN_CREDENTIALS_LIST"),
                              user=current_user, status="SUCCESS", request=request,
                              meta_data={"count": len(items)})
    except Exception:
        pass
    return CredentialsListResponse(total=len(items), credentials=items)

# ──────────────────────────────────────────────────────────────
# DELETE /webauthn/credentials/{id} — delete a passkey
# ──────────────────────────────────────────────────────────────

@router.delete(
    "/webauthn/credentials/{credential_id}",
    summary="Delete a passkey — step-up required",
    status_code=status.HTTP_204_NO_CONTENT,
)
@rate_limit("10/minute")
async def delete_webauthn_credential(
    credential_id: str = Path(..., description="Base64url credential ID"),
    request: Request = None,
    response: Response = None,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    _reauth=Depends(require_step_up()),  # deletion is sensitive
) -> Response:
    """
    Delete a passkey owned by the current user.

    Notes
    -----
    - Consider preventing deletion of the **last** MFA factor if `MFA_ENFORCED`
      (out of scope here since we don’t inspect other factors).
    """
    set_sensitive_cache(response)

    M = _model()
    q = select(M).where(M.user_id == current_user.id, M.credential_id == credential_id)
    row = (await db.execute(q)).scalar_one_or_none()
    if not row:
        # 204 on idempotent delete (don’t reveal existence)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    await db.delete(row)
    await db.commit()

    try:
        await log_audit_event(db, action=getattr(AE, "WEBAUTHN_CREDENTIAL_DELETE", "WEBAUTHN_CREDENTIAL_DELETE"),
                              user=current_user, status="SUCCESS", request=request,
                              meta_data={"credential_id": credential_id})
    except Exception:
        pass

    return Response(status_code=status.HTTP_204_NO_CONTENT)
