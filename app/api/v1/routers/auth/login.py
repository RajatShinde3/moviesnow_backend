
"""
Authentication & Organization API — hardened, production-grade
=============================================================

Endpoints
---------
POST /login
    Email+password sign-in. If the user has MFA enabled, returns an MFA
    challenge. Otherwise returns access+refresh tokens.

POST /mfa-login
    Completes the MFA flow: validates the short-lived MFA token + TOTP and
    issues access+refresh tokens.

POST /switch-org
    Switch the active organization context for the authenticated user with MFA.

GET  /my-orgs
    List organizations the authenticated user belongs to (for org switcher UI).

Security & DX
-------------
- **Route rate limits** complement Redis throttles inside services.
- **Sensitive cache headers** applied on token-issuing routes (no-store).
- **Auth logic delegated** to hardened services in `app.services.auth.login_service`.
- Neutral errors; thorough audit is done inside the service layer and switch-org.
"""

import json
import logging
from datetime import datetime, timezone
from typing import List, Optional, Union
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import get_current_user_with_mfa
from app.core.limiter import rate_limit
from app.core.redis_client import redis_wrapper
from app.core.security import create_access_token, create_refresh_token
from app.db.models.organization import Organization
from app.db.models.user import User
from app.db.models.user_organization import UserOrganization
from app.db.session import get_async_db
from app.schemas.auth import (
    LoginRequest,
    MFAChallengeResponse,
    MFALoginRequest,
    OrgSwitcherOption,
    SwitchOrgRequest,
    TokenResponse,
)
from app.security_headers import set_sensitive_cache
from app.services.auth.login_service import login_user, login_with_mfa
from app.services.token_service import store_refresh_token
from app.utils.audit import AuditEventType, log_org_event

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Authentication & Organization"])


# ──────────────────────────────────────────────────────────────
# 🔐 POST /login — Email + Password (MFA-aware)
# ──────────────────────────────────────────────────────────────
@router.post("/login", response_model=Union[TokenResponse, MFAChallengeResponse], summary="Email + password login")
@rate_limit("5/minute")
async def login(
    request: Request,
    response: Response,
    payload: LoginRequest = Body(...),
    db: AsyncSession = Depends(get_async_db),
) -> Union[TokenResponse, MFAChallengeResponse]:
    """
    Authenticate with email/password.

    Behavior
    --------
    - If the account has **MFA enabled**, returns an `MFAChallengeResponse` containing
      a short-lived token for the next step (`/mfa-login`).
    - Otherwise returns **access** + **refresh** tokens.

    Security
    --------
    - Marks the response **no-store** (so tokens are not cached).
    - Per-email and per-IP throttles executed inside `login_user`.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Delegate to login service ───────────────────────────────────
    result = await login_user(payload=payload, db=db, request=request)

    # IMPORTANT: return the Pydantic model (not JSONResponse) so the headers set
    # on `response` (e.g., Cache-Control: no-store) are preserved by FastAPI.
    return result


# ──────────────────────────────────────────────────────────────
# 🔐 POST /mfa-login — Finalize MFA with challenge + TOTP
# ──────────────────────────────────────────────────────────────
@router.post("/mfa-login", response_model=TokenResponse, summary="Finalize MFA and issue tokens")
@rate_limit("5/minute")
async def mfa_login(
    request: Request,
    response: Response,
    payload: MFALoginRequest = Body(...),
    db: AsyncSession = Depends(get_async_db),
) -> TokenResponse:
    """
    Validate MFA challenge + TOTP and issue tokens.

    Security
    --------
    - Marks the response **no-store** (so tokens are not cached).
    - Rate limiting and audit handled in service.
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] Delegate to service ─────────────────────────────────────────
    result = await login_with_mfa(payload, db, request)

    # Same note as /login about preserving headers.
    return result


# ──────────────────────────────────────────────────────────────
# 🎯 POST /switch-org — Switch active org and mint scoped tokens
# ──────────────────────────────────────────────────────────────
@router.post(
    "/switch-org",
    response_model=TokenResponse,
    status_code=200,
    summary="Switch active organization and mint scoped tokens",
)
@rate_limit("10/minute")
async def switch_org(
    payload: SwitchOrgRequest,
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user_with_mfa),
    db: AsyncSession = Depends(get_async_db),
) -> TokenResponse:
    """
    Switch the **active organization** for the current user and mint **scoped tokens**.

    Security & UX
    -------------
    - Requires an **MFA-authenticated** session (`get_current_user_with_mfa`).
    - Validates the caller's membership in the target organization.
    - **Refresh first** → derive a stable `session_id` (session lineage).
    - Registers the session in Redis: `session:{user_id}` and `sessionmeta:{jti}` (TTL = refresh expiry).
    - Issues an **access token bound to `session_id`** and **scoped** via `active_org`.

    Returns
    -------
    TokenResponse: `{ access_token, refresh_token, token_type }`
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    org_id: Optional[UUID] = payload.org_id

    # ── [Step 1] Resolve & validate target organization ──────────────────────
    if org_id:
        row = (
            await db.execute(
                select(UserOrganization.role, UserOrganization.organization_id).where(
                    UserOrganization.user_id == current_user.id,
                    UserOrganization.organization_id == org_id,
                    UserOrganization.is_active == True,  # noqa: E712
                )
            )
        ).first()
        if not row:
            logger.warning("[SwitchOrg] User %s tried unauthorized org %s", current_user.id, org_id)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not a member of this organization.")
        role = row.role
        org_id = row.organization_id
    else:
        rows = (
            await db.execute(
                select(UserOrganization.role, UserOrganization.organization_id).where(
                    UserOrganization.user_id == current_user.id,
                    UserOrganization.is_active == True,  # noqa: E712
                )
            )
        ).all()
        if len(rows) != 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="org_id is required if user belongs to multiple organizations.",
            )
        role = rows[0].role
        org_id = rows[0].organization_id

    active_org = {"org_id": str(org_id), "role": role}

    # ── [Step 2] Mint refresh first and derive session lineage ───────────────
    refresh_data = await create_refresh_token(current_user.id)
    session_id = refresh_data.get("session_id") or refresh_data["jti"]

    # ── [Step 3] Register session & metadata in Redis (best-effort) ──────────
    try:
        r = redis_wrapper.client
        await r.sadd(f"session:{current_user.id}", refresh_data["jti"])
        ttl = max(0, int((refresh_data["expires_at"] - datetime.now(timezone.utc)).total_seconds()))
        await r.hset(
            f"sessionmeta:{refresh_data['jti']}",
            mapping={
                "session_id": session_id,
                "ip": (request.client.host if request.client else "") or "",
                "ua": (request.headers.get("User-Agent") or ""),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_seen": datetime.now(timezone.utc).isoformat(),
            },
        )
        await r.expire(f"sessionmeta:{refresh_data['jti']}", ttl)
    except Exception:
        # Never fail the switch on Redis hiccups
        pass

    # ── [Step 4] Persist refresh token (hashed at rest) ───────────────────────
    await store_refresh_token(
        db=db,
        user_id=current_user.id,
        token=refresh_data["token"],
        jti=refresh_data["jti"],
        expires_at=refresh_data["expires_at"],
        parent_jti=refresh_data.get("parent_jti"),
        ip_address=(request.client.host if request.client else None),
    )

    # ── [Step 5] Mint access token scoped to org & bound to session ──────────
    access_token = await create_access_token(
        user_id=current_user.id,
        active_org=active_org,
        mfa_authenticated=True,  # enforced by dependency
        session_id=session_id,
    )

    # ── [Step 6] Activity ring buffer (best-effort) ──────────────────────────
    try:
        evt = {
            "id": refresh_data["jti"],
            "at": datetime.now(timezone.utc).isoformat(),
            "action": "SWITCH_ORG",
            "status": "SUCCESS",
            "ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("User-Agent"),
            "meta": {"session_id": session_id, "org_id": str(org_id)},
        }
        key = f"audit:recent:{current_user.id}"
        r = redis_wrapper.client
        await r.rpush(key, json.dumps(evt))
        await r.ltrim(key, -int(getattr(settings, "ACTIVITY_RING_MAX", 200)), -1)
    except Exception:
        pass

    # ── [Step 7] Org audit log (if available) ────────────────────────────────
    try:
        await log_org_event(
            db=db,
            organization_id=org_id,
            actor_id=current_user.id,
            action=AuditEventType.SWITCH_ORG,
            description=f"Switched to organization {org_id}",
            request=request,
            meta_data={"switched_to_org_id": str(org_id)},
        )
    except Exception:
        # Keep non-fatal — token issuance already succeeded
        logger.info("[SwitchOrg] Audit emit skipped (non-fatal) for user %s org %s", current_user.id, org_id)

    logger.info("[SwitchOrg] User %s switched to org %s successfully", current_user.id, org_id)

    # ── [Step 8] Respond ─────────────────────────────────────────────────────
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_data["token"],
        token_type="bearer",
        # keep if your TokenResponse schema includes `is_active`
        is_active=getattr(current_user, "is_active", True),
    )


# ──────────────────────────────────────────────────────────────
# 🏢 GET /my-orgs — List user orgs for switcher UI
# ──────────────────────────────────────────────────────────────
@router.get(
    "/my-orgs",
    response_model=List[OrgSwitcherOption],
    summary="List organizations you belong to (for org switcher)",
    tags=["Organizations", "Authentication"],
)
async def list_user_orgs_for_switching(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user_with_mfa),
) -> List[OrgSwitcherOption]:
    """
    Return organizations that the current user can switch into.

    Notes
    -----
    - Selects a minimal set of fields and **orders by organization name** for UX.
    - Protected by `get_current_user_with_mfa` so the same session semantics apply.
    """
    # ── [Step 1] Query memberships joined to org names ───────────────────────
    q = (
        select(
            UserOrganization.organization_id,
            UserOrganization.role,
            Organization.name.label("org_name"),
        )
        .join(Organization, Organization.id == UserOrganization.organization_id)
        .where(
            UserOrganization.user_id == current_user.id,
            UserOrganization.is_active == True,  # noqa: E712
        )
        .order_by(Organization.name)
    )
    rows = (await db.execute(q)).all()

    # ── [Step 2] Map to response schema ──────────────────────────────────────
    return [
        OrgSwitcherOption(org_id=row.organization_id, org_name=row.org_name, role=(row.role or "").upper())
        for row in rows
    ]


__all__ = [
    "router",
    "login",
    "mfa_login",
    "switch_org",
    "list_user_orgs_for_switching",
]
