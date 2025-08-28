
"""
User Info API — hardened, production‑grade
=========================================

Endpoints
---------
GET  /me/
    Return the authenticated user's profile + current active organization
    (derived from the access-token payload). Response is marked **no‑store**.

GET  /me/organization-memberships
    List organizations the user belongs to. Uses efficient relationship
    loading and emits audit events (one per membership by default).

Security & Hardening
--------------------
- **No-store** cache headers on all responses (tokens and PII involved).
- **Rate limiting** on both endpoints to curb scraping/abuse.
- Efficient querying with ``selectinload`` to avoid N+1.
- Clear, typed responses using your Pydantic schemas.
"""

from typing import Tuple, List, Optional
import logging

from fastapi import APIRouter, Depends, Request, Response, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.dependencies import get_current_user_with_token_payload, get_current_user_with_mfa
from app.core.limiter import rate_limit
from app.db.models.organization import Organization
from app.db.models.user import User
from app.db.models.user_organization import UserOrganization
from app.db.session import get_async_db
from app.schemas.auth import ActiveOrgInfo, MeResponse, TokenPayload
from app.schemas.enums import OrgRole
from app.schemas.organization import MyOrganizationResponse
from app.security_headers import set_sensitive_cache
from app.utils.audit import AuditEventType, log_org_event

router = APIRouter(prefix="/me", tags=["Me"])  # grouped under Me
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# 👤 GET CURRENT USER PROFILE
# ─────────────────────────────────────────────────────────────
@router.get("/", response_model=MeResponse, summary="Get current user's profile")
@rate_limit("60/minute")
async def get_me(
    request: Request,
    response: Response,
    user_and_token: Tuple[User, TokenPayload] = Depends(get_current_user_with_token_payload),
) -> MeResponse:
    """Return the authenticated user's profile and active organization context.

    Notes
    -----
    - ``active_org`` is derived from the access token payload (authoritative for
      request scope) rather than re-querying memberships here.
    - Response is marked **no-store** to prevent caching of PII/token state.
    """
    set_sensitive_cache(response)

    current_user, token_data = user_and_token

    active_org: Optional[ActiveOrgInfo] = None
    if token_data.active_org:
        active_org = ActiveOrgInfo(
            org_id=token_data.active_org.org_id,
            role=token_data.active_org.role,
        )

    return MeResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        is_active=current_user.is_active,
        mfa_enabled=current_user.mfa_enabled,
        mfa_authenticated=token_data.mfa_authenticated,
        active_org=active_org,
    )


# ─────────────────────────────────────────────────────────────
# 🏢 GET USER'S ORGANIZATION MEMBERSHIPS
# ─────────────────────────────────────────────────────────────
@router.get(
    "/organization-memberships",
    response_model=List[MyOrganizationResponse],
    summary="List organizations for the current user",
)
@rate_limit("20/minute")
async def get_my_organization_memberships(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user_with_mfa),
) -> List[MyOrganizationResponse]:
    """Return the organizations the current user belongs to.

    Performance
    -----------
    Uses ``selectinload(UserOrganization.organization)`` to avoid N+1 queries
    when accessing ``uo.organization`` attributes during response mapping.
    """
    set_sensitive_cache(response)

    try:
        stmt = (
            select(UserOrganization)
            .options(selectinload(UserOrganization.organization))
            .where(UserOrganization.user_id == current_user.id)
        )
        result = await db.execute(stmt)
        user_orgs: List[UserOrganization] = result.scalars().all()

        # Emit audit log for each membership viewed (can be batched if noisy)
        for uo in user_orgs:
            try:
                await log_org_event(
                    db=db,
                    organization_id=uo.organization_id,
                    actor_id=str(current_user.id),
                    action=AuditEventType.VIEW_ORG_MEMBERSHIP,
                    description="User viewed their org membership",
                    request=request,
                    meta_data={
                        "user_id": str(current_user.id),
                        "org_id": str(uo.organization_id),
                        "role": uo.role,
                        "is_active": uo.is_active,
                    },
                )
            except Exception:
                # Don't block reads on audit issues
                logger.debug("Audit logging failed for org %s", uo.organization_id, exc_info=True)

        # Map to API schema
        out: List[MyOrganizationResponse] = []
        for uo in user_orgs:
            org: Organization = uo.organization
            out.append(
                MyOrganizationResponse(
                    org_id=uo.organization_id,
                    name=getattr(org, "name", None),
                    slug=getattr(org, "slug", None),
                    role=OrgRole(uo.role.upper()),
                    is_active=uo.is_active,
                    joined_at=uo.joined_at,
                )
            )
        return out

    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to fetch organization memberships for user %s", current_user.id)
        # For reads, rolling back an AsyncSession without a tx is harmless; safe anyway
        try:
            await db.rollback()
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to retrieve organization memberships",
        )


__all__ = ["router", "get_me", "get_my_organization_memberships"]
