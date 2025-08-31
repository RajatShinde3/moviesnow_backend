# app/schemas/auth.py

from pydantic import BaseModel, EmailStr, Field, constr, SecretStr, ConfigDict
from typing import Optional, Union, Dict, List, Any, Literal
from uuid import UUID
from app.schemas.enums import LoginMode, OrgRole
from datetime import datetime, timezone

# ──────────────── Sign Up ────────────────
class SignupPayload(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None



# ──────────────── Login ────────────────
class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    login_mode: LoginMode = LoginMode.PERSONAL
    org_id: Optional[UUID] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    is_active: bool = True


class MFAChallengeResponse(BaseModel):
    mfa_required: bool = True
    mfa_token: str


# ──────────────── Password Reset ────────────────
class PasswordResetEmailRequest(BaseModel):
    email: EmailStr


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: constr(min_length=6, max_length=6)


class PasswordResetConfirm(BaseModel):
    email: EmailStr
    new_password: constr(min_length=6)
    otp: constr(min_length=6, max_length=6)


# ──────────────── Reactivation ────────────────
class ReactivationRequest(BaseModel):
    email: EmailStr


# ──────────────── MFA ────────────────
class EnableMFAResponse(BaseModel):
    qr_code_url: str
    secret: str


class VerifyMFARequest(BaseModel):
   code: constr(pattern=r"^\d{6,8}$")


class DisableMFARequest(BaseModel):
    password: str


class MFALoginRequest(BaseModel):
    mfa_token: str
    totp_code: constr(min_length=6, max_length=6)


class MFAProtectedActionRequest(BaseModel):
    mfa_token: Optional[str] = None
    code: constr(min_length=6, max_length=6)


# ─────────────────────────────────────────
# 🔄 Refresh & Logout Schemas
# ─────────────────────────────────────────

class RefreshTokenRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str
    revoke_all: bool = False


class TokenRevokeRequest(BaseModel):
    user_id: UUID
    organization_id: Optional[UUID] = None


# ─────────────────────────────────────────────────────────────
# Activity feed models
# ─────────────────────────────────────────────────────────────
class ActivityItem(BaseModel):
    """
    One entry in a user's auth/security activity feed.

    Notes
    -----
    - `ip` and `user_agent` are plain strings (not strict IP types) to avoid
      validation issues when upstream provides bytes/IPv4Address, etc.
    - `geo`, `device`, and `meta` are flexible maps so you can add fields
      without breaking clients.
    """
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = Field(
        None, description="Source event identifier (DB id or ring-buffer uuid)."
    )
    at: datetime = Field(
        ..., description="Event timestamp in UTC."
    )
    action: str = Field(
        ..., min_length=1, description="Action name (e.g., LOGIN_SUCCESS, MFA_CHALLENGE)."
    )
    status: str = Field(
        ..., min_length=1, description="Outcome/status (e.g., SUCCESS, FAILURE)."
    )
    ip: Optional[str] = Field(
        None, description="Client IP address as a string."
    )
    user_agent: Optional[str] = Field(
        None, description="Original or trimmed user agent string."
    )
    geo: Optional[Dict[str, Any]] = Field(
        None, description="Geolocation data (e.g., country, region, city, lat/lon)."
    )
    device: Optional[Dict[str, Any]] = Field(
        None, description="Device details (e.g., os, browser, model)."
    )
    meta: Optional[Dict[str, Any]] = Field(
        None, description="Additional metadata; keys vary by event."
    )


class ActivityResponse(BaseModel):
    """
    Pageless response wrapper for the activity feed.
    """
    model_config = ConfigDict(from_attributes=True)

    total: int = Field(..., ge=0, description="Total number of items returned.")
    items: List[ActivityItem] = Field(
        default_factory=list, description="Activity items in reverse chronological order."
    )


class AlertsSubscription(BaseModel):
    """
    User's security alert preferences.

    Defaults
    --------
    All flags default to True, so users receive alerts unless they opt out.
    """
    model_config = ConfigDict(from_attributes=True)

    new_device: bool = Field(
        True, description="Alert on sign-in from a new device."
    )
    new_location: bool = Field(
        True, description="Alert on sign-in from a new location."
    )
    impossible_travel: bool = Field(
        True, description="Alert on sign-ins that imply impossible travel velocity."
    )
    email_notifications: bool = Field(
        True, description="Send alerts via email."
    )
# ──────────────── General Purpose ────────────────
class MessageResponse(BaseModel):
    message: str

class SimpleUserResponse(BaseModel):
    email: EmailStr

class AssignSuperadminResponse(BaseModel):
    message: str
    user: SimpleUserResponse
    role: str

# ---------------------------------------------------------------------------
# Admin role assignment response (ADMIN)
# ---------------------------------------------------------------------------
class AssignADMINResponse(BaseModel):
    """Response model for assigning the ADMIN role to a user.

    Mirrors AssignSuperadminResponse shape for consistency across admin actions.
    """
    message: str
    user: SimpleUserResponse
    role: str

# ---------------------------------------------------------------------------
# Admin role revocation response (USER after revoke)
# ---------------------------------------------------------------------------
class RevokeADMINResponse(BaseModel):
    """Response model for revoking the ADMIN role (demote to USER)."""
    message: str
    user: SimpleUserResponse
    role: str


# ---------------------------------------------------------------------------
# Admin list item (org-free)
# ---------------------------------------------------------------------------
class AdminUserItem(BaseModel):
    id: UUID
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool
    role: str

# ---------------------------------------------------------------------------
# Role update request (org-free)
# ---------------------------------------------------------------------------
class RoleUpdateRequest(BaseModel):
    """Request to update a user's role.

    Accepts roles from `OrgRole` enum (e.g., USER, ADMIN, SUPERUSER).
    """
    role: OrgRole

class ReactivateAccountRequest(BaseModel):
    email: EmailStr
    otp: constr(min_length=6, max_length=6)


class EmailOnlyRequest(BaseModel):
    email: EmailStr


class MFAResetRequest(BaseModel):
    email: EmailStr


class MFAResetConfirm(BaseModel):
    token: str


class SwitchOrgRequest(BaseModel):
    org_id: Optional[UUID] = None


class MFAEnableResponse(BaseModel):
    message: str
    mfa_token: Optional[str] = None
    recovery_codes: Optional[list[str]] = None

# ──────────────── Recovery Codes ────────────────
class RecoveryCodesGenerateResponse(BaseModel):
    batch_id: str
    created_at: datetime
    total: int
    codes: list[str]

class RecoveryCodesPreview(BaseModel):
    batch_id: Optional[str] = None
    created_at: Optional[datetime] = None
    remaining: int
    preview: list[str]

class RecoveryCodeRedeemRequest(BaseModel):
    # Accepts grouped or ungrouped (e.g., ABCDE-FGHIJ or ABCDEFGHIJ)
    code: constr(pattern=r"^[A-Za-z0-9\-]{8,64}$")

class RecoveryCodeRedeemResponse(BaseModel):
    reauth_token: str
    expires_in: int

class ReauthPasswordRequest(BaseModel):
    password: SecretStr

class ReauthMFARequest(BaseModel):
    code: constr(pattern=r"^\d{6,8}$")

class ReauthTokenResponse(BaseModel):
    reauth_token: str
    expires_in: int  # seconds

class TrustedDeviceItem(BaseModel):
    id: str = Field(..., description="Server-issued device id (UUID4-as-string).")
    created_at: Optional[datetime] = Field(
        None, description="When the device was first registered as trusted (UTC)."
    )
    last_seen: Optional[datetime] = Field(
        None, description="Last successful use/refresh of this device (UTC)."
    )
    ua_hash: Optional[str] = Field(
        None, description="Privacy-preserving hash of the user agent (base64url)."
    )
    ip: Optional[str] = Field(
        None, description="Anonymized IP/network for the device (display only)."
    )
    expires_at: Optional[datetime] = Field(
        None, description="When this trust record expires and becomes invalid (UTC)."
    )

    model_config = ConfigDict(
        from_attributes=True,
        ser_json_timedelta="iso8601",  # for timedelta fields if any
    )


class TrustedDevicesList(BaseModel):
    total: int = Field(..., ge=0, description="Total number of trusted devices listed.")
    devices: List[TrustedDeviceItem] = Field(
        default_factory=list, description="Trusted device records (most-recent first)."
    )

    model_config = ConfigDict(
        from_attributes=True,
    )


class RevokeResult(BaseModel):
    revoked: int = Field(..., ge=0, description="How many trusted devices were revoked.")

    model_config = ConfigDict(from_attributes=True)


class SessionItem(BaseModel):
    """
    One active refresh-token session handle.

    Fields
    ------
    jti:          Refresh token JTI (opaque identifier; never the token itself)
    created_at:   When the refresh token was created (UTC)
    expires_at:   When the refresh token expires (UTC)
    ip_address:   Last known client IP (from metadata or DB)
    user_agent:   Last known User-Agent (from metadata)
    last_seen:    Best-effort last activity timestamp (from metadata)
    session_id:   Logical session lineage ID (often equals first JTI in chain)
    current:      Whether this entry represents the caller’s current session
    """
    jti: str = Field(..., description="Refresh token JTI")
    created_at: datetime = Field(..., description="Creation timestamp (UTC)")
    expires_at: datetime = Field(..., description="Expiry timestamp (UTC)")
    ip_address: Optional[str] = Field(None, description="Client IP (best-effort)")
    user_agent: Optional[str] = Field(None, description="User-Agent (best-effort)")
    last_seen: Optional[datetime] = Field(None, description="Last activity (best-effort)")
    session_id: Optional[str] = Field(None, description="Session lineage identifier")
    current: bool = Field(False, description="True if this is the current session")

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )



class SessionsListResponse(BaseModel):
    """
    Wrapper for session inventory responses.
    """
    total: int = Field(..., ge=0, description="Number of sessions returned")
    sessions: List[SessionItem] = Field(default_factory=list, description="Session entries")

    model_config = ConfigDict(from_attributes=True)




# ──────────────── Current User Response ────────────────
class ActiveOrgInfo(BaseModel):
    org_id: UUID
    role: str


class MeResponse(BaseModel):
    id: UUID
    email: str
    full_name: Optional[str]
    is_active: bool
    mfa_enabled: bool
    mfa_authenticated: bool
    active_org: Optional[ActiveOrgInfo]


# ──────────────── JWT Payload (used in token introspection) ────────────────

class TokenPayload(BaseModel):
    sub: str
    exp: int | datetime
    jti: str
    token_type: Optional[str] = None  # "access" | "refresh" | "mfa_token"
    iat: Optional[int | datetime] = None
    nbf: Optional[int | datetime] = None
    iss: Optional[str] = None
    aud: Optional[str] = None

    # org context
    active_org_id: Optional[UUID] = None
    org_id: Optional[UUID] = None
    org_role: Optional[str] = None
    active_org: Optional[dict] = None  # keep generic to avoid circular import

    # auth context
    mfa_authenticated: Optional[bool] = False
    session_id: Optional[UUID] = None
    login_mode: Optional[str] = None  # "personal" | "organization"

    # impersonation (optional)
    is_impersonated: Optional[bool] = False
    impersonated_by: Optional[UUID] = None
    impersonated_by_email: Optional[str] = None
    impersonation_started_at: Optional[datetime] = None


class OrgSwitcherOption(BaseModel):
    org_id: UUID
    org_name: str
    role: str


class OrgInviteInfoResponse(BaseModel):
    organization_id: UUID
    organization_name: str
    inviter_email: Optional[str]
    inviter_full_name: Optional[str]
    invited_email: str
    invited_role: OrgRole
    created_at: datetime
    expires_at: datetime

    model_config = {
        "from_attributes": True
    }

class PasswordChangeIn(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, description="At least 8 chars; enforce org policy as needed")

class EmailChangeStartIn(BaseModel):
    new_email: EmailStr
    current_password: Optional[str] = Field(None, description="Optional extra check; recommended to include")

class EmailChangeConfirmIn(BaseModel):
    token: str = Field(..., min_length=16, max_length=512)


class PublicKeyCredential(BaseModel):
    """Generic WebAuthn credential envelope from browser."""
    id: str
    rawId: str
    type: Literal["public-key"]
    response: Dict[str, Any]
    clientExtensionResults: Optional[Dict[str, Any]] = None
    authenticatorAttachment: Optional[str] = None
    model_config = ConfigDict(extra="allow")

class RegistrationOptionsResponse(BaseModel):
    publicKey: Dict[str, Any]  # The actual options object; property name matches WebAuthn spec.

class RegistrationVerifyRequest(BaseModel):
    credential: PublicKeyCredential
    nickname: Optional[str] = Field(None, description="Optional display name for this passkey")

class RegistrationVerifyResponse(BaseModel):
    id: str
    nickname: Optional[str] = None
    aaguid: Optional[str] = None
    transports: Optional[List[str]] = None
    sign_count: int
    created_at: datetime

class AssertionOptionsRequest(BaseModel):
    username: Optional[str] = Field(None, description="Email/username to narrow allowCredentials; omit for discoverable")
    discoverable: bool = Field(True, description="Allow discoverable credentials (allowCredentials empty)")
    user_verification: Literal["required", "preferred", "discouraged"] = "preferred"

class AssertionOptionsResponse(BaseModel):
    publicKey: Dict[str, Any]

class AssertionVerifyRequest(BaseModel):
    credential: PublicKeyCredential

class CredentialItem(BaseModel):
    id: str
    nickname: Optional[str] = None
    aaguid: Optional[str] = None
    transports: Optional[List[str]] = None
    sign_count: int
    created_at: datetime
    last_used_at: Optional[datetime] = None

class CredentialsListResponse(BaseModel):
    total: int
    credentials: List[CredentialItem]


