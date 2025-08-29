# app/schemas/auth.py

from pydantic import BaseModel, EmailStr, Field, constr, SecretStr, ConfigDict
from typing import Optional, Union, Dict, List
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


# ──────────────── General Purpose ────────────────
class MessageResponse(BaseModel):
    message: str

class SimpleUserResponse(BaseModel):
    email: EmailStr

class AssignSuperadminResponse(BaseModel):
    message: str
    user: SimpleUserResponse
    role: str

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
        json_encoders={datetime: lambda v: v.isoformat()},
    )


class TrustedDevicesList(BaseModel):
    total: int = Field(..., ge=0, description="Total number of trusted devices listed.")
    devices: List[TrustedDeviceItem] = Field(
        default_factory=list, description="Trusted device records (most-recent first)."
    )

    model_config = ConfigDict(
        from_attributes=True,
        json_encoders={datetime: lambda v: v.isoformat()},
    )


class RevokeResult(BaseModel):
    revoked: int = Field(..., ge=0, description="How many trusted devices were revoked.")

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
