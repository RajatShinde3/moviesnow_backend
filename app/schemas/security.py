from __future__ import annotations

"""
Security-related Pydantic models for OAuth2 and API Keys.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


# -- OAuth2: client_credentials ------------------------------------------------

class ClientCredentialsRequest(BaseModel):
    grant_type: str = Field(default="client_credentials", pattern="^client_credentials$")
    scope: Optional[str] = None  # space-delimited


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    scope: Optional[str] = None


class IntrospectionResponse(BaseModel):
    active: bool
    scope: Optional[str] = None
    client_id: Optional[str] = None
    token_type: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    nbf: Optional[int] = None
    sub: Optional[str] = None
    iss: Optional[str] = None
    aud: Optional[str] = None
    jti: Optional[str] = None
    alg: Optional[str] = None


class RevokeRequest(BaseModel):
    token: str
    token_type_hint: Optional[str] = None


# -- Admin API Keys ------------------------------------------------------------

class APIKeyCreate(BaseModel):
    label: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)
    ttl_days: Optional[int] = Field(default=None, ge=0, description="0 or None for no expiry")


class APIKeyOut(BaseModel):
    id: str
    label: str
    scopes: List[str]
    created_at: str
    expires_at: Optional[str] = None
    disabled: bool = False
    prefix: str
    # secrets are returned only at creation/rotation
    secret: Optional[str] = None


class APIKeyUpdate(BaseModel):
    label: Optional[str] = None
    scopes: Optional[List[str]] = None
    disabled: Optional[bool] = None
    rotate: bool = False
    ttl_days: Optional[int] = Field(default=None, ge=0)


__all__ = [
    "ClientCredentialsRequest",
    "TokenResponse",
    "IntrospectionResponse",
    "RevokeRequest",
    "APIKeyCreate",
    "APIKeyOut",
    "APIKeyUpdate",
]

