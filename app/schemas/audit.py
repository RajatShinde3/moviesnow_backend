# app/schemas/audit.py
from __future__ import annotations

"""
Pydantic schemas for Audit Logs — MoviesNow
===========================================

Outward‑facing response models matching the admin API and services. These are
**org‑free** and map the DB model's `occurred_at` to the API field `timestamp`.

Notes
-----
- Uses Pydantic v2 style with `from_attributes=True` for ORM compatibility.
- `ip_address` accepts either IPv4 or IPv6.
- `meta_data` is a free‑form JSON object (already scrubbed by the service).
"""

from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict, IPvAnyAddress


class AuditLogOut(BaseModel):
    """Single audit log record returned by the API.

    Fields
    ------
    id
        Primary key of the audit log.
    user_id
        Actor's user ID, if available.
    action
        Action keyword (e.g., `LOGIN`, `PLAYBACK_PLAY`).
    status
        Outcome string, typically `SUCCESS` or `FAILURE`.
    timestamp
        UTC time the event occurred (DB‑driven; from model's `occurred_at`).
    ip_address
        Client IP address (IPv4/IPv6).
    user_agent
        Raw User‑Agent string, when provided.
    meta_data
        Scrubbed, JSON‑serializable context for the event.
    request_id
        Correlation ID for tracing this request across services.
    """

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(..., description="Audit log ID")
    user_id: Optional[UUID] = Field(None, description="Actor user ID, if present")
    action: str = Field(..., min_length=1, max_length=64, description="Action keyword")
    status: str = Field(..., min_length=1, max_length=32, description="Outcome (e.g., SUCCESS / FAILURE)")
    timestamp: datetime = Field(..., description="UTC time the event occurred (from `occurred_at`)")
    ip_address: Optional[IPvAnyAddress] = Field(None, description="Client IP address (IPv4/IPv6)")
    user_agent: Optional[str] = Field(None, description="HTTP User-Agent string")
    meta_data: Optional[Dict[str, Any]] = Field(None, description="Structured, scrubbed context for the event")
    request_id: Optional[str] = Field(None, description="Correlation ID for distributed tracing")


# Optional alias for convenience (if some modules import `AuditOut`)
AuditOut = AuditLogOut


__all__ = ["AuditLogOut", "AuditOut"]
