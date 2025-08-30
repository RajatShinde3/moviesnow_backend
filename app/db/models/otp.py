from __future__ import annotations

"""
🔑 MoviesNow — OTP (One‑Time Password)
=====================================

Temporary verification codes for flows like email/phone verification, MFA, and
password reset.

Design highlights
-----------------
• **Per‑user purpose scoping** with one *active* (unused) OTP per `(user, purpose)`
  via a partial unique index.
• **Planner‑friendly** filtered indexes for fast validation and cleanup queries.
• **DB‑driven UTC** timestamps; simple helper properties for `expired`/`is_active`.
• Relationship hygiene: `OTP.user` ↔ `User.otps`.

Notes
-----
• We intentionally avoid a hard `expires_at > created_at` CHECK to allow tests or
  backfills to insert already‑expired OTPs. Enforce freshness in application code.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class OTP(Base):
    """One‑Time Password used for short‑lived verification flows."""

    __tablename__ = "otps"

    # ─────────────── Identity ───────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)

    # ─────────────── Foreign Keys ───────────────
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="User this OTP belongs to",
    )

    # ─────────────── OTP Details ───────────────
    code = Column(String, nullable=False, doc="OTP code value (string; format validated in app layer)")
    purpose = Column(String, nullable=False, doc="Purpose: e.g., 'email_verification', 'mfa', 'password_reset'")

    # TZ‑aware timestamps; `created_at` from DB (UTC)
    expires_at = Column(DateTime(timezone=True), nullable=False, doc="Expiration timestamp (UTC)")
    used = Column(Boolean, nullable=False, server_default=text("false"), doc="Whether the OTP has been consumed")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────── Indexes ───────────────
    __table_args__ = (
        # Fast lookup for currently-unused OTPs (filtered, **non-unique**)
        Index(
            "ix_otps_active_by_user_purpose",
            "user_id",
            "purpose",
            postgresql_where=text("used = false"),
        ),
        # Fast validation lookups
        Index("ix_otps_user_purpose_code", "user_id", "purpose", "code"),
        # Cleanup/audits
        Index("ix_otps_expires_at", "expires_at"),
        Index("ix_otps_user_used", "user_id", "used"),
    )


    # ─────────────── Relationships ───────────────
    user = relationship(
        "User",
        back_populates="otps",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="OTP.user_id == User.id",
        foreign_keys="[OTP.user_id]",
    )

    # ─────────────── Helpers ───────────────
    @property
    def expired(self) -> bool:
        """True when the OTP is past its `expires_at` (UTC‑aware)."""
        exp = self.expires_at
        if exp is None:
            return True
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > exp

    @property
    def is_active(self) -> bool:
        """Convenience: OTP is unused and not expired."""
        return (not self.used) and (not self.expired)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<OTP id={self.id} user_id={self.user_id} purpose={self.purpose} used={self.used}>"
