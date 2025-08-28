# app/db/models/otp.py

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base_class import Base


class OTP(Base):
    """
    One-Time Password (OTP) model for temporary codes used in user verification
    (email verification, MFA, password reset).
    """

    __tablename__ = "otp"

    # ──────────────── Primary Key ────────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)

    # ──────────────── Foreign Keys ────────────────
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="The user this OTP belongs to",
    )

    # ──────────────── OTP Details ────────────────
    code = Column(String, nullable=False, comment="OTP code value")
    purpose = Column(String, nullable=False, comment="Purpose e.g., 'email_verification', 'mfa', 'password_reset'")

    # TZ-aware timestamps; created_at from DB (UTC)
    expires_at = Column(DateTime(timezone=True), nullable=False, comment="Expiration timestamp for the OTP")
    used = Column(Boolean, default=False, nullable=False, comment="Flag if OTP has been used")
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="Timestamp of OTP creation (UTC)",
    )

    __mapper_args__ = {"eager_defaults": True}

    # ──────────────── Indexes ────────────────
    __table_args__ = (
        # General multi-column index to speed verification checks / cleanup jobs
        Index("ix_otp_user_purpose_used_exp", "user_id", "purpose", "used", "expires_at"),
        # NOTE: We intentionally DO NOT keep a CHECK like `expires_at > created_at`
        # because tests (and some flows) may insert already-expired OTPs.
        # Enforce freshness in application logic instead.
    )

    # ──────────────── Relationships ────────────────
    user = relationship("User", back_populates="otps", lazy="selectin", passive_deletes=True)

    # ──────────────── Helpers ────────────────
    @property
    def expired(self) -> bool:
        """True if the OTP has expired as of now (UTC). Handles naive/aware safely."""
        now = datetime.now(timezone.utc)
        exp = self.expires_at
        if exp is None:
            return True
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return now > exp

    def __repr__(self) -> str:
        return f"<OTP id={self.id} user_id={self.user_id} purpose={self.purpose} used={self.used}>"
