# app/db/models/mfa_reset_token.py
from __future__ import annotations

import uuid
from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    CheckConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base_class import Base


class MFAResetToken(Base):
    """
    Multi-Factor Authentication (MFA) reset token.

    Fields unchanged; we only adjust defaults and indexes so Postgres can optimize
    without violating IMMUTABLE rules in partial indexes.
    """

    __tablename__ = "mfa_reset_tokens"

    # ─────────────── Identity ───────────────
    token = Column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False,
        doc="Unique string token for the MFA reset request.",
    )

    # ─────────────── Foreign Key ───────────────
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="The ID of the user associated with the MFA reset request.",
    )

    # ─────────────── Lifecycle (timezone-aware, DB-driven) ───────────────
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="Timestamp when the token was created (UTC).",
    )
    expires_at = Column(
        DateTime(timezone=True),
        server_default=text("(now() + interval '30 minutes')"),
        nullable=False,
        doc="The datetime when the token will expire (UTC).",
    )

    used = Column(
        Boolean,
        default=False,
        nullable=False,
        doc="Flag indicating whether the token has already been used.",
    )

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────── Indexes / Constraints ───────────────
    __table_args__ = (
        # Enforce at most one *unused* token per user (no time function in predicate)
        Index(
            "uq_mfa_one_unused_per_user",
            "user_id",
            unique=True,
            postgresql_where=text("used = false"),
        ),

        # Speed “fetch active token” queries; planner will apply `expires_at > now()`
        # at runtime using this filtered index on unused tokens.
        Index(
            "ix_mfa_user_unused_exp",
            "user_id",
            "expires_at",
            postgresql_where=text("used = false"),
        ),

        # General index helpful for cleanups and audits
        Index("ix_mfa_expires_at", "expires_at"),
        Index("ix_mfa_user_used", "user_id", "used"),
    )

    # === Relationship ===
    user = relationship(
        "User",
        back_populates="mfa_reset_tokens",
        lazy="selectin",
        passive_deletes=True,
    )

    # ─────────────── Helper (no schema changes) ───────────────
    @property
    def is_expired(self) -> bool:
        from datetime import datetime, timezone
        exp = self.expires_at
        if exp is None:
            return True
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp <= datetime.now(timezone.utc)

    def __repr__(self):
        return f"<MFAResetToken token={self.token} user_id={self.user_id}>"
