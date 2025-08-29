from __future__ import annotations

"""
🔐 MoviesNow — MFA Reset Token (security‑grade)
==============================================

Single‑use token that allows a user to reset / re‑enroll multi‑factor authentication
after passing secondary verification.

Design highlights
-----------------
• **Immutable identifier** (`token`), unique by PK, generated as UUIDv4 string.
• **Lifecycle fields**: `created_at`, `expires_at` (both TZ‑aware, DB‑driven UTC).
• **One active token per user** enforced via a partial unique index (`used = false`).
• **Planner‑friendly** filtered index to accelerate lookups of unused tokens
  ordered by `expires_at` (no `now()` in the predicate).
• **Relationship hygiene**: `MFAResetToken.user` ↔ `User.mfa_reset_tokens`.

Conventions
-----------
• Use `server_default` for booleans to keep behavior consistent across writers.
• Keep application‑level semantics (e.g., token validation/consumption) in services;
  DB enforces shape & uniqueness.
"""

import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
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


class MFAResetToken(Base):
    """Multi‑Factor Authentication (MFA) reset token.

    The token is **single‑use**: mark `used = true` once redeemed.
    """

    __tablename__ = "mfa_reset_tokens"

    # ─────────────── Identity ───────────────
    token = Column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False,
        doc="Unique string token for the MFA reset request (UUIDv4).",
    )

    # ─────────────── Foreign Key ───────────────
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="ID of the user associated with this request.",
    )

    # ─────────────── Lifecycle (timezone‑aware, DB‑driven) ───────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(
        DateTime(timezone=True),
        server_default=text("(now() + interval '30 minutes')"),
        nullable=False,
    )

    used = Column(Boolean, nullable=False, server_default=text("false"))

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────── Indexes / Constraints ───────────────
    __table_args__ = (
        # Non‑blank token & sane lifecyle
        CheckConstraint("length(btrim(token)) > 0", name="ck_mfa_token_not_blank"),
        CheckConstraint("expires_at > created_at", name="ck_mfa_expires_after_created"),

        # Enforce at most one *unused* token per user
        Index("uq_mfa_one_unused_per_user", "user_id", unique=True, postgresql_where=text("used = false")),

        # Speed “fetch active token” queries on unused tokens (planner applies `expires_at > now()`)
        Index("ix_mfa_user_unused_exp", "user_id", "expires_at", postgresql_where=text("used = false")),

        # General indexes for audits / cleanups
        Index("ix_mfa_expires_at", "expires_at"),
        Index("ix_mfa_user_used", "user_id", "used"),
        Index("ix_mfa_created_at", "created_at"),
    )

    # ─────────────── Relationship ───────────────
    user = relationship(
        "User",
        back_populates="mfa_reset_tokens",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="MFAResetToken.user_id == User.id",
        foreign_keys="[MFAResetToken.user_id]",
    )

    # ─────────────── Helpers (no schema changes) ───────────────
    @property
    def is_expired(self) -> bool:
        from datetime import datetime, timezone
        exp = self.expires_at
        if exp is None:
            return True
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp <= datetime.now(timezone.utc)

    @property
    def is_active(self) -> bool:
        """Convenience: token is unused and not expired."""
        return (not self.used) and (not self.is_expired)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<MFAResetToken token={self.token} user_id={self.user_id} used={self.used}>"