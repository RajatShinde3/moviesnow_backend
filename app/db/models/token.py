# app/db/models/token.py
from __future__ import annotations

"""
🔐 MoviesNow — RefreshToken (session continuation, rotation & revocation)
========================================================================

Represents an opaque **refresh token** issued to a user. Designed for:
- **Rotation** chains via `jti` and `parent_jti`
- **Revocation** & fast “active token” lookups
- **Auditability** without storing sensitive IPs in plaintext (use INET)
- **DB-driven** timestamps to avoid tz drift

Best practices
--------------
- Store **only a hash** of `token` in production; if you do, index the hash instead.
- Use **partial indexes** on `is_revoked = false` for hot-path queries.
- Keep `expires_at > created_at` guaranteed by a DB check.
"""

from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    CheckConstraint,
    text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class RefreshToken(Base):
    """
    A refresh token bound to a `User`, with rotation and revocation support.

    Fields
    ------
    - `token`        : opaque value (recommend: store a **hash** in production)
    - `jti`          : unique JWT ID for this token instance
    - `parent_jti`   : prior token's JTI when rotating
    - `is_revoked`   : hard kill switch
    - `expires_at`   : absolute expiry
    - `ip_address`   : client IP at issue time (INET)
    """

    __tablename__ = "refresh_tokens"

    # ── Identity ────────────────────────────────────────────────────────────
    id = Column(Integer, primary_key=True, index=True, comment="Auto-incrementing token ID")

    # ── Token data ──────────────────────────────────────────────────────────
    token = Column(String, nullable=False, comment="Opaque refresh token string (store a hash in prod)")
    jti = Column(String, unique=True, nullable=False, index=True, comment="JWT ID (unique per token instance)")
    parent_jti = Column(String, nullable=True, comment="Parent JWT ID for rotation tracking")

    # ── Ownership & lifecycle ───────────────────────────────────────────────
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Owner user ID",
    )

    is_revoked = Column(Boolean, nullable=False, server_default=text("false"), comment="Revocation flag")

    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="UTC expiry timestamp",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="UTC creation timestamp (DB clock)",
    )

    # Store as INET for validation/search; keep it optional.
    ip_address = Column(INET, nullable=True, comment="Client IP at issuance (INET)")

    __mapper_args__ = {"eager_defaults": True}

    # ── Relationships ───────────────────────────────────────────────────────
    user = relationship(
        "User",
        back_populates="refresh_tokens",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="RefreshToken.user_id == User.id",
        foreign_keys="[RefreshToken.user_id]",
    )


    # ── Indexes & constraints ───────────────────────────────────────────────
    __table_args__ = (
        # Hot-path: fetch active (unrevoked) tokens and let planner apply `expires_at > now()` at runtime
        Index(
            "ix_refresh_user_unrevoked",
            "user_id",
            "expires_at",
            postgresql_where=text("is_revoked = false"),
        ),
        # Rotation/chain traversals
        Index("ix_refresh_parent_jti", "parent_jti"),
        # If you store a hash instead of raw `token`, index the hash column instead of this:
        Index("ix_refresh_token_lookup", "token"),
        # Audits by revocation state
        Index("ix_refresh_user_revoked", "user_id", "is_revoked"),
        # Cleanup / time-based scans
        Index("ix_refresh_created_at", "created_at"),
        Index("ix_refresh_expires_at", "expires_at"),
        # Hygiene checks
        CheckConstraint("char_length(btrim(token)) > 0", name="ck_refresh_token_not_blank"),
        CheckConstraint("char_length(btrim(jti)) > 0", name="ck_refresh_jti_not_blank"),
        CheckConstraint(
            "(parent_jti IS NULL) OR (parent_jti <> jti)",
            name="ck_refresh_parent_jti_not_self",
        ),
        CheckConstraint("expires_at > created_at", name="ck_refresh_expires_after_created"),
    )

    # ── Convenience ─────────────────────────────────────────────────────────
    @property
    def is_active(self) -> bool:
        """True when not revoked and not past `expires_at` (evaluate in app logic)."""
        # This is intentionally simple—DB enforces only static invariants.
        return not self.is_revoked

    def __repr__(self) -> str:  # pragma: no cover
        return f"<RefreshToken id={self.id} user={self.user_id} jti={self.jti} revoked={self.is_revoked}>"
