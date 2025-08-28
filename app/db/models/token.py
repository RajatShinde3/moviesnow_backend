# app/db/models/token.py
from __future__ import annotations

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
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base_class import Base


class RefreshToken(Base):
    """
    Represents a refresh token issued to a user for session continuation.

    - Supports token revocation and JWT rotation using `jti` and `parent_jti`.
    - Designed for secure, auditable, and revocable token handling.
    """

    __tablename__ = "refresh_tokens"

    # ──────────────── Primary Key ────────────────
    id = Column(Integer, primary_key=True, index=True, comment="Auto-incrementing token ID")

    # ──────────────── Token Data ────────────────
    token = Column(String, nullable=False, comment="Opaque refresh token string (stored securely)")
    jti = Column(String, unique=True, nullable=False, index=True, comment="JWT ID (unique per token instance)")
    parent_jti = Column(String, nullable=True, comment="Parent JWT ID for rotation tracking")

    # ──────────────── Ownership & Session ────────────────
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Reference to the owning user",
    )

    is_revoked = Column(Boolean, default=False, nullable=False, comment="Indicates whether this token has been revoked")

    # Timezone-aware, DB-driven timestamps to avoid naive/aware errors
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True, comment="Token expiration timestamp")
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Timestamp when the token was created (UTC)",
    )

    ip_address = Column(String, nullable=True, comment="IP address from which the token was generated")

    # === Relationship ===
    user = relationship(
        "User",
        back_populates="refresh_tokens",
        lazy="selectin",
        passive_deletes=True,
    )

    __table_args__ = (
        # Replace IMMUTABLE-violating predicate:
        # Keep a partial index on *unrevoked* tokens only; the planner will still
        # use it for `expires_at > now()` filters at runtime.
        Index(
            "ix_refresh_user_unrevoked",
            "user_id",
            "expires_at",
            postgresql_where=text("is_revoked = false"),
        ),

        # Fast chain/rotation traversals
        Index("ix_refresh_parent_jti", "parent_jti"),

        # Token lookup (if you store a hash of the token, index that instead)
        Index("ix_refresh_token_lookup", "token"),

        # Helpful compound filter when auditing by revocation state
        Index("ix_refresh_user_revoked", "user_id", "is_revoked"),

        # Basic temporal sanity: expire must be after created
        CheckConstraint("expires_at > created_at", name="ck_refresh_expires_after_created"),
    )

    def __repr__(self) -> str:
        return f"<RefreshToken id={self.id} user={self.user_id} jti={self.jti} revoked={self.is_revoked}>"
