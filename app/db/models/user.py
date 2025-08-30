from __future__ import annotations

"""
👤 MoviesNow — User (accounts & auth)
====================================

Canonical account entity storing login credentials, contact fields, verification
state, and links to profile/engagement/telemetry models.

Design highlights
-----------------
• **Case-insensitive uniqueness** for email and username (functional indexes).
• **DB-driven, tz-aware timestamps** (`func.now()`; `timezone=True`).
• **Defensive checks**: non-blank email/username; sane soft-delete windows.
• **Relationship hygiene** with `selectin` loading and `passive_deletes=True`.

Notes
-----
• `mfa_enabled` and `is_2fa_enabled` overlap. Prefer **`is_2fa_enabled`** and
  treat `mfa_enabled` as a transitional alias (see comment below).
"""

from uuid import uuid4
from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    Enum,
    Index,
    CheckConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.db.base_class import Base
from app.schemas.enums import OrgRole


# ──────────────────────────────────────────────────────────────────────────────
# User Model
# ──────────────────────────────────────────────────────────────────────────────

class User(Base):
    """
    Account record with auth, verification, lifecycle flags, and associated data.
    This model handles account-level attributes and relationships with other entities
    like profiles, watchlist, and WebAuthn credentials.
    """

    __tablename__ = "users"

    # ── Identity & Authentication ─────────────────────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    email = Column(String, nullable=False, unique=True)  # Email is unique and used for login
    username = Column(String, nullable=True, unique=True)  # Optional username, unique
    full_name = Column(String, nullable=True)  # User's full name
    phone = Column(String, nullable=True)  # Optional phone number

    hashed_password = Column(String, nullable=False, doc="BCrypt or Argon2 hash of the password")

    role = Column(
        Enum(OrgRole, name="org_role"),
        nullable=False,
        server_default=text("'USER'"),  # Default role is 'USER'
    )

    # ── Verification / Security ───────────────────────────────────────────────
    is_active = Column(Boolean, nullable=False, server_default=text("true"))
    is_superuser = Column(Boolean, nullable=True, server_default=text("false"))  # Superuser flag for admins

    is_verified = Column(Boolean, nullable=False, server_default=text("false"))
    is_email_verified = Column(Boolean, nullable=False, server_default=text("false"))
    is_phone_verified = Column(Boolean, nullable=False, server_default=text("false"))

    # MFA flags (Prefer is_2fa_enabled over mfa_enabled)
    is_2fa_enabled = Column(Boolean, nullable=False, server_default=text("false"))
    mfa_enabled = Column(Boolean, nullable=False, server_default=text("false"))
    totp_secret = Column(String, nullable=True)  # Secret for TOTP (Time-based One-Time Password)

    # Verification token and timestamps
    verification_token = Column(String, unique=True, index=True, default=lambda: str(uuid4()))
    verification_token_created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)

    # ── Reactivation / Lifecycle ──────────────────────────────────────────────
    reactivation_token = Column(String, nullable=True, index=True, comment="Token for reactivating a deactivated account")
    deactivated_at = Column(DateTime(timezone=True), nullable=True)
    scheduled_deletion_at = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Eligible time for permanent deletion",
    )
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ── Indexes / Constraints ────────────────────────────────────────────────
    __table_args__ = (
        CheckConstraint("length(btrim(email)) > 0", name="ck_users_email_not_blank"),
        CheckConstraint("(username IS NULL) OR (length(btrim(username)) > 0)", name="ck_users_username_not_blank"),
        Index("uq_users_email_lower", func.lower(email), unique=True),
        Index("uq_users_username_lower", func.lower(username), unique=True, postgresql_where=text("username IS NOT NULL")),
        Index("ix_users_active_superuser", "is_active", "is_superuser"),
        Index("ix_users_verification_flags", "is_verified", "is_email_verified", "is_phone_verified"),
        Index("ix_users_soft_delete", "deleted_at", "scheduled_deletion_at"),
        Index("ix_users_created_at", "created_at"),
        CheckConstraint("updated_at >= created_at", name="ck_users_updated_after_created"),
        CheckConstraint(
            "(scheduled_deletion_at IS NULL) OR (deactivated_at IS NULL) OR (scheduled_deletion_at >= deactivated_at)",
            name="ck_users_deletion_after_deactivation",
        ),
        CheckConstraint(
            "(verified_at IS NULL) OR (is_verified = true)",
            name="ck_users_verified_at_implies_flag",
        ),
    )

    # ── Relationships ───────────────────────────────────────────────────────
    profile = relationship(
        "Profile",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
        single_parent=True,
        passive_deletes=True,
        lazy="selectin",
        primaryjoin="Profile.user_id == User.id",
        foreign_keys="[Profile.user_id]",
    )

    # WebAuthn Credentials (new addition)
    webauthn_credentials = relationship(
        "WebAuthnCredential",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        primaryjoin="WebAuthnCredential.user_id == User.id",
        foreign_keys="[WebAuthnCredential.user_id]",
    )

    # ── Other Relationships ──────────────────────────────────────────────────
    otps = relationship(
        "OTP",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        primaryjoin="OTP.user_id == User.id",
        foreign_keys="[OTP.user_id]",
    )

    refresh_tokens = relationship(
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        primaryjoin="RefreshToken.user_id == User.id",
        foreign_keys="[RefreshToken.user_id]",
    )

    mfa_reset_tokens = relationship(
        "MFAResetToken",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        primaryjoin="MFAResetToken.user_id == User.id",
        foreign_keys="[MFAResetToken.user_id]",
    )

    audit_logs = relationship(
        "AuditLog",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        primaryjoin="AuditLog.user_id == User.id",
        foreign_keys="[AuditLog.user_id]",
    )

    watchlist_items = relationship(
        "WatchlistItem",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        primaryjoin="WatchlistItem.user_id == User.id",
        foreign_keys="[WatchlistItem.user_id]",
    )

    collections = relationship(
        "Collection",
        back_populates="owner",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        primaryjoin="Collection.owner_user_id == User.id",
        foreign_keys="[Collection.owner_user_id]",
    )

    progress_entries = relationship(
        "Progress",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        primaryjoin="Progress.user_id == User.id",
        foreign_keys="[Progress.user_id]",
    )

    reviews = relationship(
        "Review",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        primaryjoin="Review.user_id == User.id",
        foreign_keys="[Review.user_id]",
    )

    playback_sessions = relationship(
        "PlaybackSession",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        primaryjoin="PlaybackSession.user_id == User.id",
        foreign_keys="[PlaybackSession.user_id]",
    )

    # ── Convenience ─────────────────────────────────────────────────────────
    def __repr__(self) -> str:
        """String representation of the User object."""
        return f"<User(id={self.id}, email={self.email}, mfa_enabled={self.mfa_enabled})>"
