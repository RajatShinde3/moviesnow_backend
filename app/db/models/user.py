# app/db/models/user.py
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


class User(Base):
    """Account record with auth, verification, and lifecycle flags."""

    __tablename__ = "users"

    # ── Identity & auth ─────────────────────────────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    email = Column(String, nullable=False, unique=True)  # keep for ORM simplicity; CI index below is authoritative
    username = Column(String, nullable=True, unique=True)  # ditto; CI unique index below handles case-insensitive dupes
    full_name = Column(String, nullable=True)
    phone = Column(String, nullable=True)

    hashed_password = Column(String, nullable=False, doc="BCrypt (or argon2) hash")

    role = Column(
        Enum(OrgRole, name="org_role"),
        nullable=False,
        server_default=text("'USER'"),
    )

    # ── Verification / security ─────────────────────────────────────────────
    is_active = Column(Boolean, nullable=False, server_default=text("true"))
    is_superuser = Column(Boolean, nullable=True, server_default=text("false"))

    is_verified = Column(Boolean, nullable=False, server_default=text("false"))
    is_email_verified = Column(Boolean, nullable=False, server_default=text("false"))
    is_phone_verified = Column(Boolean, nullable=False, server_default=text("false"))

    # MFA flags (prefer `is_2fa_enabled`; `mfa_enabled` kept for backward compat)
    is_2fa_enabled = Column(Boolean, nullable=False, server_default=text("false"))
    mfa_enabled = Column(Boolean, nullable=False, server_default=text("false"))  # TODO: deprecate in favor of is_2fa_enabled
    totp_secret = Column(String, nullable=True)

    verification_token = Column(String, unique=True, index=True, default=lambda: str(uuid4()))
    verification_token_created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)

    # ── Reactivation / lifecycle ────────────────────────────────────────────
    reactivation_token = Column(String, nullable=True, index=True, comment="Token for reactivating a deactivated account")
    deactivated_at = Column(DateTime(timezone=True), nullable=True)
    scheduled_deletion_at = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Eligible time for permanent deletion",
    )
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    # ── Timestamps (DB-driven, UTC) ─────────────────────────────────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ── Indexes / constraints ───────────────────────────────────────────────
    __table_args__ = (
        # Hygiene: non-blank email; username must be non-blank if provided
        CheckConstraint("length(btrim(email)) > 0", name="ck_users_email_not_blank"),
        CheckConstraint("(username IS NULL) OR (length(btrim(username)) > 0)", name="ck_users_username_not_blank"),

        # Optional: if you enforce E.164 phone numbers, uncomment this:
        # CheckConstraint("(phone IS NULL) OR (phone ~ '^\\+?[1-9]\\d{1,14}$')", name="ck_users_phone_e164"),

        # CI uniqueness (authoritative guards against case-variant dupes)
        Index("uq_users_email_lower", func.lower(email), unique=True),
        Index("uq_users_username_lower", func.lower(username), unique=True, postgresql_where=text("username IS NOT NULL")),

        # Useful filters
        Index("ix_users_active_superuser", "is_active", "is_superuser"),
        Index("ix_users_verification_flags", "is_verified", "is_email_verified", "is_phone_verified"),
        Index("ix_users_soft_delete", "deleted_at", "scheduled_deletion_at"),
        Index("ix_users_created_at", "created_at"),

        # Temporal sanity
        CheckConstraint("updated_at >= created_at", name="ck_users_updated_after_created"),
        CheckConstraint(
            "(scheduled_deletion_at IS NULL) OR (deactivated_at IS NULL) OR (scheduled_deletion_at >= deactivated_at)",
            name="ck_users_deletion_after_deactivation",
        ),
        # If verified_at is set, user should be marked verified (advisory but helpful)
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
        passive_deletes=True,
        lazy="selectin",
    )

    otps = relationship("OTP", back_populates="user", cascade="all, delete-orphan", passive_deletes=True, lazy="selectin")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan", passive_deletes=True, lazy="selectin")
    mfa_reset_tokens = relationship("MFAResetToken", back_populates="user", cascade="all, delete-orphan", passive_deletes=True, lazy="selectin")

    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan", passive_deletes=True, lazy="selectin")
    watchlist_items = relationship("WatchlistItem", back_populates="user", cascade="all, delete-orphan", passive_deletes=True, lazy="selectin")
    collections = relationship("Collection", back_populates="owner", cascade="all, delete-orphan", passive_deletes=True, lazy="selectin")
    progress_entries = relationship("Progress", back_populates="user", cascade="all, delete-orphan", passive_deletes=True, lazy="selectin")
    reviews = relationship("Review", back_populates="user", cascade="all, delete-orphan", passive_deletes=True, lazy="selectin")
    playback_sessions = relationship("PlaybackSession", back_populates="user", cascade="all, delete-orphan", passive_deletes=True, lazy="selectin")

    # ── Convenience ─────────────────────────────────────────────────────────
    def __repr__(self) -> str:  # pragma: no cover
        return f"<User id={self.id} email={self.email!r} active={self.is_active}>"
