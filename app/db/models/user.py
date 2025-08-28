# app/db/models/user.py

from __future__ import annotations

from uuid import uuid4
from datetime import datetime
import uuid

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
    """
    Represents an individual user in the system.

    Stores authentication details, contact info, and references to related entities.
    """

    __tablename__ = "users"

    # ─────────────── Identity ───────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    email = Column(String, nullable=False, unique=True)
    full_name = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    username = Column(String, nullable=True, unique=True)
    hashed_password = Column(String, nullable=False, doc="BCrypt hashed user password")

    verification_token_created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),  # DB-driven, UTC-aware
        nullable=True,
    )

    role = Column(Enum(OrgRole, name="org_role"), default=OrgRole.USER, nullable=False)

    # ─────────────── Account Status ───────────────
    is_active = Column(Boolean, default=True, nullable=False)
    is_email_verified = Column(Boolean, default=False, nullable=False)
    is_phone_verified = Column(Boolean, default=False, nullable=False)
    is_2fa_enabled = Column(Boolean, default=False, nullable=False)
    is_superuser = Column(Boolean, default=False)
    can_create_org = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether the user is allowed to create organizations",
    )

    is_verified = Column(Boolean, default=False)

    verification_token = Column(
        String,
        unique=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
    )

    verified_at = Column(DateTime(timezone=True), nullable=True)

    # ─────────────── Reactivation Token ───────────────
    reactivation_token = Column(
        String,
        nullable=True,
        index=True,
        comment="Token used to reactivate a deactivated account",
    )
    deactivated_at = Column(DateTime(timezone=True), nullable=True)
    scheduled_deletion_at = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Timestamp after which the account is eligible for permanent deletion",
    )

    totp_secret = Column(String, nullable=True)
    mfa_enabled = Column(Boolean, default=False)

    # ─────────────── Timestamps ───────────────
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),  # DB-driven, UTC-aware
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),  # set on insert
        onupdate=func.now(),        # set on update
        nullable=False,
    )

    deleted_at = Column(DateTime, nullable=True)

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────── Indexes / Constraints ───────────────
    __table_args__ = (
        # Basic hygiene: non-blank email, if provided username must not be blank
        CheckConstraint("length(btrim(email)) > 0", name="ck_users_email_not_blank"),
        CheckConstraint(
            "username IS NULL OR length(btrim(username)) > 0",
            name="ck_users_username_not_blank",
        ),

        # Case-insensitive uniqueness (PostgreSQL functional unique indexes)
        # Keeps your existing unique=True constraints but also prevents
        # duplicates that differ only by case.
        Index("uq_users_email_lower", func.lower(email), unique=True),
        Index(
            "uq_users_username_lower",
            func.lower(username),
            unique=True,
            postgresql_where=text("username IS NOT NULL"),
        ),

        # High-value composite indexes for common filters/queries
        Index("ix_users_active_superuser", "is_active", "is_superuser"),
        Index("ix_users_verification_flags", "is_verified", "is_email_verified", "is_phone_verified"),
        Index("ix_users_soft_delete", "deleted_at", "scheduled_deletion_at"),
        Index("ix_users_created_at", "created_at"),
    )

    # ─────────────── Relationships ───────────────
    profile = relationship(
        "Profile",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    otps = relationship(
        "OTP",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    refresh_tokens = relationship(
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    mfa_reset_tokens = relationship(
        "MFAResetToken",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    audit_logs = relationship(
        "AuditLog",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    watchlist_items = relationship(
        "WatchlistItem",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    collections = relationship(
        "Collection",
        back_populates="owner",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    progress_entries = relationship(
        "Progress",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    reviews = relationship(
        "Review",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    playback_sessions = relationship(
        "PlaybackSession",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    def __repr__(self):
        return f"<User id='{self.id}' email='{self.email}'>"
