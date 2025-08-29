from __future__ import annotations

"""
👤 MoviesNow — User Profile (minimal, privacy‑friendly)
======================================================

Compact, future‑proof profile that attaches **1:1** to `User`.

Highlights
----------
• Public **handle** with strict lowercase charset and **case‑insensitive** uniqueness.
• Lightweight presentation fields (avatar/banner URLs) with sane length checks.
• **Privacy‑first**: preferences & favorite genres stored as JSONB (shape‑checked),
  no PII beyond display name and public handle.
• Fast filters for **visibility/discoverability**, plus JSONB GIN indexes.
• DB‑driven UTC timestamps and `eager_defaults=True` for consistent writes.

Relationships
-------------
• `Profile.user` ↔ `User.profile` (one‑to‑one; enforced by unique FK).
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
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class Profile(Base):
    __tablename__ = "profiles"

    # ── Identity ──────────────────────────────────────────────────────────────
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)

    user_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,  # one profile per user
        nullable=False,
        index=True,
        comment="One‑to‑one reference to the associated user",
    )

    # Public handle for profile URLs & @mentions (lowercase, strict charset)
    handle = Column(
        String(32),
        nullable=False,
        index=True,
        comment="Unique public handle (lowercase; 3–32 chars, a–z 0–9 _ . -)",
    )

    full_name = Column(String(120), nullable=True, comment="Display name")
    bio = Column(Text, nullable=True, comment="Short about text")

    # ── Presentation ──────────────────────────────────────────────────────────
    avatar_url = Column(String(2048), nullable=True)
    banner_url = Column(String(2048), nullable=True)

    # ── Privacy / Discovery ──────────────────────────────────────────────────
    is_visible = Column(Boolean, nullable=False, server_default=text("true"), comment="Visible to others")
    is_discoverable = Column(Boolean, nullable=False, server_default=text("true"), comment="Can appear in search/browse")

    # ── Preferences & Domain ─────────────────────────────────────────────────
    preferences = Column(JSONB, nullable=True, comment="Flexible settings blob (object)")
    favorite_genres = Column(JSONB, nullable=True, comment="Preferred genres (array of strings)")

    # ── Timestamps (UTC, DB‑driven) ──────────────────────────────────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ── Indexes & Constraints ────────────────────────────────────────────────
    __table_args__ = (
        # Case‑insensitive uniqueness for handle (functional unique index)
        Index("uq_profiles_handle_lower", func.lower(handle), unique=True),

        # Fast filters & lists
        Index("ix_profiles_visible_discoverable", "is_visible", "is_discoverable"),
        Index("ix_profiles_created_at", "created_at"),

        # GIN indexes for JSONB membership queries
        Index("ix_profiles_favorite_genres_gin", "favorite_genres", postgresql_using="gin"),
        Index("ix_profiles_preferences_gin", "preferences", postgresql_using="gin"),

        # Data hygiene
        CheckConstraint("updated_at >= created_at", name="ck_profiles_updated_after_created"),
        CheckConstraint("length(btrim(handle)) > 0", name="ck_profiles_handle_not_blank"),
        CheckConstraint("handle ~ '^[a-z0-9_.-]{3,32}$'", name="ck_profiles_handle_format"),
        CheckConstraint("(full_name IS NULL) OR (length(btrim(full_name)) > 0)", name="ck_profiles_full_name_not_blank_when_present"),
        CheckConstraint("(avatar_url IS NULL) OR (char_length(avatar_url) <= 2048)", name="ck_profiles_avatar_len"),
        CheckConstraint("(banner_url IS NULL) OR (char_length(banner_url) <= 2048)", name="ck_profiles_banner_len"),

        # JSONB shape guards
        CheckConstraint("jsonb_typeof(preferences) IN ('object','null')", name="ck_profiles_prefs_object"),
        CheckConstraint("jsonb_typeof(favorite_genres) IN ('array','null')", name="ck_profiles_genres_array"),
    )

    # ── Relationship ─────────────────────────────────────────────────────────
    user = relationship("User", back_populates="profile", lazy="selectin", passive_deletes=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Profile id={self.id} user_id={self.user_id} handle={self.handle}>"
