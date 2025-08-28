# app/db/models/profile.py
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
    Text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base_class import Base


class Profile(Base):
    """
    🎬 MoviesNow — User Profile (minimal & future-proof)
    ----------------------------------------------------
    Compact, privacy-friendly profile attached 1:1 to `User`.

    Includes:
    - Identity: `handle` (unique, lowercase), `full_name`
    - Presentation: `avatar_url`, optional `banner_url`, short `bio`
    - Preferences: JSONB blob for UI/content settings
    - Domain: `favorite_genres` (JSONB array of strings)
    - Visibility: `is_visible`, `is_discoverable`
    - Timestamps with DB defaults
    """

    __tablename__ = "profiles"

    # ── Identity ──────────────────────────────────────────────────────────────
    id = Column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        doc="Primary key for the profile",
    )

    user_id = Column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
        comment="One-to-one reference to the associated user",
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
    is_visible = Column(Boolean, default=True, nullable=False, comment="Visible to others")
    is_discoverable = Column(Boolean, default=True, nullable=False, comment="Can appear in search/browse")

    # ── Preferences & Domain ─────────────────────────────────────────────────
    # JSONB object for UI/language/theme/timezone, etc.
    preferences = Column(JSONB, nullable=True, comment="Flexible settings blob (object)")

    # JSONB array of strings, e.g., ['Action','Drama']
    favorite_genres = Column(JSONB, nullable=True, comment="Preferred genres (array of strings)")

    # ── Timestamps (UTC, DB-driven) ──────────────────────────────────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ── Indexes & Constraints ────────────────────────────────────────────────
    __table_args__ = (
        # Case-insensitive uniqueness for handle (Postgres expression index)
        Index("uq_profiles_handle_lower", func.lower(handle), unique=True),

        # Fast filters & lists
        Index("ix_profiles_is_visible", "is_visible"),

        # GIN indexes for JSONB membership queries
        Index("ix_profiles_favorite_genres_gin", "favorite_genres", postgresql_using="gin"),
        Index("ix_profiles_preferences_gin", "preferences", postgresql_using="gin"),

        # Data hygiene
        CheckConstraint("updated_at >= created_at", name="ck_profiles_updated_after_created"),
        CheckConstraint("handle ~ '^[a-z0-9_.-]{3,32}$'", name="ck_profiles_handle_format"),
        CheckConstraint("(avatar_url IS NULL) OR (char_length(avatar_url) <= 2048)", name="ck_profiles_avatar_len"),
        CheckConstraint("(banner_url IS NULL) OR (char_length(banner_url) <= 2048)", name="ck_profiles_banner_len"),

        # JSONB shape guards
        CheckConstraint("jsonb_typeof(preferences) IN ('object','null')", name="ck_profiles_prefs_object"),
        CheckConstraint("jsonb_typeof(favorite_genres) IN ('array','null')", name="ck_profiles_genres_array"),
    )

    # Relationship
    user = relationship(
        "User",
        back_populates="profile",
        lazy="selectin",
        passive_deletes=True,
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Profile id={self.id} user_id={self.user_id} handle={self.handle}>"
