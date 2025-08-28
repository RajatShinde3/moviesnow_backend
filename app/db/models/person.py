# app/db/models/person.py
from __future__ import annotations

"""
🎬 MoviesNow — Person Model (Cast/Crew)
======================================

Canonical catalog entity for a **human contributor** (actor, director, writer,
composer, etc.). This model captures *identity & metadata* for a person and is
referenced by credit rows (e.g., `Credit`) that bind people to a specific
Title/Season/Episode and role.

Design highlights
-----------------
- **Clean identity fields**: primary display name + optional given/family names
- **Slug** for stable URLs and case-insensitive uniqueness
- **Dates & places**: birth/death (nullable), birthplace
- **Metadata**: biography, AKA list, language tags, external IDs (IMDB/TMDB…)
- **Media**: optional portrait via `MediaAsset` (FK)
- **Indexes/constraints**: search, uniqueness, and temporal sanity checks
- **Timestamps**: DB-driven UTC `created_at`/`updated_at`
"""

from uuid import uuid4
from enum import Enum

from sqlalchemy import (
    Column,
    String,
    Text,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    CheckConstraint,
    Index,
    Enum as SAEnum,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class PersonGender(str, Enum):
    """Lightweight gender taxonomy for display and inclusive filtering."""
    MALE = "male"
    FEMALE = "female"
    NON_BINARY = "non_binary"
    OTHER = "other"
    UNKNOWN = "unknown"


class Person(Base):
    """
    Catalog person (cast/crew) with normalized identity, portrait, and metadata.

    Relationships
    -------------
    - `profile_image_asset` → MediaAsset (optional portrait)
    - `credits` → Credit (many), created in the `Credit` model (to be added)
    """

    __tablename__ = "people"

    # ─────────────── Identity ───────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    primary_name = Column(
        String(256),
        nullable=False,
        index=True,
        doc="Display/canonical name (e.g., 'Denzel Washington').",
    )
    given_name = Column(String(128), nullable=True)
    family_name = Column(String(128), nullable=True)

    slug = Column(
        String(256),
        nullable=False,
        unique=True,
        index=True,
        doc="URL-safe unique slug (e.g., 'denzel-washington').",
    )

    # Also Known As / stage names (array of strings)
    also_known_as = Column(
        JSONB,
        nullable=True,
        doc="List of alternate/stage names (array of strings).",
    )

    # ─────────────── Demographics ───────────────
    gender = Column(SAEnum(PersonGender, name="person_gender"), nullable=False, server_default=text(f"'{PersonGender.UNKNOWN.value}'"))
    birth_date = Column(Date, nullable=True)
    death_date = Column(Date, nullable=True)
    birth_place = Column(String(256), nullable=True, doc="Free-text city/region/country.")
    nationality = Column(String(2), nullable=True, doc="ISO-3166-1 alpha-2 (e.g., 'US').")

    # Languages the person works in (BCP-47 codes: ['en', 'hi', 'mr-IN'] etc.)
    languages = Column(JSONB, nullable=True)

    # ─────────────── Media / portrait ───────────────
    profile_image_asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("media_assets.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        doc="Optional portrait image (MediaAsset).",
    )

    # ─────────────── Descriptive metadata ───────────────
    biography = Column(Text, nullable=True)
    external_ids = Column(
        JSONB,
        nullable=True,
        doc="Arbitrary external IDs (e.g., {'imdb':'nm0000243','tmdb':1234}).",
    )
    popularity = Column(
        String(16),
        nullable=True,
        doc="Optional rank/score as string to avoid float precision/version churn.",
    )

    active = Column(Boolean, nullable=False, server_default=text("true"), index=True)
    verified = Column(Boolean, nullable=False, server_default=text("false"), index=True)

    # ─────────────── Audit ───────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────── Indexes & Constraints ───────────────
    __table_args__ = (
        # Non-blank name
        CheckConstraint("length(btrim(primary_name)) > 0", name="ck_people_name_not_blank"),
        # Temporal sanity: death cannot precede birth; updated >= created
        CheckConstraint("(death_date IS NULL) OR (birth_date IS NULL) OR (death_date >= birth_date)", name="ck_people_life_range"),
        CheckConstraint("updated_at >= created_at", name="ck_people_updated_after_created"),
        # Case-insensitive uniqueness for slug and a search-ready name index
        Index("uq_people_slug_lower", func.lower(slug), unique=True),
        Index("ix_people_name_lower", func.lower(primary_name)),
        # JSONB GIN indexes for aka/external ids (fast contains / existence)
        Index("ix_people_aka_gin", also_known_as, postgresql_using="gin"),
        Index("ix_people_external_ids_gin", external_ids, postgresql_using="gin"),
    )

    # ─────────────── Relationships ───────────────
    profile_image_asset = relationship("MediaAsset", lazy="selectin")

    # Credits backref (defined on Credit.person -> back_populates="person")
    credits = relationship(
        "Credit",
        back_populates="person",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Person id={self.id} name={self.primary_name!r} slug={self.slug!r} active={self.active}>"
