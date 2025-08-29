from __future__ import annotations

"""
🎬 MoviesNow — Person (cast & crew catalog)
==========================================

Canonical entity for a human contributor (actor, director, writer, composer, …).
This model stores identity & metadata for a person and is referenced by `Credit`
rows that bind people to a specific Title/Season/Episode and role.

Design highlights
-----------------
• **Clean identity**: display name + optional given/family split and URL slug.
• **Case‑insensitive slug uniqueness** via functional unique index on `lower(slug)`.
• **Lifecycle sanity**: birth/death dates with defensive checks.
• **Metadata**: biography, AKA list, languages (BCP‑47), nationality (ISO‑3166‑1 alpha‑2),
  external IDs (IMDB/TMDB/… as JSONB), popularity, portrait `MediaAsset`.
• **Indexes**: search by name, JSONB GIN for `also_known_as` and `external_ids`,
  optional unique btree on common external IDs, active/verified filters.
• **Timestamps**: DB‑driven (UTC) with eager defaults.

Relationships
-------------
• `Person.credits` ↔ `Credit.person` (many‑to‑one from credits)
• `Person.profile_image_asset` → `MediaAsset` (optional portrait)
"""

from uuid import uuid4
from enum import Enum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    Date,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.base_class import Base
from app.schemas.enums import PersonGender

# ──────────────────────────────────────────────────────────────
# 🧱 Model: Person
# ──────────────────────────────────────────────────────────────
class Person(Base):
    """Catalog person (cast/crew) with normalized identity, portrait, and metadata."""

    __tablename__ = "people"

    # ─────────────── Identity ───────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    primary_name = Column(String(256), nullable=False, index=True, doc="Display/canonical name (e.g., 'Denzel Washington').")
    given_name = Column(String(128), nullable=True)
    family_name = Column(String(128), nullable=True)

    slug = Column(String(256), nullable=False, index=True, doc="URL‑safe slug (e.g., 'denzel-washington').")

    # Also Known As / stage names (array of strings)
    also_known_as = Column(JSONB, nullable=True, doc="Alternate/stage names (array of strings).")

    # ─────────────── Demographics ───────────────
    gender = Column(
        SAEnum(PersonGender, name="person_gender"),
        nullable=False,
        server_default=text("'UNKNOWN'"), 
    )
    birth_date = Column(Date, nullable=True)
    death_date = Column(Date, nullable=True)
    birth_place = Column(String(256), nullable=True, doc="Free‑text city/region/country.")
    nationality = Column(String(2), nullable=True, doc="ISO‑3166‑1 alpha‑2 (e.g., 'US').")

    # Languages the person works in (BCP‑47 codes: ['en', 'hi', 'mr-IN'] etc.)
    languages = Column(JSONB, nullable=True)

    # ─────────────── Media / portrait ───────────────
    profile_image_asset_id = Column(UUID(as_uuid=True), ForeignKey("media_assets.id", ondelete="SET NULL"),
                                    nullable=True, index=True, doc="Optional portrait (MediaAsset).")

    # ─────────────── Descriptive metadata ───────────────
    biography = Column(Text, nullable=True)
    external_ids = Column(JSONB, nullable=True, doc="Arbitrary external IDs (e.g., {'imdb':'nm0000243','tmdb':1234}).")
    popularity = Column(String(16), nullable=True, doc="Optional rank/score as string to avoid float churn.")

    active = Column(Boolean, nullable=False, server_default=text("true"), index=True)
    verified = Column(Boolean, nullable=False, server_default=text("false"), index=True)

    # ─────────────── Audit ───────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────── Indexes & Constraints ───────────────
    __table_args__ = (
        # Non‑blank core fields
        CheckConstraint("length(btrim(primary_name)) > 0", name="ck_people_name_not_blank"),
        CheckConstraint("length(btrim(slug)) > 0", name="ck_people_slug_not_blank"),
        # Lifecycle sanity
        CheckConstraint("(death_date IS NULL) OR (birth_date IS NULL) OR (death_date >= birth_date)",
                        name="ck_people_life_range"),
        CheckConstraint("(nationality IS NULL) OR (char_length(nationality) = 2 AND nationality = upper(nationality))",
                        name="ck_people_nationality_iso_upper"),
        CheckConstraint("updated_at >= created_at", name="ck_people_updated_after_created"),
        # Case‑insensitive slug uniqueness
        Index("uq_people_slug_lower", func.lower(slug), unique=True),
        # Name search helper
        Index("ix_people_name_lower", func.lower(primary_name)),
        # JSONB accelerators
        Index("ix_people_aka_gin", also_known_as, postgresql_using="gin"),
        Index("ix_people_languages_gin", languages, postgresql_using="gin"),
        Index("ix_people_external_ids_gin", external_ids, postgresql_using="gin"),
        # Common filters
        Index("ix_people_active_verified", "active", "verified"),
        Index("ix_people_created_at", "created_at"),
        # Optional: unique external IDs when present (keeps data clean)
        Index("uq_people_imdb", text("(external_ids ->> 'imdb')"), unique=True,
              postgresql_where=text("external_ids ? 'imdb'")),
        Index("uq_people_tmdb", text("(external_ids ->> 'tmdb')"), unique=True,
              postgresql_where=text("external_ids ? 'tmdb'")),
        Index("uq_people_tvdb", text("(external_ids ->> 'tvdb')"), unique=True,
              postgresql_where=text("external_ids ? 'tvdb'")),
    )

    # ─────────────── Relationships ───────────────
    profile_image_asset = relationship(
        "MediaAsset",
        primaryjoin="Person.profile_image_asset_id == MediaAsset.id",
        foreign_keys="[Person.profile_image_asset_id]",
        viewonly=True,
        lazy="selectin",
    )

    credits = relationship(
        "Credit",
        back_populates="person",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        primaryjoin="Credit.person_id == Person.id",
        foreign_keys="[Credit.person_id]",
    )


    def __repr__(self) -> str:  # pragma: no cover
        return f"<Person id={self.id} name={self.primary_name!r} slug={self.slug!r} active={self.active}>"
