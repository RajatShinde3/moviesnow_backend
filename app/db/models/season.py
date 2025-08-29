# app/db/models/season.py
from __future__ import annotations

"""
📺 MoviesNow — Season Model (production-grade)
=============================================

Represents a **Season** belonging to a `Title` of type **SERIES**. A season
aggregates metadata, artwork pointers, and episodes with strong integrity.

Why this design?
----------------
- **Integrity**: each Season is scoped to exactly one Title (`title_id`).
- **Clean uniqueness**: `(title_id, season_number)` and case-insensitive slug per title.
- **Catalog-ready**: names, overview, dates, artwork/trailer pointers, external IDs.
- **Defensive constraints**: positive counters, valid date ranges, DB-driven UTC timestamps.
- **Query-friendly**: targeted composite/functional indexes for common lookups.

Relationships
-------------
- `title`        → Title (parent)                      [back_populates="seasons"]
- `episodes`     → Episode (children)                  [back_populates="season"]
- `media_assets` → MediaAsset (season-scoped assets)   [back_populates="season"]
- `subtitles`    → Subtitle                            [back_populates="season"]
- `credits`      → Credit                              [back_populates="season"]
- `availabilities` → Availability                      [back_populates="season"]
- `progress_entries` → Progress                        [back_populates="season"]
"""

from uuid import uuid4

from sqlalchemy import (
    CheckConstraint,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Boolean,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class Season(Base):
    """Season container for a series with clean integrity and useful indexes."""

    __tablename__ = "seasons"

    # ── Identity ────────────────────────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    title_id = Column(
        UUID(as_uuid=True),
        ForeignKey("titles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Parent Title (must be a SERIES).",
    )

    # ── Ordinal / Naming / SEO ─────────────────────────────────
    season_number = Column(Integer, nullable=False, doc="Ordinal season number (1-based).")
    name = Column(String(255), nullable=True, doc="Optional display name (e.g., 'Season of Fire').")
    slug = Column(String(255), nullable=True, index=True, doc="Optional URL-safe slug unique per title.")

    # ── Synopsis ───────────────────────────────────────────────
    overview = Column(String, nullable=True)

    # ── Dates ─────────────────────────────────────────────────
    release_date = Column(Date, nullable=True, index=True, doc="First air date for the season.")
    end_date = Column(Date, nullable=True, doc="Last air date for the season (if concluded).")

    # ── Artwork / Trailer (canonical pointers) ─────────────────
    poster_asset_id = Column(UUID(as_uuid=True), ForeignKey("media_assets.id", ondelete="SET NULL"), nullable=True)
    backdrop_asset_id = Column(UUID(as_uuid=True), ForeignKey("media_assets.id", ondelete="SET NULL"), nullable=True)
    trailer_asset_id = Column(UUID(as_uuid=True), ForeignKey("media_assets.id", ondelete="SET NULL"), nullable=True)

    # ── External IDs (ingestion/dedup) ─────────────────────────
    imdb_id = Column(String(32), nullable=True, unique=True)
    tmdb_id = Column(String(32), nullable=True, unique=True)

    # ── Catalog & Publishing ───────────────────────────────────
    episode_count = Column(Integer, nullable=False, server_default=text("0"))
    is_published = Column(Boolean, nullable=False, server_default=text("false"), index=True)

    # ── Timestamps (DB-driven, UTC) ────────────────────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ── Indexes & Constraints ─────────────────────────────────
    __table_args__ = (
        # One season number per title; enforce 1-based numbering
        UniqueConstraint("title_id", "season_number", name="uq_seasons_title_num"),
        UniqueConstraint("id", "title_id", name="uq_seasons_id_title"), 
        CheckConstraint("season_number >= 1", name="ck_seasons_num_ge_1"),
        CheckConstraint("episode_count >= 0", name="ck_seasons_episode_count_ge_0"),
        # Case-insensitive uniqueness of slug within a title (when slug present)
        # Temporal sanity
        CheckConstraint(
            "(end_date IS NULL) OR (release_date IS NULL) OR (end_date >= release_date)",
            name="ck_seasons_dates_order",
        ),
        CheckConstraint("updated_at >= created_at", name="ck_seasons_updated_after_created"),
        # Helpful composites
        Index("ix_seasons_title_published", "title_id", "is_published"),
        Index("uq_seasons_title_slug_ci", "title_id", func.lower(slug), unique=True),
        Index("ix_seasons_dates", "release_date", "end_date"),
        Index("ix_seasons_name_lower", func.lower(name)),
    )

    # ── Relationships ──────────────────────────────────────────

    # ⚙ add: from sqlalchemy import and_

    title = relationship(
        "Title",
        back_populates="seasons",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="Season.title_id == Title.id",
        foreign_keys="[Season.title_id]",
    )

    episodes = relationship(
        "Episode",
        back_populates="season",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        primaryjoin="and_(Episode.season_id == Season.id, Episode.title_id == Season.title_id)",
        foreign_keys="[Episode.season_id, Episode.title_id]",
        order_by="Episode.episode_number",
    )

    media_assets = relationship(
        "MediaAsset",
        back_populates="season",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="MediaAsset.season_id == Season.id",
        foreign_keys="[MediaAsset.season_id]",
    )

    artworks = relationship(
        "Artwork",
        back_populates="season",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="Artwork.season_id == Season.id",
        foreign_keys="[Artwork.season_id]",
    )

    subtitles = relationship(
        "Subtitle",
        back_populates="season",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="and_(Subtitle.season_id == Season.id, Subtitle.title_id == Season.title_id)",
        foreign_keys="[Subtitle.season_id, Subtitle.title_id]",
    )

    credits = relationship(
        "Credit",
        back_populates="season",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="Credit.season_id == Season.id",
        foreign_keys="[Credit.season_id]",
    )

    availabilities = relationship(
        "Availability",
        back_populates="season",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="Availability.season_id == Season.id",
        foreign_keys="[Availability.season_id]",
    )

    progress_entries = relationship(
        "Progress",
        back_populates="season",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="Progress.season_id == Season.id",
        foreign_keys="[Progress.season_id]",
    )

    certifications = relationship(
        "Certification",
        back_populates="season",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="Certification.season_id == Season.id",
        foreign_keys="[Certification.season_id]",
    )

    content_advisories = relationship(
        "ContentAdvisory",
        back_populates="season",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="ContentAdvisory.season_id == Season.id",
        foreign_keys="[ContentAdvisory.season_id]",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Season id={self.id} title_id={self.title_id} S{self.season_number} published={self.is_published}>"
