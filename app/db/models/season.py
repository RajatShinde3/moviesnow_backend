# app/db/models/season.py
from __future__ import annotations

"""
📺 MoviesNow — Season Model (Production-grade)
=============================================

Represents a **Season** that belongs to a `Title` of type **SERIES**.
A season aggregates metadata and artwork for a contiguous set of episodes.

Design goals
------------
- Strong **entity boundaries**: each Season is scoped to a single Title
- Clean **uniqueness**: `(title_id, season_number)` and case-insensitive slug
- Practical fields for **ingest**, **catalog**, and **UI** (dates, artwork, IDs)
- DB-driven timestamps and defensive **constraints**
- Relationships tuned for FastAPI/SQLAlchemy async with `selectin` loading

Key relationships
-----------------
- `title`     → Title (parent)                      [back_populates="seasons"]
- `episodes`  → Episode (children)                  [back_populates="season"]
- `media_assets` (optional) → MediaAsset (season-scoped artwork/teasers)
"""

from uuid import uuid4

from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    CheckConstraint,
    Index,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class Season(Base):
    """
    Season container for a series.

    Notes
    -----
    • `(title_id, season_number)` is unique; `season_number` starts at **1**.  
    • `slug` is optional but useful for readable URLs; uniqueness is enforced
      **per title** and **case-insensitive**.  
    • `poster_asset_id`/`backdrop_asset_id`/`trailer_asset_id` are *pointers*
      to the preferred artwork/trailer (all variants can still live in
      `MediaAsset` with a `season_id` FK).
    """

    __tablename__ = "seasons"

    # ─────────────── Identity ───────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    title_id = Column(
        UUID(as_uuid=True),
        ForeignKey("titles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Parent Title (must be a SERIES).",
    )

    # ─────────────── Ordinal / Naming / SEO ───────────────
    season_number = Column(Integer, nullable=False, doc="Ordinal season number (1-based).")
    name = Column(String(255), nullable=True, doc="Optional display name (e.g., 'Season of Fire').")
    slug = Column(String(255), nullable=True, index=True, doc="Optional URL-safe slug unique per title.")

    # ─────────────── Synopsis ───────────────
    overview = Column(String, nullable=True)

    # ─────────────── Dates ───────────────
    release_date = Column(Date, nullable=True, index=True, doc="First air date for the season.")
    end_date = Column(Date, nullable=True, doc="Last air date for the season (if concluded).")

    # ─────────────── Artwork / Trailer (canonical pointers) ───────────────
    poster_asset_id = Column(UUID(as_uuid=True), ForeignKey("media_assets.id", ondelete="SET NULL"), nullable=True)
    backdrop_asset_id = Column(UUID(as_uuid=True), ForeignKey("media_assets.id", ondelete="SET NULL"), nullable=True)
    trailer_asset_id = Column(UUID(as_uuid=True), ForeignKey("media_assets.id", ondelete="SET NULL"), nullable=True)

    # ─────────────── External IDs (ingestion/dedup) ───────────────
    imdb_id = Column(String(32), nullable=True, unique=True)
    tmdb_id = Column(String(32), nullable=True, unique=True)

    # ─────────────── Catalog & Publishing ───────────────
    episode_count = Column(Integer, nullable=False, server_default=text("0"))
    is_published = Column(Boolean, nullable=False, server_default=text("false"), index=True)

    # ─────────────── Timestamps (DB-driven, UTC) ───────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────── Indexes & Constraints ───────────────
    __table_args__ = (
        # One season number per title; enforce 1-based numbering
        UniqueConstraint("title_id", "season_number", name="uq_seasons_title_num"),
        CheckConstraint("season_number >= 1", name="ck_seasons_num_ge_1"),
        CheckConstraint("episode_count >= 0", name="ck_seasons_episode_count_ge_0"),
        # Case-insensitive uniqueness of slug within a title (when slug present)
        UniqueConstraint(
            "title_id",
            func.lower(slug),
            name="uq_seasons_title_slug_ci",
        ),
        Index("ix_seasons_title_published", "title_id", "is_published"),
        Index("ix_seasons_dates", "release_date", "end_date"),
    )

    # ─────────────── Relationships ───────────────
    title = relationship(
        "Title",
        back_populates="seasons",
        lazy="selectin",
        passive_deletes=True,
    )

    episodes = relationship(
        "Episode",
        back_populates="season",
        lazy="selectin",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="Episode.episode_number",  # natural ordering
    )

    # Optional: season-scoped asset rows (thumbnails, stills, teasers, etc.)
    media_assets = relationship(
        "MediaAsset",
        back_populates="season",
        lazy="selectin",
        passive_deletes=True,
    )
    subtitles = relationship("Subtitle", back_populates="season", passive_deletes=True, lazy="selectin")
    credits = relationship("Credit", back_populates="season", cascade="all, delete-orphan", passive_deletes=True, lazy="selectin")
    availabilities = relationship(
        "Availability",
        back_populates="season",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    progress_entries = relationship(
        "Progress",
        back_populates="season",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    def __repr__(self) -> str:  # pragma: no cover
        return f"<Season id={self.id} title_id={self.title_id} S{self.season_number} published={self.is_published}>"
