# app/db/models/episode.py
from __future__ import annotations

"""
🎬 MoviesNow — Episode Model (Production-grade)
==============================================

Represents a single **Episode** that belongs to a **Season** (which itself
belongs to a `Title` of type **SERIES**).

Why this design?
----------------
- **Integrity by design**: we carry both `season_id` and `title_id`, and enforce
  a composite FK `(season_id, title_id) → (seasons.id, seasons.title_id)` so an
  episode’s `title_id` can never mismatch its parent season’s title.
- **Clean uniqueness**: `(season_id, episode_number)` is unique; case-insensitive
  slug uniqueness **per season**.
- **Catalog-ready fields**: names, overviews, artwork/trailer pointers, external
  IDs (TMDB/IMDB/TVDB), air dates, and publishing flags.
- **Defensive constraints**: positive runtime, natural numbering, DB-driven UTC
  timestamps, and helpful indexes for common queries.

Relationships
-------------
- `season`        → Season (parent)               [back_populates="episodes"]
- `title`         → Title  (denormalized pointer, integrity enforced)
- `media_assets`  → optional season/title-scoped MediaAsset rows via FKs below
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
    ForeignKeyConstraint,
    UniqueConstraint,
    CheckConstraint,
    Index,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class Episode(Base):
    """
    A single episode within a season.

    Notes
    -----
    • `episode_number` is 1-based by default; `0` may be used for “Specials”.  
    • `title_id` is stored for query convenience and **kept consistent** with
      the parent `Season` via a composite foreign key.  
    • Artwork/trailer columns are canonical *pointers* to preferred assets
      (you can still store all variants in `MediaAsset` with `episode_id`).
    """

    __tablename__ = "episodes"

    # ─────────────── Identity ───────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    season_id = Column(
        UUID(as_uuid=True),
        ForeignKey("seasons.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Parent Season.",
    )

    title_id = Column(
        UUID(as_uuid=True),
        ForeignKey("titles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Denormalized parent Title (integrity enforced via composite FK).",
    )

    # Keep title_id in sync with season.title_id (hard DB guarantee)
    __table_args__ = (
        ForeignKeyConstraint(
            ["season_id", "title_id"],
            ["seasons.id", "seasons.title_id"],
            ondelete="CASCADE",
            name="fk_episodes_season_title_consistent",
        ),
        # uniqueness & constraints are appended below
    )

    # ─────────────── Ordinal / Naming / SEO ───────────────
    episode_number = Column(
        Integer,
        nullable=False,
        doc="Ordinal episode number within the season (1-based; 0 allowed for Specials).",
    )
    absolute_number = Column(
        Integer,
        nullable=True,
        doc="Optional absolute ordering across the whole series.",
    )

    name = Column(String(255), nullable=True)
    slug = Column(String(255), nullable=True, index=True, doc="Optional URL-safe slug unique per season.")

    # ─────────────── Synopsis & Timing ───────────────
    overview = Column(String, nullable=True)
    air_date = Column(Date, nullable=True, index=True)
    runtime_minutes = Column(Integer, nullable=True)

    # ─────────────── Artwork / Trailer (canonical pointers) ───────────────
    still_asset_id = Column(UUID(as_uuid=True), ForeignKey("media_assets.id", ondelete="SET NULL"), nullable=True)
    thumbnail_asset_id = Column(UUID(as_uuid=True), ForeignKey("media_assets.id", ondelete="SET NULL"), nullable=True)
    trailer_asset_id = Column(UUID(as_uuid=True), ForeignKey("media_assets.id", ondelete="SET NULL"), nullable=True)

    # ─────────────── External IDs (ingestion/dedup) ───────────────
    imdb_id = Column(String(32), nullable=True, unique=True)
    tmdb_id = Column(String(32), nullable=True, unique=True)
    tvdb_id = Column(String(32), nullable=True, unique=True)

    # ─────────────── Catalog & Publishing ───────────────
    is_published = Column(Boolean, nullable=False, server_default=text("false"), index=True)

    # ─────────────── Timestamps (DB-driven, UTC) ───────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────── Indexes & Constraints ───────────────
    __table_args__ = __table_args__ + (  # type: ignore[operator]
        # One episode number per season
        UniqueConstraint("season_id", "episode_number", name="uq_episodes_season_epnum"),
        # Case-insensitive slug uniqueness within a season (when slug provided)
        UniqueConstraint("season_id", func.lower(slug), name="uq_episodes_season_slug_ci"),
        # Reasonable numeric guards
        CheckConstraint("episode_number >= 0", name="ck_episodes_num_ge_0"),
        CheckConstraint(
            "(runtime_minutes IS NULL) OR (runtime_minutes BETWEEN 1 AND 1000)",
            name="ck_episodes_runtime_sane",
        ),
        CheckConstraint("updated_at >= created_at", name="ck_episodes_updated_after_created"),
        # Helpful composite indexes
        Index("ix_episodes_title_airdate", "title_id", "air_date"),
        Index("ix_episodes_season_published", "season_id", "is_published"),
    )

    # ─────────────── Relationships ───────────────
    season = relationship(
        "Season",
        back_populates="episodes",
        lazy="selectin",
        passive_deletes=True,
    )

    # Optional convenience; no back_populates to avoid requiring Title.episodes
    title = relationship(
        "Title",
        lazy="selectin",
        passive_deletes=True,
        viewonly=True,  # integrity is carried via the composite FK
        primaryjoin="Episode.title_id == Title.id",
    )

    # Example: episode-scoped assets (stills, thumbnails, etc.) if you model them
    media_assets = relationship(
        "MediaAsset",
        back_populates="episode",
        lazy="selectin",
        passive_deletes=True,
    )
    subtitles = relationship("Subtitle", back_populates="episode", passive_deletes=True, lazy="selectin")
    credits = relationship("Credit", back_populates="episode", cascade="all, delete-orphan", passive_deletes=True, lazy="selectin")
    availabilities = relationship(
        "Availability",
        back_populates="episode",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    progress_entries = relationship(
        "Progress",
        back_populates="episode",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    playback_sessions = relationship(
        "PlaybackSession",
        back_populates="episode",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Episode id={self.id} season_id={self.season_id} "
            f"E{self.episode_number} published={self.is_published}>"
        )
