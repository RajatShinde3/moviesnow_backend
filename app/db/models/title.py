# app/db/models/title.py
from __future__ import annotations

"""
🎬 MoviesNow — Title Model (Production-grade)
============================================

Represents a **canonical video work**: either a single **Movie** or a **Series**
(parent container of seasons/episodes). Designed for clean indexing, search,
and delivery-pipeline integration.

Highlights
----------
- First-class `type` (MOVIE/SERIES) + `status` (ANNOUNCED/RELEASED/ENDED/…)
- SEO-safe `slug` with case-insensitive uniqueness
- Rich release metadata (year/date), countries & languages (ISO codes)
- Canonical poster/backdrop/trailer *pointers* via optional MediaAsset FKs
- External IDs (IMDB/TMDB) for ingestion & deduplication
- Popularity/rating fields for sorting and ranking
- Timestamps driven by DB; eager defaults for consistent ORM behavior
- Strict constraints & useful composite/functional indexes

Relationships (to be added in their models)
-------------------------------------------
- `seasons`           → Season(title_id)                      [selectin]
- `media_assets`      → MediaAsset(title_id)                  [selectin]
- `credits`           → Credit(title_id)                      [selectin]
- `genres`            → via association table `title_genres`  [M2M]
- `watchlists`        → Watchlist(title_id)                   [selectin]
- `availabilities`    → Availability(title_id)                [selectin]
- `reviews`           → Review(title_id)                      [selectin]
- `progress_entries`  → Progress(title_id)                    [selectin]
"""

from enum import Enum
from uuid import uuid4

from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    Date,
    DateTime,
    Enum as SAEnum,
    Index,
    CheckConstraint,
    UniqueConstraint,
    ForeignKey,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, ARRAY, BIGINT
from sqlalchemy.orm import relationship

from app.db.base_class import Base


# ──────────────────────────────────────────────────────────────
# 📚 Enums
# ──────────────────────────────────────────────────────────────
class TitleType(str, Enum):
    MOVIE = "MOVIE"
    SERIES = "SERIES"


class TitleStatus(str, Enum):
    ANNOUNCED = "ANNOUNCED"
    IN_PRODUCTION = "IN_PRODUCTION"
    RELEASED = "RELEASED"
    ENDED = "ENDED"
    CANCELED = "CANCELED"
    HIATUS = "HIATUS"


# ──────────────────────────────────────────────────────────────
# 🎬 Model
# ──────────────────────────────────────────────────────────────
class Title(Base):
    """
    Canonical catalog entity for Movies and Series.

    Notes
    -----
    • **Movies**: use `runtime_minutes`, optional `movie_part` for multi-part films,
      and `collection_id` (when you introduce a `Collection` model).
    • **Series**: children live in `Season` (and `Episode` under Season).
    • Prefer **MediaAsset** rows for artwork/trailers; `poster_asset_id`/etc. are
      canonical *pointers* for the primary assets.
    """

    __tablename__ = "titles"

    # ─────────────── Identity ───────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    # ─────────────── Classification ───────────────
    type = Column(SAEnum(TitleType, name="title_type"), nullable=False, index=True)
    status = Column(SAEnum(TitleStatus, name="title_status"), nullable=False, index=True, server_default=text("'ANNOUNCED'"))

    # ─────────────── Names & SEO ───────────────
    name = Column(String(255), nullable=False, doc="Display name in default locale (e.g., English).")
    original_name = Column(String(255), nullable=True, doc="Original/primary production name.")
    slug = Column(String(255), nullable=False, unique=True, index=True, doc="URL-safe unique slug.")

    # ─────────────── Synopsis ───────────────
    overview = Column(String, nullable=True)
    tagline = Column(String(255), nullable=True)

    # ─────────────── Release / Runtime ───────────────
    release_year = Column(Integer, nullable=True, index=True)
    release_date = Column(Date, nullable=True, index=True)
    end_date = Column(Date, nullable=True, comment="For series: last air date when ended.")
    runtime_minutes = Column(Integer, nullable=True, comment="For movies: total runtime in minutes.")
    movie_part = Column(Integer, nullable=True, comment="For multi-part movies (1,2,3,...).")

    # ─────────────── Locales & Audience ───────────────
    origin_countries = Column(ARRAY(String(2)), nullable=True, comment="ISO-3166-1 alpha-2 country codes (e.g., ['US','IN']).")
    spoken_languages = Column(ARRAY(String(8)), nullable=True, comment="IETF/ISO language codes (e.g., ['en','hi']).")
    content_rating = Column(String(16), nullable=True, comment="Certification, e.g., 'PG-13', 'U/A 13+'.")
    is_adult = Column(Boolean, nullable=False, server_default=text("false"))

    # ─────────────── Artwork / Trailer (canonical pointers) ───────────────
    poster_asset_id = Column(UUID(as_uuid=True), ForeignKey("media_assets.id", ondelete="SET NULL"), nullable=True)
    backdrop_asset_id = Column(UUID(as_uuid=True), ForeignKey("media_assets.id", ondelete="SET NULL"), nullable=True)
    trailer_asset_id = Column(UUID(as_uuid=True), ForeignKey("media_assets.id", ondelete="SET NULL"), nullable=True)

    # ─────────────── External IDs (ingestion/dedup) ───────────────
    imdb_id = Column(String(32), nullable=True, unique=True)
    tmdb_id = Column(String(32), nullable=True, unique=True)

    # ─────────────── Popularity / Rating (aggregate) ───────────────
    popularity_score = Column(Integer, nullable=False, server_default=text("0"), index=True)
    rating_average = Column(Integer, nullable=False, server_default=text("0"), comment="Scaled 0-100 for fast sort (map from 0-10).")
    rating_count = Column(Integer, nullable=False, server_default=text("0"))

    # ─────────────── Flags ───────────────
    is_published = Column(Boolean, nullable=False, server_default=text("false"), index=True)
    is_featured = Column(Boolean, nullable=False, server_default=text("false"))

    # ─────────────── Finance (optional, useful for analytics) ───────────────
    budget_usd = Column(BIGINT, nullable=True)
    revenue_usd = Column(BIGINT, nullable=True)

    # ─────────────── Timestamps (DB-driven, UTC) ───────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────── Indexes & Constraints ───────────────
    __table_args__ = (
        # Case-insensitive uniqueness on (name, release_year) to reduce dup imports
        UniqueConstraint(func.lower(name), "release_year", name="uq_titles_name_year_ci"),
        # Basic hygiene
        CheckConstraint("runtime_minutes IS NULL OR runtime_minutes >= 0", name="ck_titles_runtime_nonneg"),
        CheckConstraint("movie_part IS NULL OR movie_part >= 1", name="ck_titles_movie_part_min_1"),
        CheckConstraint(
            "(release_year IS NULL) OR (release_year BETWEEN 1870 AND 3000)",
            name="ck_titles_release_year_sane",
        ),
        # Search/sort accelerators
        Index("ix_titles_type_status_year", "type", "status", "release_year"),
        Index("ix_titles_popularity_published", "is_published", "popularity_score"),
        Index("ix_titles_dates", "release_date", "end_date"),
    )

    # ─────────────── Relationships (defined here; targets come later) ─────────
    seasons = relationship(
        "Season",
        back_populates="title",
        lazy="selectin",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    media_assets = relationship(
        "MediaAsset",
        back_populates="title",
        lazy="selectin",
        passive_deletes=True,
    )
    credits = relationship(
        "Credit",
        back_populates="title",
        lazy="selectin",
        passive_deletes=True,
        cascade="all, delete-orphan",
    )
    # Genres via M2M
    genres = relationship(
        "Genre",
        secondary="title_genres",
        back_populates="titles",
        lazy="selectin",
        passive_deletes=True,
    )
    # Engagement/ops (to be defined in their models)
    watchlisted_by = relationship(
        "WatchlistItem",
        back_populates="title",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    collection_items = relationship(
        "CollectionItem",
        back_populates="title",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    in_collections = relationship(
        "Collection",
        secondary="collection_items",
        back_populates="titles",
        lazy="selectin",
        viewonly=True,
    )
    availabilities = relationship(
        "Availability",
        back_populates="title",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    progress_entries = relationship(
        "Progress",
        back_populates="title",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    reviews = relationship(
        "Review",
        back_populates="title",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    playback_sessions = relationship(
        "PlaybackSession",
        back_populates="title",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )
    availabilities = relationship("Availability", back_populates="title", lazy="selectin", passive_deletes=True)
    reviews = relationship("Review", back_populates="title", lazy="selectin", passive_deletes=True)
    progress_entries = relationship("Progress", back_populates="title", lazy="selectin", passive_deletes=True)
    media_assets = relationship("MediaAsset", back_populates="title", passive_deletes=True, lazy="selectin")
    subtitles = relationship("Subtitle", back_populates="title", passive_deletes=True, lazy="selectin")
    credits = relationship("Credit", back_populates="title", cascade="all, delete-orphan", passive_deletes=True, lazy="selectin")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Title id={self.id} type={self.type} name={self.name!r} published={self.is_published}>"
