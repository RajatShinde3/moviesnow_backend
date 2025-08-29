from __future__ import annotations

"""
🎬 MoviesNow — Title Model (production‑grade, deduplicated & hardened)
=====================================================================

Canonical catalog entity for a **video work**: either a single **Movie** or a
**Series** (parent of seasons/episodes). Tuned for ingestion, search, and
playback integrations with strict constraints and pragmatic indexes.

Design highlights
-----------------
• First‑class `type` (MOVIE/SERIES) and lifecycle `status`.
• Case‑insensitive **slug uniqueness** and non‑blank name/slug guards.
• Release metadata (year/date), ISO country/language arrays, optional runtime.
• Canonical **artwork/trailer pointers** to `MediaAsset` rows.
• External IDs (IMDB/TMDB) for de‑dup and backfilling.
• Popularity/ratings with **range checks**; finance fields kept non‑negative.
• Clean relationships matching the wider schema (no duplicates).

Relationships (defined here; counterparts live in their models)
--------------------------------------------------------------
• `seasons`            ↔ Season.title                     (1‑to‑many)
• `media_assets`       ↔ MediaAsset.title                 (1‑to‑many)
• `credits`            ↔ Credit.title                     (1‑to‑many)
• `genres`             ↔ M2M via `secondary="title_genres"`
• `collection_items`   ↔ CollectionItem.title             (1‑to‑many)
• `in_collections`     ↔ Collection.titles                (many‑to‑many, view‑only)
• `availabilities`     ↔ Availability.title               (1‑to‑many)
• `progress_entries`   ↔ Progress.title                   (1‑to‑many)
• `reviews`            ↔ Review.title                     (1‑to‑many)
• `playback_sessions`  ↔ PlaybackSession.title            (1‑to‑many)
• `subtitles`          ↔ Subtitle.title                   (1‑to‑many)
• `watchlisted_by`     ↔ WatchlistItem.title              (1‑to‑many)  # assumes your watchlist item class name

Conventions
-----------
• All timestamps are timezone‑aware UTC with DB‑side defaults (`func.now()`).
• Use `MediaAsset` for galleries; these pointer FKs pick the canonical poster,
  backdrop, and trailer.
• `runtime_minutes`/`movie_part` only apply to movies.
"""

from enum import Enum
from uuid import uuid4

from sqlalchemy import (
    CheckConstraint,
    Column,
    Date,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Boolean,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, ARRAY, BIGINT
from sqlalchemy.orm import relationship

from app.db.base_class import Base
from app.schemas.enums import TitleType, TitleStatus


# ──────────────────────────────────────────────────────────────
# 🎬 Model
# ──────────────────────────────────────────────────────────────
class Title(Base):
    """Canonical catalog entity for Movies and Series.

    Notes
    -----
    • **Movies**: set `runtime_minutes`; optional `movie_part` for multi‑part films.
    • **Series**: children live under `Season` → `Episode`.
    • Prefer **MediaAsset** rows for galleries; the pointer FKs here select
      the *primary* assets for UI.
    """

    __tablename__ = "titles"

    # ─────────────── Identity ───────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    # ─────────────── Classification ───────────────
    type = Column(SAEnum(TitleType, name="title_type"), nullable=False, index=True)
    status = Column(
        SAEnum(TitleStatus, name="title_status"),
        nullable=False,
        index=True,
        server_default=text("'ANNOUNCED'"),
    )

    # ─────────────── Names & SEO ───────────────
    name = Column(String(255), nullable=False, doc="Display name (default locale).")
    original_name = Column(String(255), nullable=True, doc="Original production name.")
    slug = Column(String(255), nullable=False, index=True, doc="URL‑safe slug (CI unique).")

    # ─────────────── Synopsis ───────────────
    overview = Column(String, nullable=True)
    tagline = Column(String(255), nullable=True)

    # ─────────────── Release / Runtime ───────────────
    release_year = Column(Integer, nullable=True, index=True)
    release_date = Column(Date, nullable=True, index=True)
    end_date = Column(Date, nullable=True, comment="For series: last air date when ended.")
    runtime_minutes = Column(Integer, nullable=True, comment="For movies: total runtime in minutes.")
    movie_part = Column(Integer, nullable=True, comment="For multi‑part movies (1,2,3,…).")

    # ─────────────── Locales & Audience ───────────────
    origin_countries = Column(ARRAY(String(2)), nullable=True, comment="ISO‑3166‑1 alpha‑2, e.g. ['US','IN'].")
    spoken_languages = Column(ARRAY(String(8)), nullable=True, comment="IETF/ISO codes, e.g. ['en','hi'].")
    content_rating = Column(String(16), nullable=True, comment="Certification label, e.g. 'PG‑13', 'U/A 13+'.")
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
    rating_average = Column(Integer, nullable=False, server_default=text("0"), doc="Scaled 0–100 for fast sort.")
    rating_count = Column(Integer, nullable=False, server_default=text("0"))

    # ─────────────── Flags ───────────────
    is_published = Column(Boolean, nullable=False, server_default=text("false"), index=True)
    is_featured = Column(Boolean, nullable=False, server_default=text("false"))

    # ─────────────── Finance (optional) ───────────────
    budget_usd = Column(BIGINT, nullable=True)
    revenue_usd = Column(BIGINT, nullable=True)

    # ─────────────── Timestamps (DB‑driven, UTC) ───────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────── Indexes & Constraints ───────────────
    __table_args__ = (
        # Name hygiene
        CheckConstraint("length(btrim(name)) > 0", name="ck_titles_name_not_blank"),
        CheckConstraint("length(btrim(slug)) > 0", name="ck_titles_slug_not_blank"),
        # Case‑insensitive uniqueness on slug
        Index("uq_titles_slug_lower", func.lower(slug), unique=True),
        # Reduce dup imports: CI uniqueness on (name, release_year)
        UniqueConstraint(func.lower(name), "release_year", name="uq_titles_name_year_ci"),
        # Numeric guards
        CheckConstraint("runtime_minutes IS NULL OR runtime_minutes >= 0", name="ck_titles_runtime_nonneg"),
        CheckConstraint("movie_part IS NULL OR movie_part >= 1", name="ck_titles_movie_part_min_1"),
        CheckConstraint("popularity_score >= 0", name="ck_titles_popularity_nonneg"),
        CheckConstraint("rating_average BETWEEN 0 AND 100", name="ck_titles_rating_avg_range"),
        CheckConstraint("rating_count >= 0", name="ck_titles_rating_count_nonneg"),
        CheckConstraint("budget_usd IS NULL OR budget_usd >= 0", name="ck_titles_budget_nonneg"),
        CheckConstraint("revenue_usd IS NULL OR revenue_usd >= 0", name="ck_titles_revenue_nonneg"),
        # Movie‑only fields
        CheckConstraint(
            "(type = 'MOVIE' AND runtime_minutes IS NOT NULL) OR (type <> 'MOVIE' AND runtime_minutes IS NULL) OR runtime_minutes IS NULL",
            name="ck_titles_runtime_movie_only",
        ),
        CheckConstraint(
            "(type = 'MOVIE' AND movie_part IS NOT NULL) OR (type <> 'MOVIE' AND movie_part IS NULL) OR movie_part IS NULL",
            name="ck_titles_movie_part_movie_only",
        ),
        # Dates & search/sort accelerators
        CheckConstraint("(release_year IS NULL) OR (release_year BETWEEN 1870 AND 3000)", name="ck_titles_release_year_sane"),
        Index("ix_titles_type_status_year", "type", "status", "release_year"),
        Index("ix_titles_popularity_published", "is_published", "popularity_score"),
        Index("ix_titles_dates", "release_date", "end_date"),
        # Array membership acceleration (GIN)
        Index("ix_titles_origin_countries_gin", origin_countries, postgresql_using="gin"),
        Index("ix_titles_spoken_languages_gin", spoken_languages, postgresql_using="gin"),
    )

    # ─────────────── Relationships ───────────────
    seasons = relationship(
        "Season",
        back_populates="title",
        lazy="selectin",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="Season.season_number",
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

    genres = relationship(
        "Genre",
        secondary="title_genres",
        back_populates="titles",
        lazy="selectin",
        passive_deletes=True,
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

    subtitles = relationship(
        "Subtitle",
        back_populates="title",
        passive_deletes=True,
        lazy="selectin",
    )

    # Optional; adjust to your actual watchlist item model/class name
    watchlisted_by = relationship(
        "WatchlistItem",
        back_populates="title",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Title id={self.id} type={self.type} name={self.name!r} published={self.is_published}>"