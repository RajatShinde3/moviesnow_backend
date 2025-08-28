# app/db/models/media_asset.py
from __future__ import annotations

"""
🗂️ MoviesNow — MediaAsset Model (Production-grade)
==================================================

Represents any stored/referenced **binary asset** tied to a `Title`, `Season`,
or `Episode` — e.g., posters, backdrops, stills, thumbnails, trailers, clips,
subtitles, etc.

Design highlights
-----------------
- **Scoped linking** with strong data integrity:
  • `title_id` optional (movie or series scope)
  • `season_id` optional (series season scope)
  • `episode_id` optional (per-episode scope)
  • Composite FKs ensure hierarchical **consistency** when `season_id`/`episode_id` are present.
  • CHECKs ensure scope coherence (e.g., if `episode_id` is set, `season_id` & `title_id` must be set).
- **De-dup friendly** fields: `checksum_sha256`, `bytes_size`, `mime_type`.
- **Publishing ergonomics**: `is_primary` per scope+kind+language (enforced via a partial unique index),
  `sort_order` for deterministic galleries.
- **Catalog-ready** metadata: dimensions, duration, language, tags, arbitrary JSONB metadata.
- **Safety & hygiene**: UTC DB-driven timestamps, strict CHECKs, CASCADE/SET NULL semantics.

Relationships
-------------
- `title`   → Title   (optional, CASCADE)
- `season`  → Season  (optional, CASCADE; kept consistent with `title_id`)
- `episode` → Episode (optional, CASCADE; kept consistent with `season_id` and `title_id`)
- `uploaded_by` → User (optional, SET NULL)

Tip
---
Use canonical pointers on `Title/Season/Episode` (e.g., `poster_asset_id`,
`backdrop_asset_id`, `trailer_asset_id`) for the “featured” asset, and keep the
full gallery under `MediaAsset` rows with `is_primary`/`sort_order`.
"""

from uuid import uuid4

from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    ForeignKeyConstraint,
    CheckConstraint,
    UniqueConstraint,
    Index,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class MediaAssetKind(str):
    """String enum values for asset kinds (kept as plain strings for portability)."""

    POSTER = "poster"
    BACKDROP = "backdrop"
    BANNER = "banner"
    THUMBNAIL = "thumbnail"
    STILL = "still"
    TRAILER = "trailer"
    TEASER = "teaser"
    CLIP = "clip"
    VIDEO = "video"
    IMAGE = "image"
    SUBTITLE = "subtitle"
    CAPTION = "caption"
    AUDIO = "audio"


class MediaAsset(Base):
    """Binary/media artifact associated with a Title/Season/Episode."""

    __tablename__ = "media_assets"

    # ─────────────── Identity ───────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    # ─────────────── Scope (Title / Season / Episode) ───────────────
    title_id = Column(UUID(as_uuid=True), ForeignKey("titles.id", ondelete="CASCADE"), nullable=True, index=True)

    season_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    # Keep season/title consistent when season_id is present
    # (FK is nullable, but when season_id is not NULL the pair must exist)
    # NOTE: add a CHECK below to ensure title_id is not NULL when season_id is set.
    episode_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    # Keep episode/season/title consistent when episode_id is present
    # (composite FK to episodes ensures hierarchical provenance)

    # Composite FKs for hierarchical integrity (NULL-safe)
    __table_args__ = (
        ForeignKeyConstraint(
            ["season_id", "title_id"],
            ["seasons.id", "seasons.title_id"],
            ondelete="CASCADE",
            name="fk_media_assets_season_title_consistent",
        ),
        ForeignKeyConstraint(
            ["episode_id", "season_id", "title_id"],
            ["episodes.id", "episodes.season_id", "episodes.title_id"],
            ondelete="CASCADE",
            name="fk_media_assets_episode_season_title_consistent",
        ),
    )

    # ─────────────── Kind / Language ───────────────
    kind = Column(
        SAEnum(
            MediaAssetKind.POSTER,
            MediaAssetKind.BACKDROP,
            MediaAssetKind.BANNER,
            MediaAssetKind.THUMBNAIL,
            MediaAssetKind.STILL,
            MediaAssetKind.TRAILER,
            MediaAssetKind.TEASER,
            MediaAssetKind.CLIP,
            MediaAssetKind.VIDEO,
            MediaAssetKind.IMAGE,
            MediaAssetKind.SUBTITLE,
            MediaAssetKind.CAPTION,
            MediaAssetKind.AUDIO,
            name="media_asset_kind",
        ),
        nullable=False,
        index=True,
        doc="Type of asset (poster, backdrop, still, trailer, subtitle, etc.).",
    )
    language = Column(String(16), nullable=True, index=True, doc="BCP-47/ISO language tag (e.g., 'en', 'en-US').")

    # ─────────────── Storage / Identity ───────────────
    storage_key = Column(String(1024), nullable=False, index=True, doc="Opaque storage key (e.g., S3 object key).")
    cdn_url = Column(String(2048), nullable=True, doc="Public CDN URL, if published.")
    checksum_sha256 = Column(String(64), nullable=True, index=True, doc="Hex SHA-256 checksum for dedupe/verify.")
    bytes_size = Column(Integer, nullable=True, doc="Object size in bytes.")
    mime_type = Column(String(127), nullable=True, doc="IANA media type, e.g., 'image/jpeg', 'video/mp4'.")

    # ─────────────── Media attributes ───────────────
    width = Column(Integer, nullable=True)
    height = Column(Integer, nullable=True)
    duration_seconds = Column(Integer, nullable=True, doc="For audio/video assets.")
    frame_rate = Column(Integer, nullable=True, doc="Approx FPS (integer-rounded if needed).")

    # ─────────────── Flags / Ordering ───────────────
    is_public = Column(Boolean, nullable=False, server_default=text("false"), index=True)
    is_primary = Column(
        Boolean,
        nullable=False,
        server_default=text("false"),
        doc="Marks the 'featured' asset for its (scope, kind, language).",
    )
    sort_order = Column(Integer, nullable=False, server_default=text("0"), index=True)

    # ─────────────── Ownership / Audit ───────────────
    uploaded_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    tags = Column(JSONB, nullable=True, doc="Free-form tags (array or map).")
    metadata = Column(JSONB, nullable=True, doc="Arbitrary structured metadata (codec, bitrate, color space, etc.).")

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────── Constraints & Indexes ───────────────
    __table_args__ = __table_args__ + (  # type: ignore[operator]
        # Scope coherence: at least one scope, and “stronger” scopes imply parents.
        CheckConstraint(
            "(title_id IS NOT NULL) OR (season_id IS NOT NULL) OR (episode_id IS NOT NULL)",
            name="ck_media_assets_has_some_scope",
        ),
        CheckConstraint(
            "(season_id IS NULL) OR (title_id IS NOT NULL)",
            name="ck_media_assets_season_requires_title",
        ),
        CheckConstraint(
            "(episode_id IS NULL) OR (season_id IS NOT NULL AND title_id IS NOT NULL)",
            name="ck_media_assets_episode_requires_parents",
        ),
        # Numeric sanity
        CheckConstraint("(bytes_size IS NULL) OR (bytes_size >= 0)", name="ck_media_assets_size_nonneg"),
        CheckConstraint(
            "(width IS NULL OR width > 0) AND (height IS NULL OR height > 0)",
            name="ck_media_assets_dims_positive",
        ),
        CheckConstraint(
            "(duration_seconds IS NULL) OR (duration_seconds >= 0)",
            name="ck_media_assets_duration_nonneg",
        ),
        CheckConstraint("updated_at >= created_at", name="ck_media_assets_updated_after_created"),
        # Deterministic featured asset per scope/kind/language
        Index(
            "uq_media_assets_primary_per_scope",
            "title_id",
            "season_id",
            "episode_id",
            "kind",
            "language",
            unique=True,
            postgresql_where=text("is_primary = true"),
        ),
        # Helpful composite lookups
        Index("ix_media_assets_scope_kind", "title_id", "season_id", "episode_id", "kind"),
        Index("ix_media_assets_scope_sort", "title_id", "season_id", "episode_id", "sort_order"),
    )

    # ─────────────── Relationships ───────────────
    title = relationship(
        "Title",
        back_populates="media_assets",
        lazy="selectin",
        passive_deletes=True,
    )

    season = relationship(
        "Season",
        back_populates="media_assets",
        lazy="selectin",
        passive_deletes=True,
    )

    episode = relationship(
        "Episode",
        back_populates="media_assets",
        lazy="selectin",
        passive_deletes=True,
    )

    uploaded_by = relationship(
        "User",
        lazy="selectin",
        passive_deletes=True,
    )
    stream_variants = relationship(
        "StreamVariant",
        back_populates="media_asset",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        order_by="StreamVariant.bandwidth_bps.asc()",
    )

    def __repr__(self) -> str:  # pragma: no cover
        scope = (
            f"title={self.title_id}, season={self.season_id}, episode={self.episode_id}"
        )
        return f"<MediaAsset id={self.id} kind={self.kind} {scope} primary={self.is_primary}>"
