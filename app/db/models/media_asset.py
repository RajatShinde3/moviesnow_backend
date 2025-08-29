from __future__ import annotations

"""
🗂️ MoviesNow — MediaAsset (binary artifacts: images, video, audio, subtitles)
=============================================================================

Represents any stored/referenced **binary asset** tied to a `Title`, `Season`,
or `Episode` — e.g., posters, backdrops, stills, thumbnails, trailers, clips,
subtitles, etc.

Design highlights
-----------------
• **Scoped linking** with strong integrity:
  - Optional scope columns: `title_id`, `season_id`, `episode_id`
  - Composite FKs keep (season_id,title_id) and (episode_id,season_id,title_id) consistent
  - CHECKs ensure scope coherence (episode ⇒ season & title; season ⇒ title)
• **De-dup friendly**: `checksum_sha256`, `bytes_size`, `mime_type`, and **unique `storage_key`**
• **Publishing ergonomics**: `is_primary` per (scope, kind, language) via a partial unique index;
  `sort_order` for deterministic galleries
• **Catalog metadata**: dimensions, duration, language tag, tags, JSONB metadata
• **Safety & hygiene**: DB-driven UTC timestamps, strict CHECKs, CASCADE/SET NULL semantics

Relationships
-------------
• `MediaAsset.title`            ↔  `Title.media_assets`
• `MediaAsset.season`           ↔  `Season.media_assets`
• `MediaAsset.episode`          ↔  `Episode.media_assets`
• `MediaAsset.stream_variants`  ↔  `StreamVariant.media_asset`
• `MediaAsset.uploaded_by`       →  `User` (optional, SET NULL)
"""

from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.base_class import Base
from app.schemas.enums import MediaAssetKind


# ──────────────────────────────────────────────────────────────
# 📦 Model: MediaAsset
# ──────────────────────────────────────────────────────────────
class MediaAsset(Base):
    """Binary/media artifact associated with a Title/Season/Episode."""

    __tablename__ = "media_assets"

    # ── Identity ──────────────────────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    # ── Scope (Title / Season / Episode) ─────────────────────
    title_id = Column(UUID(as_uuid=True), ForeignKey("titles.id", ondelete="CASCADE"), nullable=True, index=True)
    season_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    episode_id = Column(UUID(as_uuid=True), nullable=True, index=True)

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

    # ── Kind / Language ──────────────────────────────────────
    kind = Column(
        SAEnum(MediaAssetKind, name="media_asset_kind"),
        nullable=False,
        index=True,
        doc="Type of asset (poster, backdrop, still, trailer, subtitle, etc.).",
    )
    language = Column(String(16), nullable=True, index=True, doc="BCP-47 language tag (e.g., 'en', 'en-US').")

    # ── Storage / Identity ───────────────────────────────────
    storage_key = Column(String(1024), nullable=False, index=True, doc="Opaque storage key (e.g., S3 object key).")
    cdn_url = Column(String(2048), nullable=True, doc="Public CDN URL, if published.")
    checksum_sha256 = Column(String(64), nullable=True, index=True, doc="Hex SHA-256 checksum for dedupe/verify.")
    bytes_size = Column(Integer, nullable=True, doc="Object size in bytes.")
    mime_type = Column(String(127), nullable=True, doc="IANA media type, e.g., 'image/jpeg', 'video/mp4'.")

    # ── Media attributes ─────────────────────────────────────
    width = Column(Integer, nullable=True)
    height = Column(Integer, nullable=True)
    duration_seconds = Column(Integer, nullable=True, doc="For audio/video assets.")
    frame_rate = Column(Integer, nullable=True, doc="Approx FPS (integer-rounded if needed).")

    # ── Flags / Ordering ─────────────────────────────────────
    is_public = Column(Boolean, nullable=False, server_default=text("false"), index=True)
    is_primary = Column(
        Boolean,
        nullable=False,
        server_default=text("false"),
        doc="Marks the featured asset for its (scope, kind, language).",
    )
    sort_order = Column(Integer, nullable=False, server_default=text("0"), index=True)

    # ── Ownership / Audit ────────────────────────────────────
    uploaded_by_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        doc="Uploader (optional).",
    )

    tags = Column(JSONB, nullable=True, doc="Free-form tags (array or map).")
    metadata_json = Column(
        "metadata",
        JSONB,
        nullable=True,
        doc="Arbitrary structured metadata (codec, bitrate, color space, etc.).",
    )

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────────────────────────────────────────────────
    # 🔒 Constraints & 📇 Indexes
    # ─────────────────────────────────────────────────────────
    __table_args__ = __table_args__ + (
        # Scope coherence: at least one scope, and deeper scopes imply parents
        CheckConstraint(
            "(title_id IS NOT NULL) OR (season_id IS NOT NULL) OR (episode_id IS NOT NULL)",
            name="ck_media_assets_has_some_scope",
        ),
        CheckConstraint("(season_id IS NULL) OR (title_id IS NOT NULL)", name="ck_media_assets_season_requires_title"),
        CheckConstraint(
            "(episode_id IS NULL) OR (season_id IS NOT NULL AND title_id IS NOT NULL)",
            name="ck_media_assets_episode_requires_parents",
        ),

        # Numeric/file sanity
        CheckConstraint("(bytes_size IS NULL) OR (bytes_size >= 0)", name="ck_media_assets_size_nonneg"),
        CheckConstraint(
            "(width IS NULL OR width > 0) AND (height IS NULL OR height > 0)",
            name="ck_media_assets_dims_positive",
        ),
        CheckConstraint("(duration_seconds IS NULL) OR (duration_seconds >= 0)", name="ck_media_assets_duration_nonneg"),
        CheckConstraint("(frame_rate IS NULL) OR (frame_rate > 0)", name="ck_media_assets_fps_pos"),
        CheckConstraint("(sort_order >= 0)", name="ck_media_assets_sort_nonneg"),
        CheckConstraint("updated_at >= created_at", name="ck_media_assets_updated_after_created"),
        CheckConstraint("length(btrim(storage_key)) > 0", name="ck_media_assets_storage_key_not_blank"),
        CheckConstraint(
            "(language IS NULL) OR (length(btrim(language)) > 0)",
            name="ck_media_assets_language_not_blank",
        ),

        # Deterministic featured asset per (scope, kind, language)
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

        # Helpful lookups
        UniqueConstraint("storage_key", name="uq_media_assets_storage_key"),
        Index("ix_media_assets_scope_kind", "title_id", "season_id", "episode_id", "kind"),
        Index("ix_media_assets_scope_sort", "title_id", "season_id", "episode_id", "sort_order"),
        Index("ix_media_assets_kind_lang", "kind", "language"),
        Index("ix_media_assets_created_at", "created_at"),
        Index("ix_media_assets_tags_gin", "tags", postgresql_using="gin"),
        Index("ix_media_assets_metadata_gin", "metadata", postgresql_using="gin"),
    )

    # ─────────────────────────────────────────────────────────
    # 🔗 Relationships (disambiguated)
    # ─────────────────────────────────────────────────────────
    title = relationship(
        "Title",
        back_populates="media_assets",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="MediaAsset.title_id == Title.id",
        foreign_keys="[MediaAsset.title_id]",
    )

    season = relationship(
        "Season",
        back_populates="media_assets",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="MediaAsset.season_id == Season.id",
        foreign_keys="[MediaAsset.season_id]",
    )

    episode = relationship(
        "Episode",
        back_populates="media_assets",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="MediaAsset.episode_id == Episode.id",
        foreign_keys="[MediaAsset.episode_id]",
    )

    uploaded_by = relationship(
        "User",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="MediaAsset.uploaded_by_id == User.id",           
        foreign_keys="[MediaAsset.uploaded_by_id]",                   
    )

    stream_variants = relationship(
        "StreamVariant",
        back_populates="media_asset",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        primaryjoin="StreamVariant.media_asset_id == MediaAsset.id",
        foreign_keys="[StreamVariant.media_asset_id]",
        order_by="StreamVariant.bandwidth_bps.asc()",
    )

    # ─────────────────────────────────────────────────────────
    # 🧾 Repr
    # ─────────────────────────────────────────────────────────
    def __repr__(self) -> str:  # pragma: no cover
        scope = f"title={self.title_id}, season={self.season_id}, episode={self.episode_id}"
        return f"<MediaAsset id={self.id} kind={self.kind} {scope} primary={self.is_primary}>"
