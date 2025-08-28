# app/db/models/subtitle.py
from __future__ import annotations

"""
📝 MoviesNow — Subtitle Model (Production-grade)
===============================================

Represents a **text track** (subtitle/caption) associated with a `Title`,
`Season`, or `Episode`. This model stores track-level metadata (language,
role/flags, default/forced) and points to the underlying binary **file** via
`MediaAsset` (which carries storage info, checksum, size, mime, etc.).

Why a dedicated model?
----------------------
`MediaAsset(kind='subtitle')` captures the file itself, while `Subtitle`
captures **playback semantics** and catalog metadata (e.g., default/forced [per
scope+language], hearing-impaired/SDH, track label). This separation avoids
overloading assets with player rules and enables clean querying per scope.

Key properties
--------------
- **Scope-aware**: Optional links to `Title`, `Season`, `Episode` with composite
  FKs that preserve hierarchical consistency (episode ⇒ season ⇒ title).
- **File binding**: `asset_id` → `MediaAsset` (typically `kind='subtitle'`).
- **Playback flags**: `is_default`, `is_forced`, `is_sdh` (hearing-impaired).
- **Uniqueness guards** (PostgreSQL partial unique indexes):
  • at most one **default** track per (scope, language)  
  • at most one **forced** track per (scope, language)
- **Rich metadata**: `language` (BCP-47), `format` (srt/vtt/ass/ttml), `encoding`,
  optional `time_offset_ms`, `label`, and arbitrary JSON `metadata`.

Relations
---------
- `title`   → Title     (optional, CASCADE)
- `season`  → Season    (optional, CASCADE; consistent with `title_id`)
- `episode` → Episode   (optional, CASCADE; consistent with `season_id/title_id`)
- `asset`   → MediaAsset(kind='subtitle' or 'caption') (CASCADE)
- `created_by` → User   (optional, SET NULL)
"""

from uuid import uuid4

from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    CheckConstraint,
    Index,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class Subtitle(Base):
    """Logical subtitle/caption track bound to a media asset and a catalog scope."""

    __tablename__ = "subtitles"

    # ─────────────── Identity ───────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    # ─────────────── Scope (Title / Season / Episode) ───────────────
    title_id = Column(UUID(as_uuid=True), ForeignKey("titles.id", ondelete="CASCADE"), nullable=True, index=True)

    season_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    episode_id = Column(UUID(as_uuid=True), nullable=True, index=True)

    # Composite FKs to protect hierarchy coherence when season/episode are present
    __table_args__ = (
        ForeignKeyConstraint(
            ["season_id", "title_id"],
            ["seasons.id", "seasons.title_id"],
            ondelete="CASCADE",
            name="fk_subtitles_season_title_consistent",
        ),
        ForeignKeyConstraint(
            ["episode_id", "season_id", "title_id"],
            ["episodes.id", "episodes.season_id", "episodes.title_id"],
            ondelete="CASCADE",
            name="fk_subtitles_episode_season_title_consistent",
        ),
    )

    # ─────────────── File binding ───────────────
    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("media_assets.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,  # one track per asset
        index=True,
        doc="Points to MediaAsset row carrying the actual subtitle file.",
    )

    # ─────────────── Track metadata ───────────────
    language = Column(
        String(16),
        nullable=False,
        index=True,
        doc="BCP-47/ISO tag (e.g., 'en', 'en-US').",
    )
    format = Column(
        String(16),
        nullable=False,
        doc="Container/format (e.g., 'vtt', 'srt', 'ass', 'ttml').",
    )
    encoding = Column(String(32), nullable=True, doc="Text encoding (e.g., 'utf-8').")
    label = Column(String(128), nullable=True, doc="Human-readable label (e.g., 'English [CC]').")

    # Playback flags
    is_default = Column(Boolean, nullable=False, server_default=text("false"), index=True)
    is_forced = Column(Boolean, nullable=False, server_default=text("false"), index=True)
    is_sdh = Column(Boolean, nullable=False, server_default=text("false"), index=True)  # hearing-impaired/CC

    # Optional timing metadata
    time_offset_ms = Column(Integer, nullable=False, server_default=text("0"), doc="Track offset relative to media.")
    duration_seconds = Column(Integer, nullable=True, doc="Optional logical duration for validation/reporting.")

    # Misc
    active = Column(Boolean, nullable=False, server_default=text("true"), index=True)
    metadata = Column(JSONB, nullable=True, doc="Arbitrary structured info (supplier, notes, QC flags, etc.).")

    # Audit
    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────── Constraints & Indexes ───────────────
    __table_args__ = __table_args__ + (  # type: ignore[operator]
        # Scope coherence: at least one scope must be present
        CheckConstraint(
            "(title_id IS NOT NULL) OR (season_id IS NOT NULL) OR (episode_id IS NOT NULL)",
            name="ck_subtitles_has_some_scope",
        ),
        CheckConstraint(
            "(season_id IS NULL) OR (title_id IS NOT NULL)",
            name="ck_subtitles_season_requires_title",
        ),
        CheckConstraint(
            "(episode_id IS NULL) OR (season_id IS NOT NULL AND title_id IS NOT NULL)",
            name="ck_subtitles_episode_requires_parents",
        ),
        # Numeric sanity
        CheckConstraint("(time_offset_ms BETWEEN -10800000 AND 10800000)", name="ck_subtitles_offset_reasonable"),
        CheckConstraint(
            "(duration_seconds IS NULL) OR (duration_seconds >= 0)",
            name="ck_subtitles_duration_nonneg",
        ),
        CheckConstraint("updated_at >= created_at", name="ck_subtitles_updated_after_created"),
        # Partial uniques (PostgreSQL) to ensure one default/forced per scope+language
        Index(
            "uq_subtitles_default_per_scope_language",
            "title_id",
            "season_id",
            "episode_id",
            "language",
            unique=True,
            postgresql_where=text("is_default = true"),
        ),
        Index(
            "uq_subtitles_forced_per_scope_language",
            "title_id",
            "season_id",
            "episode_id",
            "language",
            unique=True,
            postgresql_where=text("is_forced = true"),
        ),
        # Helpful composites for listing & lookups
        Index("ix_subtitles_scope_lang_active", "title_id", "season_id", "episode_id", "language", "active"),
    )

    # ─────────────── Relationships ───────────────
    title = relationship("Title", back_populates="subtitles", lazy="selectin", passive_deletes=True)
    season = relationship("Season", back_populates="subtitles", lazy="selectin", passive_deletes=True)
    episode = relationship("Episode", back_populates="subtitles", lazy="selectin", passive_deletes=True)

    asset = relationship("MediaAsset", lazy="selectin", passive_deletes=True)
    created_by = relationship("User", lazy="selectin")

    def __repr__(self) -> str:  # pragma: no cover
        scope = f"title={self.title_id}, season={self.season_id}, episode={self.episode_id}"
        flags = f"default={self.is_default}, forced={self.is_forced}, sdh={self.is_sdh}"
        return f"<Subtitle id={self.id} lang={self.language} fmt={self.format} {flags} {scope}>"
