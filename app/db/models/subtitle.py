from __future__ import annotations

"""
📝 MoviesNow — Subtitle (logical text track)
===========================================

Represents a **text track** (subtitle/caption) associated with a `Title`, `Season`,
or `Episode`. It binds **playback semantics** (default/forced/SDH, language, label)
while the underlying file lives in `MediaAsset(kind='subtitle'|'caption')`.

Why a dedicated model?
----------------------
`MediaAsset` stores the binary/file details (storage key, checksum, size, mime),
whereas `Subtitle` captures *catalog & player rules* per scope.

Key properties
--------------
• Scope‑aware: optional links to `Title`/`Season`/`Episode` with composite FKs that
  enforce hierarchical consistency (episode ⇒ season ⇒ title).
• File binding: `asset_id` → `MediaAsset` (usually kind='subtitle' or 'caption').
• Playback flags: `is_default`, `is_forced`, `is_sdh` (hearing‑impaired/CC).
• Uniqueness guards (partial uniques): at most one **default** and one **forced**
  track per *(scope, language)* among **active** rows.
• Rich metadata: BCP‑47 `language`, `format` enum (srt/vtt/ass/ttml/…), `encoding`,
  optional `time_offset_ms`, human `label`, and JSONB `metadata`.

Relationships
-------------
• `Subtitle.title`    ↔ `Title.subtitles`
• `Subtitle.season`   ↔ `Season.subtitles`
• `Subtitle.episode`  ↔ `Episode.subtitles`
• `Subtitle.asset`    → `MediaAsset`
• `Subtitle.created_by` → `User`
"""

from uuid import uuid4
from enum import Enum as PyEnum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Enum,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.base_class import Base


# ──────────────────────────────────────────────────────────────
# 🔤 Enum: SubtitleFormat
# ──────────────────────────────────────────────────────────────
class SubtitleFormat(PyEnum):
    SRT = "SRT"
    VTT = "VTT"          # WebVTT
    ASS = "ASS"
    TTML = "TTML"        # IMSC/TTML/DFXP family
    SCC = "SCC"
    SMI = "SMI"
    UNKNOWN = "UNKNOWN"


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
    language = Column(String(16), nullable=False, index=True, doc="BCP‑47 tag (e.g., 'en', 'en-US').")
    format = Column(Enum(SubtitleFormat, name="subtitle_format"), nullable=False, server_default=text("'VTT'"))
    encoding = Column(String(32), nullable=True, doc="Text encoding (e.g., 'utf-8').")
    label = Column(String(128), nullable=True, doc="Human‑readable label (e.g., 'English [CC]').")

    # Playback flags
    is_default = Column(Boolean, nullable=False, server_default=text("false"), index=True)
    is_forced = Column(Boolean, nullable=False, server_default=text("false"), index=True)
    is_sdh = Column(Boolean, nullable=False, server_default=text("false"), index=True)  # hearing‑impaired/CC

    # Optional timing metadata
    time_offset_ms = Column(Integer, nullable=False, server_default=text("0"), doc="Track offset relative to media.")
    duration_seconds = Column(Integer, nullable=True, doc="Optional logical duration for validation/reporting.")

    # Misc
    active = Column(Boolean, nullable=False, server_default=text("true"), index=True)
    metadata_json = Column(JSONB, nullable=True, doc="Arbitrary structured info (supplier, QC flags, notes, …).")

    # Audit
    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────── Constraints & Indexes ───────────────
    __table_args__ = __table_args__ + (  # type: ignore[operator]
        # Scope coherence: at least one scope, and stronger scopes imply parents
        CheckConstraint(
            "(title_id IS NOT NULL) OR (season_id IS NOT NULL) OR (episode_id IS NOT NULL)",
            name="ck_subtitles_has_some_scope",
        ),
        CheckConstraint("(season_id IS NULL) OR (title_id IS NOT NULL)", name="ck_subtitles_season_requires_title"),
        CheckConstraint(
            "(episode_id IS NULL) OR (season_id IS NOT NULL AND title_id IS NOT NULL)",
            name="ck_subtitles_episode_requires_parents",
        ),
        # Hygiene & numeric sanity
        CheckConstraint("(time_offset_ms BETWEEN -10800000 AND 10800000)", name="ck_subtitles_offset_reasonable"),
        CheckConstraint("(duration_seconds IS NULL) OR (duration_seconds >= 0)", name="ck_subtitles_duration_nonneg"),
        CheckConstraint("updated_at >= created_at", name="ck_subtitles_updated_after_created"),
        # BCP‑47 length & shape (loose)
        CheckConstraint(
            "(char_length(language) BETWEEN 2 AND 16)",
            name="ck_subtitles_lang_len",
        ),
        CheckConstraint(
            "(language ~ '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$')",
            name="ck_subtitles_lang_shape",
        ),
        # Optional non‑blank label
        CheckConstraint("(label IS NULL) OR (length(btrim(label)) > 0)", name="ck_subtitles_label_not_blank"),

        # Partial uniques (PostgreSQL): one default/forced per (scope, language) among ACTIVE rows
        Index(
            "uq_subtitles_default_per_scope_language",
            "title_id", "season_id", "episode_id", "language",
            unique=True,
            postgresql_where=text("is_default = true AND active = true"),
        ),
        Index(
            "uq_subtitles_forced_per_scope_language",
            "title_id", "season_id", "episode_id", "language",
            unique=True,
            postgresql_where=text("is_forced = true AND active = true"),
        ),

        # JSONB/lookup helpers
        Index("ix_subtitles_scope_lang_active", "title_id", "season_id", "episode_id", "language", "active"),
        Index("ix_subtitles_metadata_gin", "metadata", postgresql_using="gin"),
        Index("ix_subtitles_created_at", "created_at"),
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
        return f"<Subtitle id={self.id} lang={self.language} fmt={self.format.name} {flags} {scope}>"