from __future__ import annotations

"""
🎨 MoviesNow — Artwork (image assets)
=====================================

Production‑grade image metadata for posters, backdrops, logos, thumbnails, and stills.

Why keep a dedicated Artwork model?
-----------------------------------
• Normalize **all imagery** (movies & series) under one schema.
• Link to **exactly one** parent: Title *or* Season *or* Episode (enforced).
• Store canonical storage key, optional CDN URL, MIME, dimensions, and hash.
• Mark **one primary** asset per (parent, kind, language) via a partial unique index.
• Include focal point + color hints for smart crops and theme extraction.

Relationships
-------------
• `Artwork.title`   ↔ `Title.artworks`
• `Artwork.season`  ↔ `Season.artworks`
• `Artwork.episode` ↔ `Episode.artworks`

Design conventions
------------------
• All timestamps are timezone‑aware UTC with DB‑driven defaults (`func.now()`).
• Booleans & integers use `server_default` for consistent behavior across writers.
• Focal coordinates use `NUMERIC(5,4)` with checks in `[0.0, 1.0]` (no FP drift).
"""

from uuid import uuid4
from enum import Enum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship, backref
from sqlalchemy.types import Numeric

from app.db.base_class import Base


# ──────────────────────────────────────────────────────────────
# 🔤 Enum: ArtworkKind
# ──────────────────────────────────────────────────────────────
class ArtworkKind(str, Enum):
    """Classifier for image usage/placement."""

    POSTER = "POSTER"        # portrait key art for detail pages
    BACKDROP = "BACKDROP"    # wide hero / background
    LOGO = "LOGO"            # transparent title treatment
    THUMBNAIL = "THUMBNAIL"  # grid/list tiles
    STILL = "STILL"          # episodic scene still / preview
    BANNER = "BANNER"        # marketing banner (wider than backdrop)
    CARD = "CARD"            # 2:3 or 3:2 editorial card


# ──────────────────────────────────────────────────────────────
# 🧱 Model: Artwork
# ──────────────────────────────────────────────────────────────
class Artwork(Base):
    """Image asset linked to **exactly one** of Title/Season/Episode.

    Identity
    --------
    Primary key is a UUID. Exactly one of `title_id`, `season_id`, `episode_id`
    must be set; this is validated with a check constraint.

    Primary selection
    -----------------
    A partial unique index ensures at most one **primary** asset exists per
    (parent, kind, language). Use this to choose the default poster/backdrop for
    a given locale without scanning all assets.
    """

    __tablename__ = "artworks"

    # Identity
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    # Parent (exactly one must be set) — ON DELETE CASCADE
    title_id = Column(UUID(as_uuid=True), ForeignKey("titles.id", ondelete="CASCADE"), nullable=True, index=True)
    season_id = Column(UUID(as_uuid=True), ForeignKey("seasons.id", ondelete="CASCADE"), nullable=True, index=True)
    episode_id = Column(UUID(as_uuid=True), ForeignKey("episodes.id", ondelete="CASCADE"), nullable=True, index=True)

    # Classification
    kind = Column(SAEnum(ArtworkKind, name="artwork_kind"), nullable=False, index=True)
    language = Column(String(15), nullable=True, index=True, doc="BCP‑47 (e.g., 'en', 'en-US')")
    region = Column(String(2), nullable=True, doc="ISO‑3166 alpha‑2 (optional targeting)")

    # Storage / addressing
    storage_key = Column(
        String,
        nullable=False,
        unique=True,
        doc="Canonical object key in storage (e.g., 'art/title/<uuid>/poster_1080.jpg')",
    )
    cdn_url = Column(String, nullable=True, doc="Optional absolute CDN URL if precomputed")

    # File / image properties
    content_type = Column(String(64), nullable=False, doc="MIME type (e.g., image/jpeg)")
    width = Column(Integer, nullable=True)
    height = Column(Integer, nullable=True)
    file_size = Column(Integer, nullable=True, doc="Bytes")
    sha256 = Column(String(64), nullable=True, index=True, doc="Optional hex digest for dedup/integrity")

    # Presentation hints
    dominant_color = Column(String(7), nullable=True, doc="Hex like '#1a2b3c'")
    palette = Column(JSONB, nullable=True, doc="Optional color palette JSON (swatches, vibrancy, etc.)")
    focus_x = Column(Numeric(5, 4), nullable=True, doc="Focal X in [0,1]")
    focus_y = Column(Numeric(5, 4), nullable=True, doc="Focal Y in [0,1]")

    # Editorial flags
    is_primary = Column(Boolean, nullable=False, server_default=text("false"), index=True)
    sort_order = Column(Integer, nullable=False, server_default=text("0"))

    # Timestamps (DB-driven, UTC)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # Indexes & Constraints
    __table_args__ = (
        # Exactly one parent must be set (Title OR Season OR Episode)
        CheckConstraint(
            "(CASE WHEN title_id  IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN season_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN episode_id IS NOT NULL THEN 1 ELSE 0 END) = 1",
            name="ck_artworks_exactly_one_parent",
        ),
        # Positive dimensions when present
        CheckConstraint("(width  IS NULL OR width  > 0)", name="ck_artworks_width_pos"),
        CheckConstraint("(height IS NULL OR height > 0)", name="ck_artworks_height_pos"),
        CheckConstraint("(file_size IS NULL OR file_size >= 0)", name="ck_artworks_filesize_nonneg"),
        # Focal points within [0,1]
        CheckConstraint(
            "(focus_x IS NULL OR (focus_x >= 0.0 AND focus_x <= 1.0))",
            name="ck_artworks_focus_x_unit",
        ),
        CheckConstraint(
            "(focus_y IS NULL OR (focus_y >= 0.0 AND focus_y <= 1.0))",
            name="ck_artworks_focus_y_unit",
        ),
        # Basic format checks
        CheckConstraint("(dominant_color IS NULL OR length(dominant_color)=7)", name="ck_artworks_hex_len"),
        CheckConstraint("(sort_order >= 0)", name="ck_artworks_sort_order_nonneg"),
        # One **primary** asset per (parent, kind, language)
        Index(
            "uq_artworks_primary_per_parent",
            "title_id",
            "season_id",
            "episode_id",
            "kind",
            "language",
            unique=True,
            postgresql_where=text("is_primary = true"),
        ),
        # Parent‑scoped accelerators (one per possible parent)
        Index(
            "ix_artworks_title_kind_lang",
            "title_id",
            "kind",
            "language",
            postgresql_where=text("title_id IS NOT NULL"),
        ),
        Index(
            "ix_artworks_season_kind_lang",
            "season_id",
            "kind",
            "language",
            postgresql_where=text("season_id IS NOT NULL"),
        ),
        Index(
            "ix_artworks_episode_kind_lang",
            "episode_id",
            "kind",
            "language",
            postgresql_where=text("episode_id IS NOT NULL"),
        ),
        Index("ix_artworks_created_at", "created_at"),
        # Ensure non‑blank storage key at DB level (in addition to `nullable=False`)
        CheckConstraint("length(btrim(storage_key)) > 0", name="ck_artworks_storage_key_not_blank"),
    )

    # Two‑way relationships (ready to match Title/Season/Episode models)
    title = relationship(
        "Title",
        back_populates="artworks",
        lazy="selectin",
        passive_deletes=True,
    )
    season = relationship(
        "Season",
        back_populates="artworks",
        lazy="selectin",
        passive_deletes=True,
    )
    episode = relationship(
        "Episode",
        back_populates="artworks",
        lazy="selectin",
        passive_deletes=True,
    )

    # ──────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────
    def parent_ref(self) -> str:
        """Return a compact parent reference string for logs (e.g., `T:…`, `S:…`, `E:…`)."""
        if self.title_id:
            return f"T:{self.title_id}"
        if self.season_id:
            return f"S:{self.season_id}"
        return f"E:{self.episode_id}"

    def __repr__(self) -> str:  # pragma: no cover
        who = self.parent_ref()
        return f"<Artwork id={self.id} kind={self.kind} primary={self.is_primary} parent={who}>"
