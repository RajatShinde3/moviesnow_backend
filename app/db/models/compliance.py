from __future__ import annotations

"""
🛡️ MoviesNow — Compliance (Certifications & Content Advisories)
===============================================================

Production‑grade metadata for regional content ratings and advisory flags.

Why these models?
-----------------
• Normalize **age ratings** (MPAA/BBFC/TVPG/etc.) across regions/systems.
• Capture **content advisories** (violence, language, self‑harm…), with optional
  scene‑level timing for episodes.
• Attach to **exactly one** parent: Title *or* Season *or* Episode (enforced).
• Strong constraints and partial unique indexes to prevent duplication.
• Fast queries via pragmatic composite/partial and JSONB indexes.

Relationships
-------------
• `Certification.title/season/episode`   ↔  `Title/Season/Episode.certifications`
• `ContentAdvisory.title/season/episode` ↔  `Title/Season/Episode.content_advisories`

Conventions
-----------
• Timestamps are TZ‑aware UTC and **DB‑driven** (`func.now()`).
• Booleans use `server_default` for consistent behavior across writers.
• Region codes are **upper‑case** ISO‑3166‑1 alpha‑2; language is BCP‑47.
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
    text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from app.schemas.enums import CertificationSystem, AdvisoryKind, AdvisorySeverity
from app.db.base_class import Base

# ──────────────────────────────────────────────────────────────
# 🧱 Model: Certification
# ──────────────────────────────────────────────────────────────
class Certification(Base):
    """Regional age/content rating attached to **exactly one** parent
    (Title/Season/Episode). Typically one **current** rating per
    (parent, region, system). Historical changes can be kept by
    toggling `is_current` to `false`.
    """

    __tablename__ = "certifications"

    # Identity
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    # Parent (exactly one) — ON DELETE CASCADE
    title_id = Column(UUID(as_uuid=True), ForeignKey("titles.id", ondelete="CASCADE"), nullable=True, index=True)
    season_id = Column(UUID(as_uuid=True), ForeignKey("seasons.id", ondelete="CASCADE"), nullable=True, index=True)
    episode_id = Column(UUID(as_uuid=True), ForeignKey("episodes.id", ondelete="CASCADE"), nullable=True, index=True)

    # Regional/system metadata
    region = Column(String(2), nullable=False, doc="ISO‑3166 country code (e.g., 'US', 'IN')")
    system = Column(SAEnum(CertificationSystem, name="certification_system"), nullable=False)
    rating_code = Column(String, nullable=False, doc="Board‑specific code (e.g., 'PG-13', 'TV-MA', 'U/A', '16').")
    age_min = Column(Integer, nullable=True, doc="Derived minimum age if applicable (e.g., 13/16/18).")

    # Optional human context
    meaning = Column(String, nullable=True, doc="Short human‑readable meaning/label.")
    descriptors = Column(JSONB, nullable=True, doc="Optional list/dict of board descriptors.")
    source = Column(String, nullable=True, doc="Internal source tag (ingest pipeline, admin).")
    source_url = Column(String, nullable=True, doc="Link to authority/reference if available.")
    certified_at = Column(DateTime(timezone=True), nullable=True)

    # State
    is_current = Column(Boolean, nullable=False, server_default=text("true"), index=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    __table_args__ = (
        # Exactly one parent must be set
        CheckConstraint(
            "(CASE WHEN title_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN season_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN episode_id IS NOT NULL THEN 1 ELSE 0 END) = 1",
            name="ck_cert_exactly_one_parent",
        ),
        # Region formatting
        CheckConstraint("char_length(region) = 2 AND region = upper(region)", name="ck_cert_region_iso_upper"),
        CheckConstraint("(age_min IS NULL OR age_min BETWEEN 0 AND 21)", name="ck_cert_age_min_range"),
        # One current rating per (parent, region, system)
        Index(
            "uq_cert_current_per_parent",
            "title_id",
            "season_id",
            "episode_id",
            "region",
            "system",
            unique=True,
            postgresql_where=text("is_current = true"),
        ),
        # Common access patterns
        Index("ix_cert_parent_current", "title_id", "season_id", "episode_id", "is_current"),
        Index("ix_cert_region_system", "region", "system"),
        Index("ix_cert_rating_code", "rating_code"),
        Index("ix_cert_created_at", "created_at"),
    )

    # Relationships (two‑way; add `certifications` on parents)
    title = relationship("Title", back_populates="certifications", lazy="selectin", passive_deletes=True)
    season = relationship("Season", back_populates="certifications", lazy="selectin", passive_deletes=True)
    episode = relationship("Episode", back_populates="certifications", lazy="selectin", passive_deletes=True)

    def __repr__(self) -> str:  # pragma: no cover
        parent = "T" if self.title_id else ("S" if self.season_id else "E")
        return f"<Certification {parent} rating={self.rating_code} {self.system} {self.region} current={self.is_current}>"


# ──────────────────────────────────────────────────────────────
# 🧱 Model: ContentAdvisory
# ──────────────────────────────────────────────────────────────
class ContentAdvisory(Base):
    """Advisory flag for sensitive content (violence, language, etc.) attached to
    **exactly one** parent (Title/Season/Episode). Supports optional scene‑level
    timing (e.g., start/end in milliseconds) for episode playback UX.

    For global advisories (entire title/season/episode), leave timing fields NULL.
    """

    __tablename__ = "content_advisories"

    # Identity
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    # Parent (exactly one) — ON DELETE CASCADE
    title_id = Column(UUID(as_uuid=True), ForeignKey("titles.id", ondelete="CASCADE"), nullable=True, index=True)
    season_id = Column(UUID(as_uuid=True), ForeignKey("seasons.id", ondelete="CASCADE"), nullable=True, index=True)
    episode_id = Column(UUID(as_uuid=True), ForeignKey("episodes.id", ondelete="CASCADE"), nullable=True, index=True)

    # Advisory data
    kind = Column(SAEnum(AdvisoryKind, name="advisory_kind"), nullable=False, index=True)
    severity = Column(SAEnum(AdvisorySeverity, name="advisory_severity"), nullable=False)
    language = Column(String(15), nullable=True, doc="BCP‑47 (for localized 'notes').")
    notes = Column(String, nullable=True, doc="Optional short explanation shown to users.")
    tags = Column(JSONB, nullable=True, doc="Optional free‑form tags/keywords (array/object).")

    # Optional scene‑level timing (milliseconds from start)
    start_ms = Column(Integer, nullable=True)
    end_ms = Column(Integer, nullable=True)

    # Moderation / provenance
    source = Column(String, nullable=True, doc="Internal source tag (ingest/moderation).")
    is_active = Column(Boolean, nullable=False, server_default=text("true"), index=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    __table_args__ = (
        # Exactly one parent must be set
        CheckConstraint(
            "(CASE WHEN title_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN season_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN episode_id IS NOT NULL THEN 1 ELSE 0 END) = 1",
            name="ck_cadv_exactly_one_parent",
        ),
        # Timing sanity
        CheckConstraint("(start_ms IS NULL OR start_ms >= 0)", name="ck_cadv_start_ms_nonneg"),
        CheckConstraint("(end_ms IS NULL OR end_ms >= 0)", name="ck_cadv_end_ms_nonneg"),
        CheckConstraint("(start_ms IS NULL OR end_ms IS NULL OR end_ms >= start_ms)", name="ck_cadv_end_ge_start"),
        # Prevent duplicate **global** advisories per (parent, kind, language) when active
        Index(
            "uq_cadv_global_per_parent",
            "title_id",
            "season_id",
            "episode_id",
            "kind",
            "language",
            unique=True,
            postgresql_where=text("start_ms IS NULL AND end_ms IS NULL AND is_active = true"),
        ),
        # Common filters
        Index("ix_cadv_parent_active", "title_id", "season_id", "episode_id", "is_active"),
        Index("ix_cadv_kind_severity", "kind", "severity"),
        Index("ix_cadv_scene_window", "start_ms", "end_ms"),
        Index("ix_cadv_created_at", "created_at"),
        Index("ix_cadv_tags_gin", "tags", postgresql_using="gin"),
    )

    # Relationships (two‑way; add `content_advisories` on parents)
    title = relationship("Title", back_populates="content_advisories", lazy="selectin", passive_deletes=True)
    season = relationship("Season", back_populates="content_advisories", lazy="selectin", passive_deletes=True)
    episode = relationship("Episode", back_populates="content_advisories", lazy="selectin", passive_deletes=True)

    # Helpers
    def is_scene_level(self) -> bool:
        """True when this advisory applies to a time‑bounded segment."""
        return self.start_ms is not None or self.end_ms is not None

    def __repr__(self) -> str:  # pragma: no cover
        parent = "T" if self.title_id else ("S" if self.season_id else "E")
        scope = "scene" if self.is_scene_level() else "global"
        return f"<ContentAdvisory {parent} {self.kind} sev={self.severity} {scope} active={self.is_active}>"
