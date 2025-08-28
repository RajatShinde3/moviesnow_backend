# app/db/models/availability.py
from __future__ import annotations

"""
🌍 Availability — licensing, territories, and time windows (production-grade)
============================================================================

Defines *where* and *when* a **Title** (optionally narrowed to a Season/Episode)
may be streamed or downloaded, along with distribution channel flags (SVOD/AVOD/TVOD/EST),
DRM/download policy, and extensible rights metadata.

Why this model
--------------
- Central, query-friendly record for rights checks: *is this playable here, now, on this plan?*
- Territory scoping via ISO-3166 country codes (include/exclude or global).
- Open-ended or bounded time windows with defensive constraints.
- Array fields for distribution types and device classes (Postgres-optimized).
- JSONB `rights` for licensor/licensee notes or contract extras without migrations.

Relationships
-------------
- `Availability.title`     ←→  `Title.availabilities`
- `Availability.season`    ←→  `Season.availabilities`  (optional, to narrow a title)
- `Availability.episode`   ←→  `Episode.availabilities` (optional, to override season/title)
Only `title_id` is required; `season_id` and `episode_id` allow more granular overrides.

Query examples
--------------
- Find currently playable entries for a user in IN:
  `WHERE now() BETWEEN window_start AND COALESCE(window_end, 'infinity')
     AND (territory_mode='GLOBAL' OR  ('IN' = ANY(countries) AND territory_mode='INCLUDE')
          OR ('IN' <> ALL(countries) AND territory_mode='EXCLUDE'))`
- Prefer the most specific record (episode > season > title) in application logic.
"""

from enum import Enum as PyEnum

from sqlalchemy import (
    ARRAY,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base_class import Base


# ──────────────────────────────────────────────────────────────
# 🔤 Enums
# ──────────────────────────────────────────────────────────────
class TerritoryMode(PyEnum):
    GLOBAL = "GLOBAL"     # worldwide, no country filtering
    INCLUDE = "INCLUDE"   # *only* in listed countries
    EXCLUDE = "EXCLUDE"   # *everywhere except* listed countries


class DistributionKind(PyEnum):
    SVOD = "SVOD"         # subscription VOD
    AVOD = "AVOD"         # ad-supported VOD
    TVOD = "TVOD"         # transactional (rental)
    EST = "EST"           # electronic sell-through (purchase)
    FREE = "FREE"         # free (no login/payment), often with ads


class DeviceClass(PyEnum):
    WEB = "WEB"
    MOBILE = "MOBILE"
    TV = "TV"
    TABLET = "TABLET"
    CONSOLE = "CONSOLE"
    OTHER = "OTHER"


# ──────────────────────────────────────────────────────────────
# 📦 Model
# ──────────────────────────────────────────────────────────────
class Availability(Base):
    """
    A licensing/rights record that governs **when/where/how** a title/season/episode
    can be offered.

    Specificity precedence (application side):
        Episode-scoped > Season-scoped > Title-level.

    De-duplication:
        A uniqueness guard helps prevent identical duplicate rows per scope+window.
    """

    __tablename__ = "availabilities"

    # ── Identity & scope ──────────────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True)

    title_id = Column(
        UUID(as_uuid=True),
        ForeignKey("titles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    season_id = Column(
        UUID(as_uuid=True),
        ForeignKey("seasons.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        doc="Optional: narrow the availability to a specific season.",
    )
    episode_id = Column(
        UUID(as_uuid=True),
        ForeignKey("episodes.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        doc="Optional: narrow the availability to a specific episode.",
    )

    # ── Window (UTC) ──────────────────────────────────────────
    window_start = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        doc="Start of rights window (inclusive, UTC).",
    )
    window_end = Column(
        DateTime(timezone=True),
        nullable=True,
        doc="End of rights window (exclusive, UTC). NULL = open-ended.",
    )

    # ── Territories ───────────────────────────────────────────
    territory_mode = Column(
        Enum(TerritoryMode, name="territory_mode"),
        nullable=False,
        default=TerritoryMode.GLOBAL,
    )
    countries = Column(
        ARRAY(String(2)),
        nullable=True,
        doc="ISO-3166-1 alpha-2 country codes (required when mode != GLOBAL).",
    )

    # ── Distribution / device policy ──────────────────────────
    distribution = Column(
        ARRAY(Enum(DistributionKind, name="distribution_kind")),
        nullable=False,
        server_default=text("'{SVOD}'::distribution_kind[]"),
        doc="One or more distribution channels this availability permits.",
    )
    device_classes = Column(
        ARRAY(Enum(DeviceClass, name="device_class")),
        nullable=True,
        doc="Optional device class restrictions; NULL = all devices.",
    )
    is_download_allowed = Column(Boolean, nullable=False, default=False)
    max_offline_days = Column(Integer, nullable=True, doc="If downloads allowed, max days the download can remain playable.")

    # ── Extensible rights/contract info ───────────────────────
    rights = Column(
        JSON,
        nullable=True,
        doc="Free-form contract extras (e.g., licensor, carve-outs, priority, notes).",
    )

    # ── Timestamps ────────────────────────────────────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __mapper_args__ = {"eager_defaults": True}

    __table_args__ = (
        # Window sanity
        CheckConstraint("window_end IS NULL OR window_end > window_start", name="ck_avail_valid_window"),

        # Territory sanity
        CheckConstraint(
            "(territory_mode = 'GLOBAL') OR (countries IS NOT NULL AND array_length(countries, 1) > 0)",
            name="ck_avail_countries_required_when_scoped",
        ),

        # Episode scope implies same title (enforced app-side; DB helps via FK chain).
        # If you also FK seasons. title_id → seasons.title_id, rely on app logic for strictness.

        # De-dup guard for exact duplicates within the same scope & window
        UniqueConstraint(
            "title_id",
            "season_id",
            "episode_id",
            "window_start",
            "window_end",
            "territory_mode",
            "countries",
            name="uq_avail_scope_window_territory",
        ),

        # Useful selectors
        Index("ix_avail_active_window", "window_start", "window_end"),
        Index("ix_avail_scope_title_season_episode", "title_id", "season_id", "episode_id"),
        Index("ix_avail_distribution_gin", distribution, postgresql_using="gin"),
        Index("ix_avail_countries_gin", countries, postgresql_using="gin"),
    )

    # ── Relationships ─────────────────────────────────────────
    title = relationship(
        "Title",
        back_populates="availabilities",
        lazy="selectin",
        passive_deletes=True,
    )
    season = relationship(
        "Season",
        back_populates="availabilities",
        lazy="selectin",
        passive_deletes=True,
    )
    episode = relationship(
        "Episode",
        back_populates="availabilities",
        lazy="selectin",
        passive_deletes=True,
    )

    # ── Helpers ───────────────────────────────────────────────
    def applies_to_country(self, country_code: str) -> bool:
        """
        Lightweight in-process check for a single country code (uppercased).
        Prefer SQL filters for set operations at scale.
        """
        cc = (country_code or "").upper()
        if self.territory_mode == TerritoryMode.GLOBAL:
            return True
        if not self.countries:
            return False
        if self.territory_mode == TerritoryMode.INCLUDE:
            return cc in {c.upper() for c in self.countries}
        if self.territory_mode == TerritoryMode.EXCLUDE:
            return cc not in {c.upper() for c in self.countries}
        return False

    def __repr__(self) -> str:  # pragma: no cover
        scope = (
            f"ep={self.episode_id}"
            if self.episode_id
            else f"season={self.season_id}" if self.season_id else f"title={self.title_id}"
        )
        terr = self.territory_mode.value + (f"[{','.join(self.countries or [])}]" if self.territory_mode != TerritoryMode.GLOBAL else "")
        win = f"{self.window_start.isoformat()}→{self.window_end.isoformat() if self.window_end else '∞'}"
        return f"<Availability {scope} {terr} {win} dist={self.distribution}>"
