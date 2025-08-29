from __future__ import annotations

"""
🌍 MoviesNow — Availability (rights, territories & windows)
==========================================================

Production-grade model defining **where**, **when**, and **how** a Title
(optionally narrowed to a Season or Episode) can be streamed or downloaded.

Why this model?
---------------
• Central, query-friendly record for rights checks:
  “is this playable here, now, on this device/plan?”
• Territory scoping via ISO-3166 country codes with GLOBAL / INCLUDE / EXCLUDE modes.
• Open-ended or bounded windows with defensive constraints.
• PostgreSQL-optimized arrays for distribution channels & device classes.
• Extensible JSONB `rights` for contract extras without migrations.

Specificity & precedence
------------------------
Application logic should prefer **Episode > Season > Title** when multiple records
match. This model does not enforce exclusivity; it provides the data to rank.

Indexing strategy
-----------------
• B-tree composites for scope & quick filters.
• GIN on arrays for membership queries.
• GiST on `tstzrange(window_start, COALESCE(window_end, 'infinity'))` for efficient
  *overlaps/contains* time-window queries.
"""

from uuid import uuid4

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
    String,
    UniqueConstraint,
    func,
    text,
    literal_column,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.schemas.enums import TerritoryMode, DistributionKind, DeviceClass
from app.db.base_class import Base


# ──────────────────────────────────────────────────────────────
# 📦 Model
# ──────────────────────────────────────────────────────────────
class Availability(Base):
    """
    Licensing/rights record governing **when/where/how** a title/season/episode can be offered.

    De-duplication
    --------------
    A uniqueness guard helps avoid exact duplicates per **scope + window + territory**.
    (Widen to additional columns if your contracts require it.)
    """

    __tablename__ = "availabilities"

    # ── Identity & scope ──────────────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)

    title_id = Column(
        UUID(as_uuid=True),
        ForeignKey("titles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Owning title (always present).",
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
        server_default=text("'GLOBAL'"),
        doc="How `countries` should be interpreted: GLOBAL / INCLUDE / EXCLUDE.",
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
        doc="One or more distribution channels this availability permits (e.g., SVOD, AVOD, TVOD).",
    )
    device_classes = Column(
        ARRAY(Enum(DeviceClass, name="device_class")),
        nullable=True,
        doc="Optional device class restrictions; NULL = all devices.",
    )
    is_download_allowed = Column(Boolean, nullable=False, server_default=text("false"))
    max_offline_days = Column(
        Integer,
        nullable=True,
        doc="If downloads are allowed, maximum days the download may remain playable.",
    )

    # ── Extensible rights/contract info ───────────────────────
    rights = Column(
        JSONB,
        nullable=True,
        doc="Structured contract extras (licensor, carve-outs, priority, notes).",
    )

    # ── Timestamps ────────────────────────────────────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __mapper_args__ = {"eager_defaults": True}

    # ──────────────────────────────────────────────────────────
    # 🔒 Constraints & 📇 Indexes
    # ──────────────────────────────────────────────────────────
    __table_args__ = (
        # Window sanity
        CheckConstraint(
            "window_end IS NULL OR window_end > window_start",
            name="ck_avail_valid_window",
        ),

        # Territory sanity — cast enum to text to avoid DDL enum coercion pitfalls
        CheckConstraint(
            "(territory_mode::text = 'GLOBAL') "
            "OR (countries IS NOT NULL AND array_length(countries, 1) > 0)",
            name="ck_avail_countries_required_when_scoped",
        ),

        # Download policy consistency
        CheckConstraint(
            "(NOT is_download_allowed AND max_offline_days IS NULL) "
            "OR (is_download_allowed AND max_offline_days IS NOT NULL AND max_offline_days > 0)",
            name="ck_avail_download_policy_consistent",
        ),

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

        # B-tree: sort/filter by time window
        Index("ix_avail_active_window", "window_start", "window_end"),

        # Partial index for open-ended windows (fast WHERE window_end IS NULL)
        Index(
            "ix_avail_open_ended",
            "title_id",
            "season_id",
            "episode_id",
            "window_start",
            postgresql_where=(window_end.is_(None)),
        ),

        # Scope lookups
        Index("ix_avail_scope_title_season_episode", "title_id", "season_id", "episode_id"),

        # GIN for ARRAY membership filters
        Index("ix_avail_distribution_gin", "distribution", postgresql_using="gin"),
        Index("ix_avail_countries_gin", "countries", postgresql_using="gin"),

        # GiST for time-window overlap/containment queries
        Index(
            "ix_avail_window_gist",
            func.tstzrange(
                window_start,
                func.coalesce(window_end, literal_column("'infinity'::timestamptz")),
            ),
            postgresql_using="gist",
        ),
    )

    # ──────────────────────────────────────────────────────────
    # 🔗 Relationships (disambiguated)
    # ──────────────────────────────────────────────────────────
    title = relationship(
        "Title",
        back_populates="availabilities",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="Availability.title_id == Title.id",
        foreign_keys="[Availability.title_id]",
    )

    season = relationship(
        "Season",
        back_populates="availabilities",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="Availability.season_id == Season.id",
        foreign_keys="[Availability.season_id]",
    )

    episode = relationship(
        "Episode",
        back_populates="availabilities",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="Availability.episode_id == Episode.id",
        foreign_keys="[Availability.episode_id]",
    )

    # ──────────────────────────────────────────────────────────
    # 🧰 Helpers
    # ──────────────────────────────────────────────────────────
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
        upper = {c.upper() for c in self.countries}
        if self.territory_mode == TerritoryMode.INCLUDE:
            return cc in upper
        if self.territory_mode == TerritoryMode.EXCLUDE:
            return cc not in upper
        return False

    def is_active_at(self, at_ts) -> bool:
        """Return True if the window includes the given aware datetime."""
        if at_ts is None:
            return False
        if self.window_end is None:
            return at_ts >= self.window_start
        return self.window_start <= at_ts < self.window_end

    def __repr__(self) -> str:  # pragma: no cover
        scope = (
            f"ep={self.episode_id}"
            if self.episode_id
            else (f"season={self.season_id}" if self.season_id else f"title={self.title_id}")
        )
        terr = self.territory_mode.value + (
            f"[{','.join(self.countries or [])}]"
            if self.territory_mode != TerritoryMode.GLOBAL
            else ""
        )
        win_end = self.window_end.isoformat() if self.window_end else "∞"
        return (
            f"<Availability {scope} {terr} "
            f"{self.window_start.isoformat()}→{win_end} dist={self.distribution}>"
        )
