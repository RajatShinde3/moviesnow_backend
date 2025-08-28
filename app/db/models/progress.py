# app/db/models/progress.py
from __future__ import annotations

"""
⏯️ Progress — user playback state (production-grade)
====================================================

Tracks a user’s *resume position* and completion state for any playable item:
- **Movies** → progress scoped to `title_id`
- **Episodes** → progress scoped to `episode_id` (optionally with `season_id`)

Design highlights
-----------------
- **Single row per scope** via partial unique indexes:
  - `(user_id, episode_id)` when `episode_id IS NOT NULL`
  - `(user_id, title_id)` when `episode_id IS NULL`  (movies)
- **Defensive constraints** for position/duration sanity.
- **Extensible** JSON `player_state` for client-specific details without migrations.
- **Device/app context** to analyze drop-offs by surface.
- **Lean writes**: update in place; `updated_at` auto-maintained.

Relationships
-------------
- `Progress.user`     ←→  `User.progress_entries`
- `Progress.title`    ←→  `Title.progress_entries`
- `Progress.season`   ←→  `Season.progress_entries`
- `Progress.episode`  ←→  `Episode.progress_entries`
"""

from enum import Enum as PyEnum

from sqlalchemy import (
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
from app.db.models.availability import DeviceClass  # keep device taxonomy consistent


class ProgressStatus(PyEnum):
    """High-level playback state."""
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    RESET = "RESET"               # user scrubbed back / started over
    ABANDONED = "ABANDONED"       # explicitly abandoned or long-idle


class Progress(Base):
    """
    Per-user playback progress for a movie or an episode.

    Scope rules
    -----------
    - Movies: `title_id` set, `episode_id` NULL.
    - Episodes: `episode_id` set (and `title_id` set via FK chain), `season_id` optional.
    """

    __tablename__ = "progress"

    # ── Identity & scope ──────────────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True)

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    title_id = Column(
        UUID(as_uuid=True),
        ForeignKey("titles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Owning title (movie or series). Always populated.",
    )
    season_id = Column(
        UUID(as_uuid=True),
        ForeignKey("seasons.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        doc="Optional: season for episodic progress.",
    )
    episode_id = Column(
        UUID(as_uuid=True),
        ForeignKey("episodes.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        doc="NULL for movies; set for episode progress.",
    )

    # ── Playback position ─────────────────────────────────────
    position_seconds = Column(
        Integer,
        nullable=False,
        server_default=text("0"),
        doc="Current resume position (s).",
    )
    duration_seconds = Column(
        Integer,
        nullable=True,
        doc="Known runtime (s). NULL if unknown at write time.",
    )
    status = Column(
        Enum(ProgressStatus, name="progress_status"),
        nullable=False,
        server_default=text("'IN_PROGRESS'"),
    )

    # ── UX / context ──────────────────────────────────────────
    last_played_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
        doc="Last time this row was updated by the player.",
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)
    times_restarted = Column(Integer, nullable=False, server_default=text("0"))
    playback_rate = Column(String(8), nullable=True, doc="e.g., '1.0', '1.25'")

    audio_language = Column(String(12), nullable=True)     # BCP-47 or ISO code
    subtitle_language = Column(String(12), nullable=True)

    device_class = Column(
        Enum(DeviceClass, name="device_class"),
        nullable=True,
        doc="Last known device class for this write (WEB/MOBILE/TV/...).",
    )
    client_app = Column(String(64), nullable=True, doc="App/build identifier, e.g., 'web@1.42.0'")

    player_state = Column(
        JSON,
        nullable=True,
        doc="Extensible blob for client hints (quality, CDN edge, errors, etc.).",
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
        # Progress sanity
        CheckConstraint("position_seconds >= 0", name="ck_progress_pos_nonneg"),
        CheckConstraint("duration_seconds IS NULL OR duration_seconds > 0", name="ck_progress_dur_pos"),
        CheckConstraint(
            "duration_seconds IS NULL OR position_seconds <= duration_seconds",
            name="ck_progress_pos_lte_dur",
        ),
        # Scope sanity (one of movie or episode)
        CheckConstraint(
            "(episode_id IS NOT NULL) OR (episode_id IS NULL AND season_id IS NULL)",
            name="ck_progress_scope_movie_or_episode",
        ),
        # One row per scope per user
        UniqueConstraint("user_id", "episode_id", name="uq_progress_user_episode"),
        UniqueConstraint(
            "user_id",
            "title_id",
            name="uq_progress_user_movie",
            deferrable=False,
            initially="IMMEDIATE",
        ),
        # Make the movie uniqueness apply *only* when episode_id IS NULL (partial index)
        Index(
            "uq_progress_user_movie_partial",
            "user_id",
            "title_id",
            unique=True,
            postgresql_where=text("episode_id IS NULL"),
        ),
        # Helpful selectors
        Index("ix_progress_user_updated", "user_id", "updated_at"),
        Index("ix_progress_user_status", "user_id", "status"),
    )

    # ── Relationships ─────────────────────────────────────────
    user = relationship(
        "User",
        back_populates="progress_entries",
        lazy="selectin",
        passive_deletes=True,
    )
    title = relationship(
        "Title",
        back_populates="progress_entries",
        lazy="selectin",
        passive_deletes=True,
    )
    season = relationship(
        "Season",
        back_populates="progress_entries",
        lazy="selectin",
        passive_deletes=True,
    )
    episode = relationship(
        "Episode",
        back_populates="progress_entries",
        lazy="selectin",
        passive_deletes=True,
    )

    # ── Convenience properties ────────────────────────────────
    @property
    def percent_complete(self) -> float:
        """Return a 0–100 percentage based on position/duration (best-effort)."""
        if not self.duration_seconds or self.duration_seconds <= 0:
            return 0.0
        pct = (self.position_seconds / float(self.duration_seconds)) * 100.0
        return max(0.0, min(100.0, round(pct, 2)))

    def __repr__(self) -> str:  # pragma: no cover
        scope = f"ep={self.episode_id}" if self.episode_id else f"title={self.title_id}"
        return f"<Progress user={self.user_id} {scope} pos={self.position_seconds}s status={self.status.value}>"
