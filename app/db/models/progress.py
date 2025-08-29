from __future__ import annotations

"""
⏯️ MoviesNow — Progress (per‑user resume state)
===============================================

Tracks a user’s *resume position* and completion state for any playable item:
• **Movies**  → scoped to `title_id`
• **Episodes** → scoped to `episode_id` (with `season_id` optional for UX)

Design highlights
-----------------
• **One row per scope** using uniqueness:
  - `(user_id, episode_id)` unique when episode scope
  - `(user_id, title_id)` unique **only for movies** (`episode_id IS NULL`) via a partial unique index
• **Hierarchical integrity** with composite FKs to keep `season_id/title_id` and
  `episode_id/season_id/title_id` consistent (when set).
• **Defensive constraints** for timing and counters; DB‑driven UTC timestamps.
• **Extensible** `player_state` JSON for client hints without schema churn.

Relationships
-------------
• `Progress.user`    ↔ `User.progress_entries`
• `Progress.title`   ↔ `Title.progress_entries`
• `Progress.season`  ↔ `Season.progress_entries`
• `Progress.episode` ↔ `Episode.progress_entries`
"""

from enum import Enum as PyEnum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    ForeignKeyConstraint,
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
from uuid import uuid4
from app.db.base_class import Base
from app.db.models.availability import DeviceClass  # share enum across models
from app.schemas.enums import ProgressStatus



class Progress(Base):
    """Per‑user playback progress for a movie or an episode.

    Scope rules
    -----------
    • Movies: `title_id` set, `episode_id` **NULL**.
    • Episodes: `episode_id` set (and `title_id` kept consistent via FK chain),
      `season_id` optional.
    """

    __tablename__ = "progress"

    # ── Identity & scope ──────────────────────────────────────
    id = Column(UUID(as_uuid=True),default=uuid4, primary_key=True)

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    title_id = Column(UUID(as_uuid=True), ForeignKey("titles.id", ondelete="CASCADE"), nullable=False, index=True,
                      doc="Owning title (movie or series). Always populated.")
    season_id = Column(UUID(as_uuid=True), nullable=True, index=True, doc="Optional: season for episodic progress.")
    episode_id = Column(UUID(as_uuid=True), nullable=True, index=True, doc="NULL for movies; set for episode progress.")

    # Keep season/title and episode/season/title consistent when set
    __table_args__ = (
        ForeignKeyConstraint(["season_id", "title_id"], ["seasons.id", "seasons.title_id"],
                             ondelete="CASCADE", name="fk_progress_season_title_consistent"),
        ForeignKeyConstraint(["episode_id", "season_id", "title_id"],
                             ["episodes.id", "episodes.season_id", "episodes.title_id"],
                             ondelete="CASCADE", name="fk_progress_episode_season_title_consistent"),
    )

    # ── Playback position ─────────────────────────────────────
    position_seconds = Column(Integer, nullable=False, server_default=text("0"), doc="Current resume position (s).")
    duration_seconds = Column(Integer, nullable=True, doc="Known runtime (s). NULL if unknown at write time.")

    status = Column(Enum(ProgressStatus, name="progress_status"), nullable=False, server_default=text("'IN_PROGRESS'"))

    # ── UX / context ──────────────────────────────────────────
    last_played_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now(),
                            doc="Last time this row was updated by the player.")
    completed_at = Column(DateTime(timezone=True), nullable=True)
    times_restarted = Column(Integer, nullable=False, server_default=text("0"))
    playback_rate = Column(String(8), nullable=True, doc="e.g., '1.0', '1.25'")

    audio_language = Column(String(12), nullable=True)     # BCP‑47 or ISO code
    subtitle_language = Column(String(12), nullable=True)

    device_class = Column(Enum(DeviceClass, name="device_class"), nullable=True,
                          doc="Last known device class for this write (WEB/MOBILE/TV/...).")
    client_app = Column(String(64), nullable=True, doc="App/build identifier, e.g., 'web@1.42.0'")

    player_state = Column(JSON, nullable=True, doc="Extensible blob for client hints (quality, errors, etc.).")

    # ── Timestamps ────────────────────────────────────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ── Constraints & Indexes ─────────────────────────────────
    __table_args__ = __table_args__ + (
        # Progress sanity
        CheckConstraint("position_seconds >= 0", name="ck_progress_pos_nonneg"),
        CheckConstraint("duration_seconds IS NULL OR duration_seconds > 0", name="ck_progress_dur_pos"),
        CheckConstraint("duration_seconds IS NULL OR position_seconds <= duration_seconds", name="ck_progress_pos_lte_dur"),
        CheckConstraint(
            "(status <> 'COMPLETED') OR (completed_at IS NOT NULL)",
            name="ck_progress_completed_has_timestamp",
        ),
        # Scope sanity (movie or episode)
        CheckConstraint("(episode_id IS NOT NULL) OR (episode_id IS NULL AND season_id IS NULL)",
                        name="ck_progress_scope_movie_or_episode"),

        # One row per scope per user
        UniqueConstraint("user_id", "episode_id", name="uq_progress_user_episode"),
        # IMPORTANT: `user_id, title_id` must be unique **only for movie scope** (episode_id IS NULL)
        Index("uq_progress_user_movie_partial", "user_id", "title_id", unique=True,
              postgresql_where=text("episode_id IS NULL")),

        # Helpful selectors
        Index("ix_progress_user_updated", "user_id", "updated_at"),
        Index("ix_progress_user_status", "user_id", "status"),
        Index("ix_progress_title_user", "title_id", "user_id"),
    )

    # ── Relationships ─────────────────────────────────────────
    user = relationship(
        "User",
        back_populates="progress_entries",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="Progress.user_id == User.id",
        foreign_keys="[Progress.user_id]",
    )

    title = relationship(
        "Title",
        back_populates="progress_entries",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="Progress.title_id == Title.id",
        foreign_keys="[Progress.title_id]",
    )

    season = relationship(
        "Season",
        back_populates="progress_entries",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="Progress.season_id == Season.id",
        foreign_keys="[Progress.season_id]",
    )

    episode = relationship(
        "Episode",
        back_populates="progress_entries",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="Progress.episode_id == Episode.id",
        foreign_keys="[Progress.episode_id]",
    )

    # ── Convenience properties ────────────────────────────────
    @property
    def percent_complete(self) -> float:
        """Return a 0–100 percentage based on position/duration (best‑effort)."""
        if not self.duration_seconds or self.duration_seconds <= 0:
            return 0.0
        pct = (self.position_seconds / float(self.duration_seconds)) * 100.0
        return max(0.0, min(100.0, round(pct, 2)))

    @property
    def is_complete(self) -> bool:
        """True when status is COMPLETED and timestamp present."""
        return self.status == ProgressStatus.COMPLETED and self.completed_at is not None

    def __repr__(self) -> str:  # pragma: no cover
        scope = f"ep={self.episode_id}" if self.episode_id else f"title={self.title_id}"
        return f"<Progress user={self.user_id} {scope} pos={self.position_seconds}s status={self.status.value}>"