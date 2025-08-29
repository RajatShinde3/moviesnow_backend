from __future__ import annotations

"""
🎬 MoviesNow — PlaybackSession (granular stream telemetry)
=========================================================

Tracks a single viewer playback session for a `Title` or specific `Episode`,
including lifecycle status, device/network traits, CDN/stream info, and
high‑level QoE counters. Designed for privacy (hashes/aggregate metrics) and
efficient analytics.

Why this model
--------------
• Relates **user ↔ title/episode ↔ stream variant** for accurate attribution.
• Captures **bitrate/rebuffer telemetry** without storing personal content.
• Enables **compliance & abuse controls** via coarse geo and **hashed IP** only.
• Performs under load with targeted indexes and defensive constraints.

Privacy & hygiene
-----------------
• Store **`ip_hash`** (hex digest) and not raw IPs.
• Keep **coarse geo** (country/region codes) only.
• Keep free‑form blobs compact (JSONB) for diagnostics/metrics.

Relationships
-------------
• `PlaybackSession.user`            ↔ `User.playback_sessions`
• `PlaybackSession.title`           ↔ `Title.playback_sessions`
• `PlaybackSession.episode`         ↔ `Episode.playback_sessions`
• `PlaybackSession.stream_variant`  ↔ `StreamVariant.playback_sessions`

Integrity
---------
• Composite FK `(episode_id, title_id) → (episodes.id, episodes.title_id)` ensures
  the episode (when present) belongs to the specified title.
• Time/order and non‑negative counters enforced by CHECK constraints.
"""

from enum import Enum as PyEnum

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from uuid import uuid4
from app.db.base_class import Base


# ───────────────────────────────────────────────────────────────
# Enums
# ───────────────────────────────────────────────────────────────
class PlaybackStatus(PyEnum):
    INITIATED = "INITIATED"   # created, before first bytes rendered
    PLAYING   = "PLAYING"     # actively rendering frames
    PAUSED    = "PAUSED"      # paused by user/app
    ENDED     = "ENDED"       # ended normally or with a reason
    ABORTED   = "ABORTED"     # crashed/closed without graceful end


class EndReason(PyEnum):
    COMPLETED     = "COMPLETED"      # reached end of content
    USER_EXIT     = "USER_EXIT"      # user navigated away/closed
    ERROR         = "ERROR"          # unrecoverable playback error
    TIMEOUT       = "TIMEOUT"        # idle/pause timeout
    NETWORK       = "NETWORK"        # network loss or congestion
    DRM           = "DRM"            # license/DRM failure
    UNKNOWN       = "UNKNOWN"


class DrmScheme(PyEnum):
    NONE      = "NONE"
    WIDEVINE  = "WIDEVINE"
    FAIRPLAY  = "FAIRPLAY"
    PLAYREADY = "PLAYREADY"


class StreamProtocol(PyEnum):
    HLS  = "HLS"
    DASH = "DASH"
    MP4  = "MP4"


# ───────────────────────────────────────────────────────────────
# Model
# ───────────────────────────────────────────────────────────────
class PlaybackSession(Base):
    """Immutable record of a viewer session for analytics, support, and audits."""

    __tablename__ = "playback_sessions"

    # ── Identity & foreign keys ─────────────────────────────────────────────
    id = Column(UUID(as_uuid=True),default=uuid4, primary_key=True)

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"),
                     nullable=True, index=True, doc="Viewer; NULL when playback occurs before sign‑in.")

    title_id = Column(UUID(as_uuid=True), ForeignKey("titles.id", ondelete="CASCADE"),
                      nullable=False, index=True, doc="Movie or series (umbrella for an episode).")

    episode_id = Column(UUID(as_uuid=True), ForeignKey("episodes.id", ondelete="SET NULL"),
                        nullable=True, index=True, doc="Specific episode when title is a series; NULL for movies.")

    # Ensure the episode (when present) belongs to the specified title
    __table_args__ = (
        ForeignKeyConstraint(["episode_id", "title_id"], ["episodes.id", "episodes.title_id"],
                             name="fk_playback_episode_title_consistent", ondelete="SET NULL"),
    )

    stream_variant_id = Column(UUID(as_uuid=True), ForeignKey("stream_variants.id", ondelete="SET NULL"),
                               nullable=True, index=True, doc="Selected ABR rendition (protocol/DRM/bitrate ladder).")

    client_session_id = Column(String(64), nullable=True, index=True,
                               doc="Opaque client‑side session token to correlate heartbeats/logs.")

    # ── Lifecycle ───────────────────────────────────────────────────────────
    status = Column(Enum(PlaybackStatus, name="playback_status"), nullable=False,
                    server_default=text("'INITIATED'"), index=True)

    end_reason = Column(Enum(EndReason, name="playback_end_reason"), nullable=True, index=True)

    started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    ended_at = Column(DateTime(timezone=True), nullable=True)

    # ── QoE & counters ─────────────────────────────────────────────────────
    duration_ms = Column(Integer, nullable=True, doc="Approx. total watch time for this session (ms).")
    bytes_served = Column(BigInteger, nullable=True, doc="Total bytes downloaded for media segments.")

    rebuffer_events = Column(Integer, nullable=False, server_default=text("0"),
                             doc="Count of stall/rebuffer incidents.")
    rebuffer_time_ms = Column(Integer, nullable=False, server_default=text("0"),
                               doc="Cumulative stall time (ms).")

    bitrate_start_kbps = Column(Integer, nullable=True)
    bitrate_avg_kbps = Column(Integer, nullable=True)
    bitrate_max_kbps = Column(Integer, nullable=True)

    heartbeat_count = Column(Integer, nullable=False, server_default=text("0"),
                             doc="Number of heartbeat pings associated to this session.")

    # ── Stream/DRM/CDN descriptors ─────────────────────────────────────────
    protocol = Column(Enum(StreamProtocol, name="stream_protocol"), nullable=True,
                      doc="Primary streaming protocol observed.")
    drm_scheme = Column(Enum(DrmScheme, name="drm_scheme"), nullable=True,
                        doc="DRM scheme negotiated for this session.")
    drm_session_id = Column(String(128), nullable=True, index=True,
                            doc="Hashed/opaque DRM session identifier (no raw license data).")

    cdn_provider = Column(String(64), nullable=True)
    edge_pop = Column(String(64), nullable=True)

    # ── Device / app / network snapshot ────────────────────────────────────
    device_os = Column(String(32), nullable=True)
    device_os_version = Column(String(32), nullable=True)
    device_model = Column(String(64), nullable=True)
    app_version = Column(String(32), nullable=True)
    player_version = Column(String(32), nullable=True)

    network_type = Column(String(16), nullable=True, doc="wifi | cellular | ethernet | unknown")

    # ── Privacy‑preserving client traits ───────────────────────────────────
    ip_hash = Column(String(64), nullable=True, index=True, doc="Hashed remote IP (e.g., sha256). Never store raw IPs.")
    user_agent = Column(String(256), nullable=True)
    country_code = Column(String(2), nullable=True, index=True, doc="ISO‑3166‑1 alpha‑2")
    region_code = Column(String(8), nullable=True, doc="e.g., US‑CA")

    # ── Flags & misc ───────────────────────────────────────────────────────
    is_download = Column(Boolean, nullable=False, server_default=text("false"),
                         doc="True if offline/downloaded playback.")
    notes = Column(Text, nullable=True, doc="Optional text notes for support/debug.")

    # ── JSON blobs (keep compact) ──────────────────────────────────────────
    metrics = Column(JSONB, nullable=True, doc="Compact metrics snapshot (e.g., ladder/quality switches).")
    diagnostics = Column(JSONB, nullable=True, doc="Last error codes, player states, brief traces.")

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ── Constraints & indexes ──────────────────────────────────────────────
    __table_args__ = __table_args__ + (
        # Time sanity
        CheckConstraint("ended_at IS NULL OR ended_at >= started_at", name="ck_playback_session_time_order"),
        # If ended/aborted, ended_at should be present (soft requirement; can be relaxed if needed)
        CheckConstraint(
            "(status NOT IN ('ENDED','ABORTED')) OR (ended_at IS NOT NULL)",
            name="ck_playback_session_end_has_timestamp",
        ),
        # Non‑negative counters
        CheckConstraint("duration_ms IS NULL OR duration_ms >= 0", name="ck_playback_session_duration_nonneg"),
        CheckConstraint("bytes_served IS NULL OR bytes_served >= 0", name="ck_playback_session_bytes_nonneg"),
        CheckConstraint("rebuffer_events >= 0", name="ck_playback_session_rebuffer_events_nonneg"),
        CheckConstraint("rebuffer_time_ms >= 0", name="ck_playback_session_rebuffer_time_nonneg"),
        CheckConstraint("heartbeat_count >= 0", name="ck_playback_session_heartbeats_nonneg"),
        # Bitrate sanity
        CheckConstraint(
            "(bitrate_start_kbps IS NULL OR bitrate_start_kbps >= 0) AND "
            "(bitrate_avg_kbps IS NULL OR bitrate_avg_kbps >= 0) AND "
            "(bitrate_max_kbps IS NULL OR bitrate_max_kbps >= 0)",
            name="ck_playback_session_bitrates_nonneg",
        ),
        CheckConstraint(
            "(bitrate_max_kbps IS NULL OR bitrate_avg_kbps IS NULL OR bitrate_max_kbps >= bitrate_avg_kbps)",
            name="ck_playback_session_bitrate_avg_le_max",
        ),
        # Privacy/geo hygiene
        CheckConstraint(
            "(ip_hash IS NULL) OR (char_length(ip_hash) = 64)",
            name="ck_playback_session_iphash_len",
        ),
        CheckConstraint(
            "(country_code IS NULL) OR (char_length(country_code) = 2 AND country_code = upper(country_code))",
            name="ck_playback_session_country_upper2",
        ),
        CheckConstraint(
            "(region_code IS NULL) OR (char_length(region_code) <= 8)",
            name="ck_playback_session_region_len",
        ),

        # Hot paths
        Index("ix_playback_user_started", "user_id", "started_at"),
        Index("ix_playback_title_started", "title_id", "started_at"),
        Index("ix_playback_episode_started", "episode_id", "started_at"),
        Index("ix_playback_stream_started", "stream_variant_id", "started_at"),
        Index("ix_playback_status_started", "status", "started_at"),
        Index("ix_playback_country_started", "country_code", "started_at"),
        # Only ended sessions
        Index("ix_playback_ended", "title_id", "ended_at", postgresql_where=text("ended_at IS NOT NULL")),
        # Active sessions (planner can use for dashboards)
        Index(
            "ix_playback_active_status",
            "status",
            postgresql_where=text("status IN ('INITIATED','PLAYING','PAUSED')"),
        ),
        # JSONB helpers
        Index("ix_playback_metrics_gin", "metrics", postgresql_using="gin"),
        Index("ix_playback_diagnostics_gin", "diagnostics", postgresql_using="gin"),
    )

    # ── Relationships ──────────────────────────────────────────────────────
    user = relationship("User", back_populates="playback_sessions", lazy="selectin", passive_deletes=True)
    title = relationship("Title", back_populates="playback_sessions", lazy="selectin", passive_deletes=True)
    episode = relationship("Episode", back_populates="playback_sessions", lazy="selectin", passive_deletes=True)
    stream_variant = relationship("StreamVariant", back_populates="playback_sessions", lazy="selectin", passive_deletes=True)

    # ── Convenience ────────────────────────────────────────────────────────
    @property
    def is_active(self) -> bool:
        """True while the session is in INITIATED/PLAYING/PAUSED and not ended/aborted."""
        return self.status in {PlaybackStatus.INITIATED, PlaybackStatus.PLAYING, PlaybackStatus.PAUSED}

    def __repr__(self) -> str:  # pragma: no cover
        kind = "episode" if self.episode_id else "title"
        return (
            f"<PlaybackSession id={self.id} user={self.user_id} "
            f"{kind}={self.episode_id or self.title_id} status={self.status.value}>"
        )
