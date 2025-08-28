# app/db/models/playback_session.py
from __future__ import annotations

"""
🎬 PlaybackSession — granular stream telemetry (production-grade)
================================================================

Tracks a single viewer playback session for a `Title` or specific `Episode`,
including lifecycle status, device/network traits, CDN/stream info, and
high-level QoE counters. Designed for privacy (hashes/aggregate metrics) and
efficient analytics.

Why this model
--------------
- Relates **user ↔ title/episode ↔ stream variant** for accurate attribution.
- Captures **bitrate/rebuffer telemetry** without storing personal content.
- Enables **compliance & abuse controls** via coarse geo and **hashed IP** only.
- Performs under load with targeted indexes and conservative constraints.

Privacy & hygiene
-----------------
- Store **`ip_hash`** and not raw IPs.
- Keep **coarse geo** (e.g., country/region codes) only.
- Limit free-form blobs to small **JSON** fields for diagnostics/metrics.
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
    Index,
    Integer,
    String,
    JSON,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

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
    """
    Immutable record of a viewer session for analytics, support, and audits.

    Relationships
    -------------
    - `user_id` → `users.id` (nullable for anonymous/preview sessions)
    - `title_id` → `titles.id` (always present; movies & series umbrella)
    - `episode_id` → `episodes.id` (nullable for movies)
    - `stream_variant_id` → `stream_variants.id` (chosen rendition/DRM/protocol)

    Counters & QoE
    --------------
    - `duration_ms`, `bytes_served`
    - `rebuffer_events`, `rebuffer_time_ms`
    - bitrate stats: `bitrate_start_kbps`, `bitrate_avg_kbps`, `bitrate_max_kbps`

    Device/Network Snapshot
    -----------------------
    - `device_os`, `device_os_version`, `device_model`
    - `app_version`, `player_version`
    - `network_type` (wifi/cellular/ethernet/unknown)
    - CDN hints: `cdn_provider`, `edge_pop`

    Security/Privacy
    ----------------
    - `ip_hash` (hex digest) and optionally `user_agent`
    - coarse geo: `country_code`, `region_code`
    """

    __tablename__ = "playback_sessions"

    # ── Identity & foreign keys ─────────────────────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True)

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        doc="Viewer; NULL when playback occurs before sign-in.",
    )

    title_id = Column(
        UUID(as_uuid=True),
        ForeignKey("titles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Movie or series (umbrella for an episode).",
    )

    episode_id = Column(
        UUID(as_uuid=True),
        ForeignKey("episodes.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        doc="Specific episode when title is a series; NULL for movies.",
    )

    stream_variant_id = Column(
        UUID(as_uuid=True),
        ForeignKey("stream_variants.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        doc="Selected ABR rendition (protocol/DRM/bitrate ladder).",
    )

    client_session_id = Column(
        String(64),
        nullable=True,
        index=True,
        doc="Opaque client-side session token to correlate heartbeats/logs.",
    )

    # ── Lifecycle ───────────────────────────────────────────────────────────
    status = Column(
        Enum(PlaybackStatus, name="playback_status"),
        nullable=False,
        server_default=text("'INITIATED'"),
        index=True,
    )

    end_reason = Column(
        Enum(EndReason, name="playback_end_reason"),
        nullable=True,
        index=True,
    )

    started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    ended_at = Column(DateTime(timezone=True), nullable=True)

    # ── QoE & counters ─────────────────────────────────────────────────────
    duration_ms = Column(
        Integer,
        nullable=True,
        doc="Approx. total watch time for this session (ms).",
    )
    bytes_served = Column(
        BigInteger,
        nullable=True,
        doc="Total bytes downloaded for media segments.",
    )

    rebuffer_events = Column(
        Integer,
        nullable=False,
        server_default=text("0"),
        doc="Count of stall/rebuffer incidents.",
    )
    rebuffer_time_ms = Column(
        Integer,
        nullable=False,
        server_default=text("0"),
        doc="Cumulative stall time (ms).",
    )

    bitrate_start_kbps = Column(Integer, nullable=True)
    bitrate_avg_kbps = Column(Integer, nullable=True)
    bitrate_max_kbps = Column(Integer, nullable=True)

    heartbeat_count = Column(
        Integer,
        nullable=False,
        server_default=text("0"),
        doc="Number of heartbeat pings associated to this session.",
    )

    # ── Stream/DRM/CDN descriptors ─────────────────────────────────────────
    protocol = Column(
        Enum(StreamProtocol, name="stream_protocol"),
        nullable=True,
        doc="Primary streaming protocol observed.",
    )
    drm_scheme = Column(
        Enum(DrmScheme, name="drm_scheme"),
        nullable=True,
        doc="DRM scheme negotiated for this session.",
    )
    drm_session_id = Column(
        String(128),
        nullable=True,
        index=True,
        doc="Hashed/opaque DRM session identifier (no raw license data).",
    )

    cdn_provider = Column(String(64), nullable=True)
    edge_pop = Column(String(64), nullable=True)

    # ── Device / app / network snapshot ────────────────────────────────────
    device_os = Column(String(32), nullable=True)
    device_os_version = Column(String(32), nullable=True)
    device_model = Column(String(64), nullable=True)
    app_version = Column(String(32), nullable=True)
    player_version = Column(String(32), nullable=True)

    network_type = Column(String(16), nullable=True, doc="wifi | cellular | ethernet | unknown")

    # ── Privacy-preserving client traits ───────────────────────────────────
    ip_hash = Column(
        String(64),
        nullable=True,
        index=True,
        doc="Hashed remote IP (e.g., sha256). Never store raw IPs.",
    )
    user_agent = Column(String(256), nullable=True)
    country_code = Column(String(2), nullable=True, index=True)   # ISO-3166-1 alpha-2
    region_code = Column(String(8), nullable=True)                # e.g., US-CA

    # ── Flags & misc ───────────────────────────────────────────────────────
    is_download = Column(
        Boolean,
        nullable=False,
        server_default=text("false"),
        doc="True if offline/downloaded playback.",
    )
    notes = Column(Text, nullable=True, doc="Optional text notes for support/debug.")

    # ── JSON blobs (keep compact) ──────────────────────────────────────────
    metrics = Column(
        JSON,
        nullable=True,
        doc="Compact metrics snapshot (e.g., ladder/quality switches).",
    )
    diagnostics = Column(
        JSON,
        nullable=True,
        doc="Last error codes, player states, brief stack traces.",
    )

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ── Constraints & indexes ──────────────────────────────────────────────
    __table_args__ = (
        CheckConstraint(
            "ended_at IS NULL OR ended_at >= started_at",
            name="ck_playback_session_time_order",
        ),
        CheckConstraint(
            "duration_ms IS NULL OR duration_ms >= 0",
            name="ck_playback_session_duration_nonneg",
        ),
        CheckConstraint(
            "bytes_served IS NULL OR bytes_served >= 0",
            name="ck_playback_session_bytes_nonneg",
        ),
        Index("ix_playback_user_started", "user_id", "started_at"),
        Index("ix_playback_title_started", "title_id", "started_at"),
        Index("ix_playback_episode_started", "episode_id", "started_at"),
        Index(
            "ix_playback_ended",
            "title_id",
            "ended_at",
            postgresql_where=text("ended_at IS NOT NULL"),
        ),
    )

    # ── Relationships ──────────────────────────────────────────────────────
    user = relationship(
        "User",
        back_populates="playback_sessions",
        lazy="selectin",
        passive_deletes=True,
    )
    title = relationship(
        "Title",
        back_populates="playback_sessions",
        lazy="selectin",
        passive_deletes=True,
    )
    episode = relationship(
        "Episode",
        back_populates="playback_sessions",
        lazy="selectin",
        passive_deletes=True,
    )
    stream_variant = relationship(
        "StreamVariant",
        back_populates="playback_sessions",
        lazy="selectin",
        passive_deletes=True,
    )

    # ── Convenience ────────────────────────────────────────────────────────
    @property
    def is_active(self) -> bool:
        """True while the session is in INITIATED/PLAYING/PAUSED and not ended/aborted."""
        return self.status in {PlaybackStatus.INITIATED, PlaybackStatus.PLAYING, PlaybackStatus.PAUSED}

    def __repr__(self) -> str:  # pragma: no cover
        kind = "episode" if self.episode_id else "title"
        return f"<PlaybackSession id={self.id} user={self.user_id} {kind}={self.episode_id or self.title_id} status={self.status.value}>"
