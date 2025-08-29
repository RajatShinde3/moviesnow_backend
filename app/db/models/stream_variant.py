# app/db/models/stream_variant.py
from __future__ import annotations

"""
🎞️ MoviesNow — StreamVariant (per-rendition streams)
===================================================

Represents a single streaming/download rendition derived from a source
**MediaAsset** (e.g., HLS ladder entries, progressive MP4s, audio-only).

Streaming policy (your requirement)
-----------------------------------
• Only these three *streamable* tiers are allowed: **1080p, 720p, 480p**.
• At most **one** streamable variant per (asset, tier): admin picks which file
  is used for streaming by setting `is_streamable=true` and `stream_tier`.
• Other qualities (4K, HDR masters, etc.) may still exist, but should be
  flagged **download-only** (keep `is_streamable=false`, set `is_downloadable=true`).

Conventions
-----------
• `url_path` is a **relative** CDN/storage path (e.g., `videos/.../1080p.m3u8`).
• Keep Title/Episode references on `MediaAsset`; variants hang off the asset.
"""

from uuid import uuid4
from enum import Enum as PyEnum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.base_class import Base
from app.schemas.enums import (
    StreamProtocol,  # HLS / DASH / PROGRESSIVE
    Container,       # TS / FMP4 / MP4
    VideoCodec,      # H264 / H265 / VP9 / AV1 / NONE
    AudioCodec,      # AAC / AC3 / EAC3 / OPUS / NONE
    DRMType,         # NONE / WIDEVINE / FAIRPLAY / PLAYREADY
    HDRFormat,       # SDR / HDR10 / HLG / DOLBY_VISION
    StreamTier,      # <-- NEW: P1080, P720, P480 (add to app.schemas.enums)
)

class StreamVariant(Base):
    """
    A single playable or downloadable rendition of a `MediaAsset`.

    De-duplication:
        • Unique per (media_asset_id, protocol, url_path).
        • A secondary uniqueness across core technical params helps prevent
          accidental duplicates in an ABR ladder.

    Streaming policy:
        • `is_streamable = true` requires a `stream_tier` of P1080/P720/P480.
        • One streamable row per (asset, tier) enforced by a partial unique index.
    """

    __tablename__ = "stream_variants"

    # ── Identity / linkage ──────────────────────────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)
    media_asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("media_assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Locator ─────────────────────────────────────────────────────────────
    url_path = Column(
        String(1024),
        nullable=False,
        index=True,
        doc="Relative path to the variant playlist/representation or progressive file.",
    )

    # ── Playback descriptors ────────────────────────────────────────────────
    protocol = Column(Enum(StreamProtocol, name="stream_protocol"), nullable=False)
    container = Column(Enum(Container, name="stream_container"), nullable=False)
    video_codec = Column(Enum(VideoCodec, name="video_codec"), nullable=False, server_default=text("'H264'"))
    audio_codec = Column(Enum(AudioCodec, name="audio_codec"), nullable=False, server_default=text("'AAC'"))

    # ── ABR / quality characteristics ───────────────────────────────────────
    bandwidth_bps = Column(Integer, nullable=False, doc="Peak bandwidth in bps (EXT-X-STREAM-INF BANDWIDTH).")
    avg_bandwidth_bps = Column(Integer, nullable=True, doc="Average bandwidth in bps (EXT-X-STREAM-INF AVERAGE-BANDWIDTH).")
    width = Column(Integer, nullable=True)
    height = Column(Integer, nullable=True)
    frame_rate = Column(Float, nullable=True, doc="Frames per second, e.g., 23.976, 24, 30, 60.")

    # ── Audio details ───────────────────────────────────────────────────────
    audio_channels = Column(Integer, nullable=True, doc="Channel count (e.g., 2, 6).")
    audio_language = Column(String(16), nullable=True, doc="BCP-47 tag (e.g., 'en', 'en-US').")

    # ── Color / HDR ─────────────────────────────────────────────────────────
    hdr = Column(Enum(HDRFormat, name="hdr_format"), nullable=False, server_default=text("'SDR'"))
    bit_depth = Column(Integer, nullable=True, doc="Color bit depth (8, 10, 12).")

    # ── DRM ─────────────────────────────────────────────────────────────────
    drm_type = Column(Enum(DRMType, name="drm_type"), nullable=False, server_default=text("'NONE'"))
    drm_kid = Column(UUID(as_uuid=True), nullable=True, doc="Key ID (UUID) if applicable.")
    drm_params = Column(JSONB, nullable=True, doc="Provider-specific DRM data (e.g., Widevine PSSH b64).")

    # ── Operational flags / sizing ──────────────────────────────────────────
    is_default = Column(Boolean, nullable=False, server_default=text("false"),
                        doc="General default indicator (e.g., preferred within a group).")
    is_audio_only = Column(Boolean, nullable=False, server_default=text("false"))
    is_downloadable = Column(Boolean, nullable=False, server_default=text("false"))

    # NEW: streaming policy knobs
    is_streamable = Column(
        Boolean,
        nullable=False,
        server_default=text("false"),
        index=True,
        doc="If true, this row is one of the *three* streamable tiers (1080/720/480).",
    )
    stream_tier = Column(
        Enum(StreamTier, name="stream_tier"),
        nullable=True,
        index=True,
        doc="P1080, P720, or P480 when `is_streamable` is true.",
    )

    size_bytes = Column(Integer, nullable=True, doc="Approx size for progressive; null for segmented.")

    # ── Labeling ────────────────────────────────────────────────────────────
    label = Column(String(64), nullable=True, doc="Human label (e.g., '1080p', '4K HDR', 'Audio EN').")

    # ── Timestamps (DB-driven UTC) ─────────────────────────────────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ── Constraints & Indexes ──────────────────────────────────────────────
    __table_args__ = (
        # Hygiene
        CheckConstraint("length(btrim(url_path)) > 0", name="ck_stream_variant_path_not_blank"),
        CheckConstraint("bandwidth_bps > 0", name="ck_stream_variant_bandwidth_positive"),
        CheckConstraint("(width IS NULL) OR (width >= 0)", name="ck_stream_variant_width_nonneg"),
        CheckConstraint("(height IS NULL) OR (height >= 0)", name="ck_stream_variant_height_nonneg"),
        CheckConstraint("(frame_rate IS NULL) OR (frame_rate > 0)", name="ck_stream_variant_fps_positive"),
        CheckConstraint("(audio_channels IS NULL) OR (audio_channels >= 0)", name="ck_stream_variant_audio_channels_nonneg"),
        CheckConstraint("(size_bytes IS NULL) OR (size_bytes >= 0)", name="ck_stream_variant_size_nonneg"),
        CheckConstraint("updated_at >= created_at", name="ck_stream_variant_updated_after_created"),
        CheckConstraint("(label IS NULL) OR (length(btrim(label)) > 0)", name="ck_stream_variant_label_not_blank"),
        CheckConstraint("(audio_language IS NULL) OR (char_length(audio_language) BETWEEN 2 AND 16)", name="ck_stream_variant_lang_len"),

        # Audio/video logic
        CheckConstraint(
            "NOT is_audio_only OR (width IS NULL AND height IS NULL AND video_codec = 'NONE' AND audio_codec <> 'NONE')",
            name="ck_stream_variant_audio_only_implies_audio_track",
        ),
        CheckConstraint(
            "is_audio_only OR video_codec <> 'NONE'",
            name="ck_stream_variant_non_audio_has_video",
        ),

        # Downloadability guard (allow MP4 or HLS offline; avoid DASH)
        CheckConstraint(
            "(NOT is_downloadable) OR (protocol IN ('MP4','HLS'))",
            name="ck_stream_variant_downloadable_protocol",
        ),

        # ── STREAMING POLICY ENFORCEMENT ────────────────────────────────────
        # Must specify a tier when marking a row streamable
        CheckConstraint(
            "NOT is_streamable OR stream_tier IS NOT NULL",
            name="ck_stream_variant_streamable_requires_tier",
        ),
        # Streamable rows must be video (not audio-only)
        CheckConstraint(
            "NOT is_streamable OR (is_audio_only = false)",
            name="ck_stream_variant_streamable_not_audio_only",
        ),
        # Constrain streamable rows to the three heights (if height is set)
        CheckConstraint(
            "NOT is_streamable OR height IS NULL OR height IN (1080, 720, 480)",
            name="ck_stream_variant_streamable_height_whitelist",
        ),
        # Recommend HLS for streamable rows (tighten if you want HLS-only)
        CheckConstraint(
            "NOT is_streamable OR protocol = 'HLS'",
            name="ck_stream_variant_streamable_hls_only",
        ),
        # At most one streamable row per (asset, tier)
        Index(
            "uq_stream_variant_one_streamable_per_tier",
            "media_asset_id",
            "stream_tier",
            unique=True,
            postgresql_where=text("is_streamable = true"),
        ),

        # ── De-duplication & lookup ─────────────────────────────────────────
        UniqueConstraint("media_asset_id", "protocol", "url_path", name="uq_stream_variant_asset_proto_path"),
        UniqueConstraint(
            "media_asset_id",
            "protocol",
            "container",
            "video_codec",
            "audio_codec",
            "bandwidth_bps",
            "width",
            "height",
            name="uq_stream_variant_tech_params",
        ),

        # One "default" per (asset, language, hdr) when flagged
        Index(
            "uq_stream_variant_default_per_scope",
            "media_asset_id", "audio_language", "hdr",
            unique=True,
            postgresql_where=text("is_default = true"),
        ),

        # Useful selectors
        Index("ix_stream_variant_asset_default", "media_asset_id", "is_default"),
        Index("ix_stream_variant_quality", "height", "bandwidth_bps"),
        Index("ix_stream_variant_drm", "protocol", "drm_type"),
        Index("ix_stream_variant_created_at", "created_at"),
    )

    # ── Relationships ───────────────────────────────────────────────────────
    media_asset = relationship(
        "MediaAsset",
        back_populates="stream_variants",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="StreamVariant.media_asset_id == MediaAsset.id",
        foreign_keys="[StreamVariant.media_asset_id]",
    )

    playback_sessions = relationship(
        "PlaybackSession",
        back_populates="stream_variant",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="PlaybackSession.stream_variant_id == StreamVariant.id",
        foreign_keys="[PlaybackSession.stream_variant_id]",
    )

    # ── Convenience ─────────────────────────────────────────────────────────
    def __repr__(self) -> str:  # pragma: no cover
        wh = f"{self.width}x{self.height}" if self.width and self.height else ("audio" if self.is_audio_only else "unknown")
        tier = f" tier={self.stream_tier.value}" if self.stream_tier else ""
        return (
            f"<StreamVariant id={self.id} asset={self.media_asset_id} "
            f"{self.protocol.value}/{self.container.value} {self.video_codec.value}/{self.audio_codec.value} "
            f"{wh} @ {self.bandwidth_bps}bps streamable={self.is_streamable}{tier}>"
        )
