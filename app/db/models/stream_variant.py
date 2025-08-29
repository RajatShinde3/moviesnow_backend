from __future__ import annotations

"""
🎞️ MoviesNow — StreamVariant (per‑rendition streams)
===================================================

Represents an individual streaming/download rendition derived from a source
**MediaAsset** (e.g., HLS/DASH ladder entries, audio‑only tracks, progressive MP4).

Why this model
--------------
• Clean separation between the **source asset** and its **derived variants**.
• Strong typing for protocol/container/codec/DRM to avoid free‑form strings.
• Practical fields for ABR selection (bandwidth, resolution, fps), audio, HDR.
• Flexible `drm_params` JSONB for provider‑specific bits (PSSH, FairPlay data).
• Protective constraints & indexes for de‑duplication and fast selection.

Relationships
-------------
• `StreamVariant.media_asset`  ↔ `MediaAsset.stream_variants`
• `StreamVariant.playback_sessions` ↔ `PlaybackSession.stream_variant`

Conventions
-----------
• `url_path` should be a **relative** CDN/storage path (e.g., `videos/.../1080p.m3u8`).
• Manifest protocols use `url_path` for a variant playlist (HLS) or representation (DASH).
• Keep **Title/Episode** references on `MediaAsset`; variants hang off the asset.
"""

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
from uuid import uuid4
from app.db.base_class import Base
from app.schemas.enums import( 
    StreamProtocol, Container,
    VideoCodec, AudioCodec,
    DRMType, HDRFormat

)

# ──────────────────────────────────────────────────────────────
# 🎬 Model
# ──────────────────────────────────────────────────────────────
class StreamVariant(Base):
    """
    A single playable rendition of a video `MediaAsset`.

    Examples
    --------
    • HLS 1080p @ 6.5 Mbps, H.264/AAC, SDR
    • DASH 2160p @ 14 Mbps, H.265/EAC3, HDR10
    • Progressive 720p MP4 @ 3 Mbps, H.264/AAC
    • Audio‑only HLS @ 128 kbps, AAC

    De‑duplication
    --------------
    Uniqueness is enforced per `(media_asset_id, protocol, url_path)`. A secondary
    technical signature prevents accidental duplicates in the ladder.
    """

    __tablename__ = "stream_variants"

    # Identity / linkage
    id = Column(UUID(as_uuid=True),default=uuid4, primary_key=True)
    media_asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("media_assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Locator
    url_path = Column(
        String(1024),
        nullable=False,
        index=True,
        doc="Relative path to the variant playlist/representation or progressive file.",
    )

    # Playback descriptors
    protocol = Column(Enum(StreamProtocol, name="stream_protocol"), nullable=False)
    container = Column(Enum(Container, name="stream_container"), nullable=False)
    video_codec = Column(
        Enum(VideoCodec, name="video_codec"),
        nullable=False,
        server_default=text("'H264'"),
    )
    audio_codec = Column(
        Enum(AudioCodec, name="audio_codec"),
        nullable=False,
        server_default=text("'AAC'"),
    )

    # ABR / quality characteristics
    bandwidth_bps = Column(Integer, nullable=False, doc="Peak bandwidth in bits per second (EXT-X-STREAM-INF BANDWIDTH).")
    avg_bandwidth_bps = Column(Integer, nullable=True, doc="Average bandwidth in bps (EXT-X-STREAM-INF AVERAGE-BANDWIDTH).")
    width = Column(Integer, nullable=True)
    height = Column(Integer, nullable=True)
    frame_rate = Column(Float, nullable=True, doc="Frames per second (e.g., 23.976, 24, 25, 29.97, 60).")

    # Audio details
    audio_channels = Column(Integer, nullable=True, doc="Channel count (e.g., 2, 6).")
    audio_language = Column(String(16), nullable=True, doc="BCP‑47 language tag (e.g., 'en', 'en-US').")

    # Color / HDR
    hdr = Column(Enum(HDRFormat, name="hdr_format"), nullable=False, server_default=text("'SDR'"))
    bit_depth = Column(Integer, nullable=True, doc="Color bit depth (8, 10, 12).")

    # DRM
    drm_type = Column(Enum(DRMType, name="drm_type"), nullable=False, server_default=text("'NONE'"))
    drm_kid = Column(UUID(as_uuid=True), nullable=True, doc="Content key ID (UUID) when applicable.")
    drm_params = Column(
        JSONB,
        nullable=True,
        doc="Provider‑specific DRM data (e.g., Widevine PSSH b64, FairPlay cert URL).",
    )

    # Operational flags / sizing
    is_default = Column(Boolean, nullable=False, server_default=text("false"),
                        doc="Preferred variant when no client preference is provided.")
    is_audio_only = Column(Boolean, nullable=False, server_default=text("false"))
    is_downloadable = Column(Boolean, nullable=False, server_default=text("false"))
    size_bytes = Column(Integer, nullable=True, doc="Approx size of progressive file; NULL for segmented streams.")

    # Labeling
    label = Column(String(64), nullable=True, doc="Human label (e.g., '1080p', '4K HDR', 'Audio EN').")

    # Timestamps (DB‑driven UTC)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    __table_args__ = (
        # Basic hygiene
        CheckConstraint("length(btrim(url_path)) > 0", name="ck_stream_variant_path_not_blank"),
        CheckConstraint("bandwidth_bps > 0", name="ck_stream_variant_bandwidth_positive"),
        CheckConstraint("(width IS NULL) OR (width >= 0)", name="ck_stream_variant_width_nonneg"),
        CheckConstraint("(height IS NULL) OR (height >= 0)", name="ck_stream_variant_height_nonneg"),
        CheckConstraint("(frame_rate IS NULL) OR (frame_rate > 0)", name="ck_stream_variant_fps_positive"),
        CheckConstraint("(audio_channels IS NULL) OR (audio_channels >= 0)", name="ck_stream_variant_audio_channels_nonneg"),
        CheckConstraint("(size_bytes IS NULL) OR (size_bytes >= 0)", name="ck_stream_variant_size_nonneg"),
        CheckConstraint("updated_at >= created_at", name="ck_stream_variant_updated_after_created"),

        # Audio/video logic
        CheckConstraint(
            "NOT is_audio_only OR (width IS NULL AND height IS NULL AND video_codec = 'NONE' AND audio_codec <> 'NONE')",
            name="ck_stream_variant_audio_only_implies_audio_track",
        ),
        CheckConstraint(
            "is_audio_only OR video_codec <> 'NONE'",
            name="ck_stream_variant_non_audio_has_video",
        ),

        # Optional language tag length sanity
        CheckConstraint("(audio_language IS NULL) OR (char_length(audio_language) BETWEEN 2 AND 16)",
                        name="ck_stream_variant_lang_len"),
        # Optional non‑blank label
        CheckConstraint("(label IS NULL) OR (length(btrim(label)) > 0)", name="ck_stream_variant_label_not_blank"),

        # Downloadability guard (allow PROGRESSIVE or HLS offline; forbid DASH by default)
        CheckConstraint(
            "(NOT is_downloadable) OR (protocol IN ('PROGRESSIVE','HLS'))",
            name="ck_stream_variant_downloadable_protocol",
        ),

        # Path uniqueness per asset & protocol
        UniqueConstraint("media_asset_id", "protocol", "url_path", name="uq_stream_variant_asset_proto_path"),

        # Technical de‑duplication guard (best‑effort)
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

        # One default per (asset, audio_language, hdr) when flagged
        Index(
            "uq_stream_variant_default_per_scope",
            "media_asset_id",
            "audio_language",
            "hdr",
            unique=True,
            postgresql_where=text("is_default = true"),
        ),

        # Useful selectors
        Index("ix_stream_variant_asset_default", "media_asset_id", "is_default"),
        Index("ix_stream_variant_quality", "height", "bandwidth_bps"),
        Index("ix_stream_variant_drm", "protocol", "drm_type"),
        Index("ix_stream_variant_created_at", "created_at"),
    )

    # ── Relationships ─────────────────────────────────────────
    media_asset = relationship(
        "MediaAsset",
        back_populates="stream_variants",
        lazy="selectin",
        passive_deletes=True,
    )
    playback_sessions = relationship(
        "PlaybackSession",
        back_populates="stream_variant",
        passive_deletes=True,
        lazy="selectin",
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        wh = f"{self.width}x{self.height}" if self.width and self.height else ("audio" if self.is_audio_only else "unknown")
        return (
            f"<StreamVariant id={self.id} asset={self.media_asset_id} "
            f"{self.protocol.value}/{self.container.value} {self.video_codec.value}/{self.audio_codec.value} "
            f"{wh} @ {self.bandwidth_bps}bps default={self.is_default}>"
        )
