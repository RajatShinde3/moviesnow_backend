from __future__ import annotations

"""
MoviesNow • Bundle (Season ZIP)
===============================

Represents a downloadable ZIP bundle for a season or a curated set of episodes.

Design
------
- Standalone entity with storage key, size, checksum, and expiry.
- Linked to a Title, optional season_number, and optional episode_ids.
- Purposely not tied to MediaAsset to keep day-1 workflow simple.

Security / Performance / Failure Modes
--------------------------------------
- S3 objects live under `bundles/{title_id}/S{season:02}.zip` (documented).
- Short expiry strongly recommended (7–30 days) enforced by lifecycle/IaC.
- Deletions are best-effort on S3; DB row removal is authoritative.
"""

from uuid import uuid4
from typing import Optional

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Index,
    UniqueConstraint,
    CheckConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class Bundle(Base):
    """Season or curated episode ZIP bundle."""

    __tablename__ = "bundles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)
    title_id = Column(UUID(as_uuid=True), ForeignKey("titles.id", ondelete="CASCADE"), nullable=False, index=True)
    season_number = Column(Integer, nullable=True, index=True)
    episode_ids = Column(JSONB, nullable=True, doc="Array of episode UUIDs included in the bundle.")

    storage_key = Column(String(1024), nullable=False, unique=True, index=True)
    size_bytes = Column(Integer, nullable=True)
    sha256 = Column(String(64), nullable=True, index=True)

    label = Column(String(128), nullable=True, doc="Human label (e.g., 'Season 1 ZIP').")

    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)

    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    __table_args__ = (
        # Hygiene
        CheckConstraint("length(btrim(storage_key)) > 0", name="ck_bundle_storage_key_not_blank"),
        CheckConstraint("(size_bytes IS NULL) OR (size_bytes >= 0)", name="ck_bundle_size_nonneg"),
        CheckConstraint("(label IS NULL) OR (length(btrim(label)) > 0)", name="ck_bundle_label_not_blank"),
        CheckConstraint("(season_number IS NULL) OR (season_number >= 0)", name="ck_bundle_season_nonneg"),
        CheckConstraint("(expires_at IS NULL) OR (expires_at > created_at)", name="ck_bundle_expiry_after_create"),

        # Only one active bundle per (title, season_number) conventionally
        Index(
            "uq_bundle_per_title_season",
            "title_id",
            "season_number",
            unique=True,
            postgresql_where=text("season_number IS NOT NULL"),
        ),

        Index("ix_bundles_created_at", "created_at"),
    )

    title = relationship("Title", back_populates="bundles", lazy="selectin", passive_deletes=True)
    created_by = relationship("User", lazy="selectin")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Bundle id={self.id} title={self.title_id} season={self.season_number} key={self.storage_key}>"

