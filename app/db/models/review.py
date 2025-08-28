# app/db/models/review.py
from __future__ import annotations

"""
⭐ Review — user ratings with optional text (production-grade)
=============================================================

Captures a user’s opinion of a Title (movie or series) with moderation,
spoiler flags, and light anti-abuse metadata.

Highlights
----------
- **Single review per (user,title)** via unique constraint.
- **Moderation workflow** with compact enum: PENDING/APPROVED/REJECTED/REMOVED.
- **Spoiler & language** fields for UX filters and i18n.
- **Sanity checks** on rating range and content length.
- **Analytics-friendly indexes**, including a partial index over approved rows.
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
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    JSON,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class ModerationStatus(PyEnum):
    """Lifecycle of a review in the moderation system."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REMOVED = "REMOVED"  # admin hard-remove but keep row for audit


class Review(Base):
    """
    A user’s rating and optional text commentary for a `Title`.

    Conventions
    -----------
    - `rating` is a **1..10** integer (store halves client-side as 2×, if needed).
    - `content` is plain text or already-sanitized HTML (sanitization happens at the API layer).
    - `moderation_status` controls visibility in public feeds & aggregates.
    """

    __tablename__ = "reviews"

    # ── Identity & ownership ────────────────────────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True)

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Author of the review.",
    )

    title_id = Column(
        UUID(as_uuid=True),
        ForeignKey("titles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Reviewed Title (movie or series).",
    )

    # ── Core review fields ──────────────────────────────────────────────────
    rating = Column(
        SmallInteger,
        nullable=False,
        doc="User rating, integer 1..10.",
    )

    content = Column(
        Text,
        nullable=True,
        doc="Optional review text (sanitized upstream).",
    )

    is_spoiler = Column(
        Boolean,
        nullable=False,
        server_default=text("false"),
        doc="Marks the review as containing spoilers.",
    )

    language = Column(
        String(12),
        nullable=True,
        doc="BCP-47/ISO language tag for `content`, e.g. 'en', 'en-US'.",
    )

    # ── Moderation / abuse / meta ───────────────────────────────────────────
    moderation_status = Column(
        Enum(ModerationStatus, name="review_moderation_status"),
        nullable=False,
        server_default=text("'PENDING'"),
        index=True,
    )

    abuse_report_count = Column(
        Integer,
        nullable=False,
        server_default=text("0"),
        doc="Number of times users reported this review.",
    )

    last_reported_at = Column(DateTime(timezone=True), nullable=True)

    helpful_count = Column(
        Integer,
        nullable=False,
        server_default=text("0"),
        doc="Community 'helpful' votes.",
    )

    ip_hash = Column(
        String(64),
        nullable=True,
        index=True,
        doc="Hashed remote IP (for rate-limiting/abuse heuristics; never store raw IP).",
    )

    client_app = Column(
        String(64),
        nullable=True,
        doc="Client build identifier, e.g. 'web@1.42.0'.",
    )

    moderation_meta = Column(
        JSON,
        nullable=True,
        doc="Free-form moderation notes/labels (kept minimal; no PII).",
    )

    # ── Timestamps ─────────────────────────────────────────────────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    published_at = Column(
        DateTime(timezone=True),
        nullable=True,
        doc="When it first became public (upon approval).",
    )

    __mapper_args__ = {"eager_defaults": True}

    # ── Constraints & indexes ──────────────────────────────────────────────
    __table_args__ = (
        # One review per (user,title)
        UniqueConstraint("user_id", "title_id", name="uq_reviews_user_title"),
        # Rating sanity (1..10)
        CheckConstraint("rating BETWEEN 1 AND 10", name="ck_reviews_rating_range"),
        # Keep review bodies reasonably bounded at the DB layer
        CheckConstraint(
            "content IS NULL OR char_length(content) <= 8000",
            name="ck_reviews_content_len",
        ),
        # Speed up listing/aggregations over visible reviews
        Index(
            "ix_reviews_title_approved",
            "title_id",
            unique=False,
            postgresql_where=text("moderation_status = 'APPROVED'"),
        ),
        Index("ix_reviews_title_created", "title_id", "created_at"),
        Index("ix_reviews_user_created", "user_id", "created_at"),
    )

    # ── Relationships ──────────────────────────────────────────────────────
    user = relationship(
        "User",
        back_populates="reviews",
        lazy="selectin",
        passive_deletes=True,
    )
    title = relationship(
        "Title",
        back_populates="reviews",
        lazy="selectin",
        passive_deletes=True,
    )

    # ── Convenience API ────────────────────────────────────────────────────
    @property
    def stars_5(self) -> float:
        """Return a 0–5 star value (half-star precision) derived from the 1–10 rating."""
        return round(self.rating / 2.0, 1)

    @property
    def is_public(self) -> bool:
        """True if this review is publicly visible."""
        return self.moderation_status == ModerationStatus.APPROVED

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Review user={self.user_id} title={self.title_id} rating={self.rating} status={self.moderation_status.value}>"
