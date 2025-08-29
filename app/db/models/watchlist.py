# app/db/models/watchlist.py
from __future__ import annotations

"""
🎬 MoviesNow — WatchlistItem (user ↔ title bookmark)
====================================================

Tracks titles a user saved to their watchlist with lightweight state for
ordering, favorites, progress, and notifications.

Why this design?
----------------
• **Composite PK** (user_id, title_id) — no surrogate key, no duplicates.  
• **DB-driven, tz-aware timestamps** via `func.now()`.  
• **Server defaults** for all booleans/ints to keep writers consistent.  
• **Partial indexes** for common queries (visible items, favorites, notifications).  
• **Optional per-user ordering** via `sort_index` (partial unique when set).
"""

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class WatchlistItem(Base):
    __tablename__ = "watchlist_items"

    # ── Composite identity ──────────────────────────────────────────────────
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
        doc="Owner of the watchlist entry.",
    )
    title_id = Column(
        UUID(as_uuid=True),
        ForeignKey("titles.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
        doc="Bookmarked title.",
    )

    # ── State / presentation ────────────────────────────────────────────────
    sort_index = Column(Integer, nullable=True, doc="Optional per-user order; lower = earlier.")
    is_favorite = Column(Boolean, nullable=False, server_default=text("false"))
    archived = Column(Boolean, nullable=False, server_default=text("false"), doc="Soft hide without losing history.")

    # ── Progress / engagement ───────────────────────────────────────────────
    progress_pct = Column(Integer, nullable=False, server_default=text("0"), doc="0–100 for resume/continue watching.")
    last_watched_at = Column(DateTime(timezone=True), nullable=True)

    # ── Notifications ───────────────────────────────────────────────────────
    notify_new_content = Column(Boolean, nullable=False, server_default=text("true"))

    # ── Notes (tiny) ───────────────────────────────────────────────────────
    note = Column(String(280), nullable=True, doc="Short user note (<=280 chars).")

    # ── Timestamps (DB-driven UTC) ─────────────────────────────────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ── Constraints & indexes ───────────────────────────────────────────────
    __table_args__ = (
        # Progress and note hygiene
        CheckConstraint("progress_pct BETWEEN 0 AND 100", name="ck_watchlist_progress_bounds"),
        CheckConstraint("note IS NULL OR char_length(note) <= 280", name="ck_watchlist_note_len"),
        CheckConstraint("updated_at >= created_at", name="ck_watchlist_updated_after_created"),

        # Optional: keep sort_index unique per user when set
        Index(
            "uq_watchlist_user_sortindex",
            "user_id",
            "sort_index",
            unique=True,
            postgresql_where=text("sort_index IS NOT NULL"),
        ),

        # Common query paths
        Index("ix_watchlist_user_created", "user_id", "created_at"),
        Index("ix_watchlist_user_visible", "user_id", postgresql_where=text("archived = false")),
        Index("ix_watchlist_user_favorites", "user_id", postgresql_where=text("is_favorite = true")),
        Index("ix_watchlist_user_notify", "user_id", postgresql_where=text("notify_new_content = true")),
    )

    # ── Relationships ───────────────────────────────────────────────────────
    user = relationship(
        "User",
        back_populates="watchlist_items",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="WatchlistItem.user_id == User.id",
        foreign_keys="[WatchlistItem.user_id]",
    )

    title = relationship(
        "Title",
        back_populates="watchlisted_by",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="WatchlistItem.title_id == Title.id",
        foreign_keys="[WatchlistItem.title_id]",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<WatchlistItem user_id={self.user_id} title_id={self.title_id} "
            f"fav={self.is_favorite} progress={self.progress_pct}% archived={self.archived}>"
        )
