# app/db/models/watchlist.py
from __future__ import annotations

"""
🎬 WatchlistItem — user ↔ title bookmark (production-grade)
===========================================================

Tracks titles a user has saved to their watchlist, with lightweight state
for ordering, favorites, progress, and notifications.

Design notes
------------
- **Composite PK** `(user_id, title_id)` prevents duplicates without an extra id.
- **CASCADE** on both FKs ensures automatic cleanup when user/title is deleted.
- **Ordering** via `sort_index` (nullable → client can omit; backend can backfill).
- **Progress** captured as a percentage (0–100) for “continue watching”.
- **Archiving** lets users hide without losing history.
- **Notification toggle** for new seasons/episodes/drops.
- Tight indexes for common queries: “all items for a user”, “is title in user’s list?”.

Relationships
-------------
`User.watchlist_items` ←→ `WatchlistItem.user`  
`Title.watchlisted_by`  ←→ `WatchlistItem.title`
"""

from datetime import datetime
from sqlalchemy import (
    Column,
    Boolean,
    DateTime,
    Integer,
    String,
    CheckConstraint,
    Index,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base_class import Base


class WatchlistItem(Base):
    __tablename__ = "watchlist_items"

    # ─────────────── Composite identity ───────────────
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
        doc="Owner of the watchlist entry",
    )
    title_id = Column(
        UUID(as_uuid=True),
        ForeignKey("titles.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
        doc="Bookmarked title",
    )

    # ─────────────── State / presentation ───────────────
    sort_index = Column(
        Integer,
        nullable=True,
        doc="Optional client-controlled ordering (lower = earlier).",
    )
    is_favorite = Column(Boolean, nullable=False, default=False)
    archived = Column(
        Boolean,
        nullable=False,
        default=False,
        doc="Soft hide from default lists while retaining history.",
    )

    # ─────────────── Progress / engagement ───────────────
    progress_pct = Column(
        Integer,
        nullable=False,
        default=0,
        doc="0–100 playback progress for resume/continue watching.",
    )
    last_watched_at = Column(DateTime(timezone=True), nullable=True)

    # ─────────────── Notifications ───────────────
    notify_new_content = Column(
        Boolean,
        nullable=False,
        default=True,
        doc="Send alerts for new episodes/seasons or platform drops.",
    )

    # ─────────────── Notes (tiny) ───────────────
    note = Column(
        String(280),
        nullable=True,
        doc="Short user note (kept small to avoid bloat).",
    )

    # ─────────────── Timestamps (DB-driven UTC) ───────────────
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __mapper_args__ = {"eager_defaults": True}

    __table_args__ = (
        # Valid progress range
        CheckConstraint("progress_pct >= 0 AND progress_pct <= 100", name="ck_watchlist_progress_bounds"),
        # If you want to keep sort_index unique per user, uncomment the next line:
        # Index("uq_watchlist_user_sort", "user_id", "sort_index", unique=True, postgresql_where=(sort_index.isnot(None))),
        # Fast listings per user
        Index("ix_watchlist_user_created", "user_id", "created_at"),
    )

    # ─────────────── Relationships ───────────────
    user = relationship(
        "User",
        back_populates="watchlist_items",
        lazy="selectin",
        passive_deletes=True,
    )
    title = relationship(
        "Title",
        back_populates="watchlisted_by",
        lazy="selectin",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return (
            f"<WatchlistItem user_id={self.user_id} title_id={self.title_id} "
            f"fav={self.is_favorite} progress={self.progress_pct}% archived={self.archived}>"
        )
