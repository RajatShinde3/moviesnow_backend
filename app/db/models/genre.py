# app/db/models/genre.py
from __future__ import annotations

"""
🍿 MoviesNow — Genre Model
=========================

Normalized catalog of content **genres** with optional parent/child hierarchy and
a many-to-many link to **Title**. Designed for fast filtering, clean dedupe, and
stable SEO-friendly slugs.

Highlights
----------
- Canonical `slug` with case-insensitive uniqueness guard on `name`.
- Optional hierarchy via `parent_id` for subgenres.
- Many-to-many association to `Title` through `title_genres` join table.
- Compact indexes for common queries and listings.
- UTC, DB-driven timestamps; defensive constraints.
"""

from uuid import uuid4

from sqlalchemy import (
    Column,
    String,
    Text,
    Boolean,
    Integer,
    DateTime,
    ForeignKey,
    Index,
    CheckConstraint,
    UniqueConstraint,
    func,
    text,
    Table,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.base_class import Base

# ──────────────────────────────────────────────────────────────
# 🔗 Association: Title ↔ Genre (composite PK; no duplicates)
# ──────────────────────────────────────────────────────────────
title_genres = Table(
    "title_genres",
    Base.metadata,
    Column("title_id", UUID(as_uuid=True),
           ForeignKey("titles.id", ondelete="CASCADE"), primary_key=True),
    Column("genre_id", UUID(as_uuid=True),
           ForeignKey("genres.id", ondelete="CASCADE"), primary_key=True),
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Index("ix_title_genres_title", "title_id"),
    Index("ix_title_genres_genre", "genre_id"),
)


class Genre(Base):
    """
    Canonical genre row (e.g., "Action", "Drama", "Sci-Fi").

    Fields
    ------
    name            Human-readable display name.
    slug            Stable, URL-safe identifier (unique).
    description     Optional longer copy for landing pages.
    aliases         Optional list of alternate spellings/labels.
    parent_id       Optional parent for hierarchical subgenres.
    is_active       Toggle for curation without hard deletes.
    display_order   Optional sort weight for curated menus.

    Relationships
    -------------
    titles    Many-to-many via `title_genres` (see Title.genres backref).
    parent    Self-reference to parent Genre (nullable).
    children  Self-reference collection of subgenres.
    """

    __tablename__ = "genres"

    # Identity
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    # Canonical naming
    name = Column(String(80), nullable=False)
    slug = Column(String(96), nullable=False, unique=True, index=True)

    # Copy / SEO
    description = Column(Text, nullable=True)
    aliases = Column(JSONB, nullable=True, doc="Optional list of alternate names for search/ingest.")
    seo_title = Column(String(140), nullable=True)
    seo_description = Column(String(180), nullable=True)

    # Hierarchy
    parent_id = Column(
        UUID(as_uuid=True),
        ForeignKey("genres.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Curation & ordering
    is_active = Column(Boolean, nullable=False, server_default=text("true"))
    display_order = Column(Integer, nullable=True, index=True)

    # Audit
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # Constraints & indexes
    __table_args__ = (
        # Basic hygiene
        CheckConstraint("length(btrim(name)) > 0", name="ck_genres_name_not_blank"),
        CheckConstraint("updated_at >= created_at", name="ck_genres_updated_after_created"),
        # Extra dedupe shield: prevent case-only duplicates of name
        UniqueConstraint(func.lower(name), name="uq_genres_name_lower"),
        # Handy composite index for catalogs
        Index("ix_genres_active_order", "is_active", "display_order"),
    )

    # Relationships
    parent = relationship(
        "Genre",
        remote_side=lambda: [Genre.id],  # type: ignore[name-defined]
        back_populates="children",
        lazy="selectin",
        passive_deletes=True,
    )
    children = relationship(
        "Genre",
        back_populates="parent",
        lazy="selectin",
        passive_deletes=True,
    )

    titles = relationship(
        "Title",
        secondary=title_genres,
        back_populates="genres",
        lazy="selectin",
        passive_deletes=True,
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Genre id={self.id} slug={self.slug} active={self.is_active}>"
