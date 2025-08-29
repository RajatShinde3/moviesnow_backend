from __future__ import annotations

"""
🍿 MoviesNow — Genre (normalized taxonomy)
=========================================

Production‑grade model for a normalized catalog of genres with optional hierarchy
and many‑to‑many linkage to `Title` via the `title_genres` association table.

Highlights
----------
• **Case‑insensitive** uniqueness for both `name` and `slug` (functional indexes).
• Optional **hierarchy** (`parent_id`) with non‑self constraint.
• SEO fields and **aliases** (JSONB) for search and ingest synonyms.
• Clean timestamps (UTC, DB‑driven) and pragmatic indexes for storefront queries.

Relationships
-------------
• `Genre.parent`   ↔  `Genre.children`
• `Genre.titles`   ↔  `Title.genres` (via `title_genres`)

Conventions
-----------
• Avoid the reserved `metadata` name; not used here.
• Use `func.now()` server defaults and `eager_defaults=True` for consistency.
"""

from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class Genre(Base):
    __tablename__ = "genres"

    # ───────────────── Identity ─────────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    # ───────────────── Canonical naming ─────────────────
    name = Column(String(80), nullable=False)
    slug = Column(String(96), nullable=False, index=True, doc="URL‑friendly key")

    # ───────────────── Copy / SEO ─────────────────
    description = Column(Text, nullable=True)
    aliases = Column(JSONB, nullable=True, doc="Alternate names for search/ingest (array/object).")
    seo_title = Column(String(140), nullable=True)
    seo_description = Column(String(180), nullable=True)

    # ───────────────── Hierarchy ─────────────────
    parent_id = Column(UUID(as_uuid=True), ForeignKey("genres.id", ondelete="SET NULL"), nullable=True, index=True)

    # ───────────────── Curation & ordering ─────────────────
    is_active = Column(Boolean, nullable=False, server_default=text("true"))
    display_order = Column(Integer, nullable=True, index=True)

    # ───────────────── Audit (DB‑driven UTC) ─────────────────
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    __table_args__ = (
        # Non‑blank guards
        CheckConstraint("length(btrim(name)) > 0", name="ck_genres_name_not_blank"),
        CheckConstraint("length(btrim(slug)) > 0", name="ck_genres_slug_not_blank"),
        # Display order sanity
        CheckConstraint("(display_order IS NULL OR display_order >= 0)", name="ck_genres_display_order_nonneg"),
        # Prevent self‑parenting (deep cycles are application‑guarded)
        CheckConstraint("(parent_id IS NULL OR parent_id <> id)", name="ck_genres_no_self_parent"),
        CheckConstraint("updated_at >= created_at", name="ck_genres_updated_after_created"),
        # Case‑insensitive uniqueness
        Index("uq_genres_name_ci", func.lower(name), unique=True),
        Index("uq_genres_slug_ci", func.lower(slug), unique=True),
        # Handy filters
        Index("ix_genres_active_order", "is_active", "display_order"),
        Index("ix_genres_parent_order", "parent_id", "display_order"),
        Index("ix_genres_created_at", "created_at"),
        # Search helpers
        Index("ix_genres_aliases_gin", "aliases", postgresql_using="gin"),
    )

    # ───────────────── Relationships ─────────────────
    # Self-hierarchy
    parent = relationship(
        "Genre",
        remote_side=lambda: [Genre.id],
        back_populates="children",
        lazy="selectin",
        passive_deletes=True,
    )

    children = relationship(
        "Genre",
        back_populates="parent",
        order_by=lambda: (Genre.display_order.asc().nulls_last(), Genre.name.asc()),
        lazy="selectin",
        passive_deletes=True,
    )

    # M2M to titles
    titles = relationship(
        "Title",
        secondary="title_genres",
        back_populates="genres",
        lazy="selectin",
        passive_deletes=True,
    )


    def __repr__(self) -> str:  # pragma: no cover
        return f"<Genre id={self.id} slug={self.slug} active={self.is_active}>"
