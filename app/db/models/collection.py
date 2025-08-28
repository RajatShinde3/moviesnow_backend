# app/db/models/collection.py
from __future__ import annotations

"""
📚 Collection & CollectionItem (production-grade)
================================================

Curated sets of titles (franchises, themed rows, editor picks, or user playlists)
with ordered membership.

Highlights
----------
- **Collection**
  - Global or user-owned (`owner_user_id` nullable).
  - Strong slug rules with **case-insensitive** uniqueness (global vs per-owner).
  - Visibility & kind enums, publish/feature flags, cover/hero artwork keys.
  - Tags & metadata for flexible storefront curation.
- **CollectionItem**
  - Ordered many-to-many association (composite PK).
  - Optional `position` unique per collection (when provided).
  - `added_by_user_id` audit trail for collaborative playlists.

Back-refs (add to existing models)
----------------------------------
- `User.collections`  ←→  `Collection.owner`
- `Title.collection_items` / `Title.in_collections`  ←→  `CollectionItem.title` / `Collection.titles`
"""

from enum import Enum as PyEnum
from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    JSON,
    Index,
    CheckConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base_class import Base


# ──────────────────────────────────────────────────────────────
# 🔤 Enums
# ──────────────────────────────────────────────────────────────
class CollectionVisibility(PyEnum):
    PUBLIC = "PUBLIC"
    UNLISTED = "UNLISTED"
    PRIVATE = "PRIVATE"


class CollectionKind(PyEnum):
    FRANCHISE = "FRANCHISE"        # e.g., "The Avengers Collection"
    THEME = "THEME"                # e.g., "Holiday Classics"
    EDITORIAL = "EDITORIAL"        # curated rows
    PLAYLIST = "PLAYLIST"          # user-created list
    SERIES_SET = "SERIES_SET"      # grouped limited/anthology, etc.


# ──────────────────────────────────────────────────────────────
# 🗂️ Collection
# ──────────────────────────────────────────────────────────────
class Collection(Base):
    """
    A curated set of titles with ordered membership.

    Scope:
        - **Global** (no owner): editorial collections, franchises, storefront rows.
        - **User-owned** (owner_user_id): personal/public playlists.

    Slug rules:
        - Global collections: slug unique (case-insensitive) across all.
        - User-owned: slug unique per owner (case-insensitive).
    """

    __tablename__ = "collections"

    id = Column(UUID(as_uuid=True), primary_key=True)
    owner_user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Null for global/editorial collections; set for user playlists.",
    )

    # Identity / presentation
    name = Column(String(200), nullable=False)
    slug = Column(String(200), nullable=False, index=True, doc="URL-friendly key")
    description = Column(String, nullable=True)

    # Curation attributes
    kind = Column(Enum(CollectionKind, name="collection_kind"), nullable=False, default=CollectionKind.EDITORIAL)
    visibility = Column(
        Enum(CollectionVisibility, name="collection_visibility"),
        nullable=False,
        default=CollectionVisibility.PUBLIC,
    )
    is_published = Column(Boolean, nullable=False, default=False)
    is_featured = Column(Boolean, nullable=False, default=False)
    published_at = Column(DateTime(timezone=True), nullable=True)

    # Artwork / metadata
    cover_image_key = Column(String, nullable=True, doc="S3/CDN key for cover art")
    hero_image_key = Column(String, nullable=True, doc="S3/CDN key for hero/banner art")
    tags = Column(JSON, nullable=True, comment="Freeform labels for discovery")
    metadata = Column(JSON, nullable=True, comment="Arbitrary curation/config data")

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __mapper_args__ = {"eager_defaults": True}

    __table_args__ = (
        # Non-blank name & slug
        CheckConstraint("length(btrim(name)) > 0", name="ck_collections_name_not_blank"),
        CheckConstraint("length(btrim(slug)) > 0", name="ck_collections_slug_not_blank"),

        # Publish invariant: published_at implies is_published
        CheckConstraint(
            "(published_at IS NULL) OR (is_published = TRUE)",
            name="ck_collections_published_at_requires_flag",
        ),

        # Case-insensitive uniqueness for slugs:
        # 1) Global collections: owner_user_id IS NULL
        Index(
            "uq_collections_slug_global",
            func.lower(slug),
            unique=True,
            postgresql_where=text("owner_user_id IS NULL"),
        ),
        # 2) User-owned collections: unique per owner
        Index(
            "uq_collections_slug_per_owner",
            func.lower(slug),
            "owner_user_id",
            unique=True,
            postgresql_where=text("owner_user_id IS NOT NULL"),
        ),

        # Handy filters
        Index("ix_collections_visibility_published", "visibility", "is_published"),
        Index("ix_collections_featured", "is_featured"),
        Index("ix_collections_created_at", "created_at"),
    )

    # Relationships
    owner = relationship(
        "User",
        back_populates="collections",
        lazy="selectin",
        passive_deletes=True,
    )

    items = relationship(
        "CollectionItem",
        back_populates="collection",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        order_by="CollectionItem.position.asc().nulls_last(), CollectionItem.added_at.asc()",
    )

    # Convenience many-to-many to reach titles directly
    titles = relationship(
        "Title",
        secondary="collection_items",
        back_populates="in_collections",
        lazy="selectin",
        viewonly=True,  # authoritative edits go via CollectionItem
    )

    def __repr__(self) -> str:
        return f"<Collection id={self.id} slug='{self.slug}' kind={self.kind.value} vis={self.visibility.value}>"


# ──────────────────────────────────────────────────────────────
# 🔗 CollectionItem (association)
# ──────────────────────────────────────────────────────────────
class CollectionItem(Base):
    """
    Ordered association between a `Collection` and a `Title`.

    - Composite primary key `(collection_id, title_id)` prevents duplicates.
    - `position` supports deterministic ordering within a collection.
    - `added_by_user_id` preserves authorship for collaborative playlists.
    """

    __tablename__ = "collection_items"

    collection_id = Column(
        UUID(as_uuid=True),
        ForeignKey("collections.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )
    title_id = Column(
        UUID(as_uuid=True),
        ForeignKey("titles.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )

    # Ordering & audit
    position = Column(Integer, nullable=True, doc="0-based ordering; nullable when not curated.")
    added_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    added_by_user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    note = Column(String(280), nullable=True)

    __table_args__ = (
        # If you want unique positions per collection (when supplied), keep this partial unique index:
        Index(
            "uq_collection_item_position_per_collection",
            "collection_id",
            "position",
            unique=True,
            postgresql_where=text("position IS NOT NULL"),
        ),
        Index("ix_collection_items_collection_order", "collection_id", "position", "added_at"),
    )

    # Relationships
    collection = relationship(
        "Collection",
        back_populates="items",
        lazy="selectin",
        passive_deletes=True,
    )
    title = relationship(
        "Title",
        back_populates="collection_items",
        lazy="selectin",
        passive_deletes=True,
    )
    added_by = relationship(
        "User",
        lazy="selectin",
        foreign_keys=[added_by_user_id],
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<CollectionItem collection_id={self.collection_id} title_id={self.title_id} pos={self.position}>"
