from __future__ import annotations

"""
🎬 MoviesNow — Collections & Items (production‑grade)
====================================================

Defines:
  • `Collection`: curated sets of titles (editorial rows, franchises, playlists).
  • `CollectionItem`: ordered association object linking a Collection ↔ Title.

Design highlights
-----------------
• **Case‑insensitive slug uniqueness** for global vs user‑owned collections.
• **Optional ordering** with `position`; when absent, items sort by creation time.
• **Per‑item window** (`starts_at`/`ends_at`) + soft flag `is_active`.
• **Auditability** via `created_at`, `updated_at`, and `added_by_user_id`.
• **Efficient indexes** for common storefront queries.
• Clean SQLAlchemy patterns: eager defaults, passive deletes, deferred `order_by`.

Conventions
-----------
• All timestamps are timezone‑aware (UTC) and DB‑driven (`func.now()`).
• Avoid the reserved attribute name `metadata` by exposing it as `metadata_json`
  while keeping the DB column name "metadata".

Relationships expected elsewhere
--------------------------------
• `User.collections`  ↔  `Collection.owner`
• `Title.collection_items` / `Title.in_collections`  ↔  `CollectionItem.title` / `Collection.titles`
"""

from enum import Enum as PyEnum
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import nullslast
from app.schemas.enums import CollectionVisibility, CollectionKind
from app.db.base_class import Base



# ──────────────────────────────────────────────────────────────
# 🗂️ Collection
# ──────────────────────────────────────────────────────────────
class Collection(Base):
    """Curated set of titles with ordered membership.

    Scope
    -----
    • Global/editorial (``owner_user_id`` is ``NULL``)
    • User‑owned playlists (``owner_user_id`` set)

    Slug rules
    ----------
    • Global: slug unique *case‑insensitively* across all global collections.
    • Per‑owner: slug unique *case‑insensitively* within a given owner.

    Ordering
    --------
    Items are ordered by ``position`` (NULLS LAST), then by ``created_at``. This
    allows deterministic ordering when curated, while newly added items still have
    a stable order without explicit positions.
    """

    __tablename__ = "collections"

    # Identity / ownership
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    owner_user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="NULL for global/editorial; set for user playlists.",
    )

    # Presentation
    name = Column(String(200), nullable=False)
    slug = Column(String(200), nullable=False, index=True, doc="URL‑friendly key")
    description = Column(String, nullable=True)

    # Curation attributes
    kind = Column(Enum(CollectionKind, name="collection_kind"), nullable=False, default=CollectionKind.EDITORIAL)
    visibility = Column(
        Enum(CollectionVisibility, name="collection_visibility"),
        nullable=False,
        default=CollectionVisibility.PUBLIC,
    )
    is_published = Column(Boolean, nullable=False, server_default=text("false"))
    is_featured = Column(Boolean, nullable=False, server_default=text("false"))
    published_at = Column(DateTime(timezone=True), nullable=True)

    # Artwork / metadata
    cover_image_key = Column(String, nullable=True, doc="S3/CDN key for cover art")
    hero_image_key = Column(String, nullable=True, doc="S3/CDN key for hero/banner art")
    tags = Column(JSON, nullable=True, comment="Freeform labels for discovery")
    metadata_json = Column("metadata", JSON, nullable=True, comment="Arbitrary curation/config data")

    # Timestamps (DB‑driven UTC)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    __table_args__ = (
        # Non‑blank name & slug
        CheckConstraint("length(btrim(name)) > 0", name="ck_collections_name_not_blank"),
        CheckConstraint("length(btrim(slug)) > 0", name="ck_collections_slug_not_blank"),

        # Publish invariant: published_at implies is_published
        CheckConstraint(
            "(published_at IS NULL) OR (is_published = TRUE)",
            name="ck_collections_published_at_requires_flag",
        ),

        # Case‑insensitive uniqueness for slugs
        Index(
            "uq_collections_slug_global",
            func.lower(slug),
            unique=True,
            postgresql_where=text("owner_user_id IS NULL"),
        ),
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
        primaryjoin="Collection.owner_user_id == User.id",
        foreign_keys="[Collection.owner_user_id]",
    )

    items = relationship(
        "CollectionItem",
        back_populates="collection",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
        primaryjoin="CollectionItem.collection_id == Collection.id",
        foreign_keys="[CollectionItem.collection_id]",
        order_by=lambda: (nullslast(CollectionItem.position.asc()), CollectionItem.created_at.asc()),
    )

    titles = relationship(  # view-only convenience
        "Title",
        secondary="collection_items",
        primaryjoin="CollectionItem.collection_id == Collection.id",
        secondaryjoin="CollectionItem.title_id == Title.id",
        viewonly=True,
        lazy="selectin",
)
    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Collection id={self.id} slug='{self.slug}' "
            f"kind={self.kind.value} vis={self.visibility.value}>"
        )


# ──────────────────────────────────────────────────────────────
# 🔗 CollectionItem (association object)
# ──────────────────────────────────────────────────────────────
class CollectionItem(Base):
    """Ordered association between a :class:`Collection` and a :class:`Title`.

    Identity
    --------
    Composite primary key ``(collection_id, title_id)`` prevents duplicates.

    Ordering
    --------
    ``position`` (0‑based) controls editorial order; when ``NULL``, items fall back
    to ``created_at``. A **partial unique index** enforces that each *non‑NULL*
    position is unique per collection.

    Visibility window
    -----------------
    ``is_active`` allows temporary hides without deletion; ``starts_at``/``ends_at``
    bound item visibility in time.

    Audit
    -----
    ``created_at``, ``updated_at`` are DB‑driven; ``added_by_user_id`` preserves
    authorship for collaborative playlists.

    Indexing
    --------
    Optimized for storefront queries (by collection, by position/active, by title).
    """

    __tablename__ = "collection_items"

    # Composite identity
    collection_id = Column(
        UUID(as_uuid=True),
        ForeignKey("collections.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
        nullable=False,
        doc="FK → collections.id; CASCADE ensures cleanup when the collection is removed.",
    )
    title_id = Column(
        UUID(as_uuid=True),
        ForeignKey("titles.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
        nullable=False,
        doc="FK → titles.id; CASCADE ensures cleanup when the title is removed.",
    )

    # Editorial / toggles
    position = Column(Integer, nullable=True, doc="0‑based ordering; NULL when not curated.")
    featured = Column(Boolean, nullable=False, server_default=text("false"), doc="Highlight in UI (hero/large tile).")
    is_active = Column(Boolean, nullable=False, server_default=text("true"), doc="Soft activation toggle.")
    note = Column(String(280), nullable=True, doc="Optional short editorial note/label.")

    # Optional per‑item window (UTC)
    starts_at = Column(DateTime(timezone=True), nullable=True, doc="Visibility start (UTC).")
    ends_at = Column(DateTime(timezone=True), nullable=True, doc="Visibility end (UTC).")

    # Audit
    added_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Timestamps (DB‑driven UTC)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    __table_args__ = (
        # Keep position sensible & window valid
        CheckConstraint("(position IS NULL) OR (position >= 0)", name="ck_collection_item_position_nonneg"),
        CheckConstraint(
            "(starts_at IS NULL) OR (ends_at IS NULL) OR (ends_at >= starts_at)",
            name="ck_collection_item_window_valid",
        ),
        # Helpful access patterns
        Index("ix_collection_items_collection_active", "collection_id", "is_active"),
        Index(
            "uq_collection_item_position_per_collection",
            "collection_id",
            "position",
            unique=True,
            postgresql_where=text("position IS NOT NULL"),
        ),
        Index("ix_collection_items_collection_position", "collection_id", "position"),
        Index("ix_collection_items_title", "title_id"),
        Index("ix_collection_items_created_at", "created_at"),
    )

    # Relationships
    collection = relationship(
        "Collection",
        back_populates="items",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="CollectionItem.collection_id == Collection.id",
        foreign_keys="[CollectionItem.collection_id]",
    )

    title = relationship(
        "Title",
        back_populates="collection_items",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="CollectionItem.title_id == Title.id",
        foreign_keys="[CollectionItem.title_id]",
    )

    added_by = relationship(
        "User",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="CollectionItem.added_by_user_id == User.id",
        foreign_keys="[CollectionItem.added_by_user_id]",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<CollectionItem collection_id={self.collection_id} title_id={self.title_id} "
            f"pos={self.position} active={self.is_active}>"
        )
