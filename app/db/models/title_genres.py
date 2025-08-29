from __future__ import annotations

"""
🎬 MoviesNow — Title ⇄ Genre Association (production‑grade)
==========================================================

A mapped association model linking a **Title** (movie/series) to a **Genre** with
editorial ordering and auditing. Prefer a mapped class (vs. a raw secondary Table)
so we can carry `weight`, timestamps, and future metadata without schema churn.

Why a mapped model?
-------------------
• Deterministic **ordering** inside a title via `weight` (nullable ⇒ not curated).
• **Auditable** writes with DB‑driven UTC timestamps.
• Clean **CASCADE** semantics and selective indexes for common access paths.

Relationships
-------------
• `Title.genres`  ↔ many‑to‑many through `secondary="title_genres"` (on Title)
• `Genre.titles`  ↔ many‑to‑many through `secondary="title_genres"` (on Genre)
• Lightweight convenience edges here: `TitleGenre.title` and `TitleGenre.genre`.

Conventions
-----------
• Composite primary key `(title_id, genre_id)` ⇒ each pair is unique by design.
• `weight` is **not** unique; ties are allowed unless your UX forbids them.
• All timestamps are timezone‑aware (UTC) and DB‑driven (`func.now()`).
"""

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class TitleGenre(Base):
    """Association row connecting a :class:`Title` to a :class:`Genre`."""

    __tablename__ = "title_genres"

    # ── Composite identity ──────────────────────────────────────────────────
    title_id = Column(
        UUID(as_uuid=True),
        ForeignKey("titles.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
        nullable=False,
        doc="FK → titles.id; CASCADE so removing a title cleans up mappings.",
    )
    genre_id = Column(
        UUID(as_uuid=True),
        ForeignKey("genres.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
        nullable=False,
        doc="FK → genres.id; CASCADE so removing a genre cleans up mappings.",
    )

    # ── Editorial / auditing ────────────────────────────────────────────────
    weight = Column(
        Integer,
        nullable=True,
        doc="Optional per‑title ordering for genres (smaller = earlier).",
    )
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="UTC creation time (DB‑driven).",
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        doc="UTC last update time (DB‑driven).",
    )

    __mapper_args__ = {"eager_defaults": True}

    # ── Lightweight convenience relationships (no back_populates required) ──
    title = relationship(
        "Title",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="TitleGenre.title_id == Title.id",
        foreign_keys="[TitleGenre.title_id]",
    )

    genre = relationship(
        "Genre",
        lazy="selectin",
        passive_deletes=True,
        primaryjoin="TitleGenre.genre_id == Genre.id",
        foreign_keys="[TitleGenre.genre_id]",
    )

    # ── Indexes / constraints ───────────────────────────────────────────────
    __table_args__ = (
        # Keep weight sensible when provided
        CheckConstraint("weight IS NULL OR weight >= 0", name="ck_title_genres_weight_nonneg"),
        # Helpful access patterns
        Index("ix_title_genres_title_weight", "title_id", "weight"),
        Index("ix_title_genres_genre_title", "genre_id", "title_id"),
        Index("ix_title_genres_created_at", "created_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<TitleGenre title_id={self.title_id} genre_id={self.genre_id} weight={self.weight}>"