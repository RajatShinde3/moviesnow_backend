from __future__ import annotations

"""
🎞️ MoviesNow — Credit (Cast & Crew)
===================================

Associates a **Person** with a specific **Title**, **Season**, or **Episode** in a
well‑typed, query‑friendly way. Supports cast (actors/voice/guest/cameo) and crew
(director/writer/producer/etc.) with ordering and display metadata.

Design highlights
-----------------
• **Exactly one parent**: a credit belongs to a Title *or* Season *or* Episode (enforced).
• **Rich typing**: `kind` (cast/crew) + `role` (actor/director/…) + optional
  `department` and `job_title` for fine‑grained crew taxonomy.
• **Cast metadata**: `character_name`, `billing_order`, voice/guest/cameo/uncredited flags.
• **De‑dup protection**: partial unique indexes per parent prevent duplicates for the
  same (parent, person, role, character/job) tuple.
• **Fast listings**: composite indexes for `(parent, kind, billing_order)`.

Relationships
-------------
• `Credit.person`  ↔  `Person.credits`
• `Credit.title`   ↔  `Title.credits`
• `Credit.season`  ↔  `Season.credits`
• `Credit.episode` ↔  `Episode.credits`

Conventions
-----------
• All timestamps are timezone‑aware UTC with DB‑driven defaults (`func.now()`).
• Booleans use `server_default` for consistent behavior across writers.
"""

from uuid import uuid4
from enum import Enum

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.base_class import Base
from app.schemas.enums import CreditKind, CreditRole 


# ──────────────────────────────────────────────────────────────
# 🧱 Model: Credit
# ──────────────────────────────────────────────────────────────
class Credit(Base):
    """Single credit linking a person to a title/season/episode with role metadata.

    Notes
    -----
    • Exactly one of (`title_id`, `season_id`, `episode_id`) must be non‑NULL.
    • Use `billing_order` to sort cast lists (lower = earlier). Crew typically sorts
      by `role` then name.
    • Use `credited_as` to preserve on‑screen credit strings differing from Person name.
    """

    __tablename__ = "credits"

    # Identity
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    # Parent (exactly one) — ON DELETE CASCADE
    title_id = Column(UUID(as_uuid=True), ForeignKey("titles.id", ondelete="CASCADE"), nullable=True, index=True)
    season_id = Column(UUID(as_uuid=True), ForeignKey("seasons.id", ondelete="CASCADE"), nullable=True, index=True)
    episode_id = Column(UUID(as_uuid=True), ForeignKey("episodes.id", ondelete="CASCADE"), nullable=True, index=True)

    # Person (required)
    person_id = Column(UUID(as_uuid=True), ForeignKey("people.id", ondelete="CASCADE"), nullable=False, index=True)

    # Taxonomy
    kind = Column(SAEnum(CreditKind, name="credit_kind"), nullable=False)
    role = Column(SAEnum(CreditRole, name="credit_role"), nullable=False)

    # Crew typing (optional; useful for BI/UI grouping)
    department = Column(String(128), nullable=True, doc="High‑level department (e.g., 'Directing', 'Writing').")
    job_title = Column(String(128), nullable=True, doc="Display job title (e.g., 'Executive Producer').")

    # Cast metadata
    character_name = Column(String(256), nullable=True)
    billing_order = Column(Integer, nullable=True, index=True, doc="Lower = earlier in billing; cast lists sort by this.")

    # Display overrides
    credited_as = Column(String(256), nullable=True, doc="On‑screen credited name (if different from person name).")

    # Flags
    is_uncredited = Column(Boolean, nullable=False, server_default=text("false"))
    is_voice = Column(Boolean, nullable=False, server_default=text("false"))
    is_guest = Column(Boolean, nullable=False, server_default=text("false"))
    is_cameo = Column(Boolean, nullable=False, server_default=text("false"))

    # Aggregates (optional; handy for season/title‑level credits)
    episode_count = Column(Integer, nullable=True, doc="For season/title credits: episodes this credit spans.")

    # Extra vendor/ingest metadata
    meta = Column(JSONB, nullable=True)

    # Audit (DB‑driven UTC)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # Constraints & Indexes
    __table_args__ = (
        # Exactly one parent
        CheckConstraint(
            "(CASE WHEN title_id  IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN season_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN episode_id IS NOT NULL THEN 1 ELSE 0 END) = 1",
            name="ck_credit_exactly_one_parent",
        ),
        # Sanity checks
        CheckConstraint("(billing_order IS NULL OR billing_order >= 0)", name="ck_credits_billing_nonneg"),
        CheckConstraint("(episode_count IS NULL OR episode_count > 0)", name="ck_credits_episode_count_pos"),
        # Optional taxonomy consistency (kind ↔ role)
        CheckConstraint(
            "(kind = 'cast' AND role IN ('actor','voice','guest_star','cameo')) OR "
            "(kind = 'crew' AND role IN (\n"
            "  'director','writer','producer','executive_producer','showrunner','creator','composer',\n"
            "  'editor','cinematographer','costume_designer','vfx_supervisor','sound_mixer','music_supervisor',\n"
            "  'stunt_coordinator','other'\n"
            "))",
            name="ck_credits_kind_role_consistent",
        ),

        # De‑dup per scope
        Index(
            "uq_credits_title_person_role_char_job",
            "title_id", "person_id", "role", "character_name", "job_title",
            unique=True,
            postgresql_where=text("title_id IS NOT NULL"),
        ),
        Index(
            "uq_credits_season_person_role_char_job",
            "season_id", "person_id", "role", "character_name", "job_title",
            unique=True,
            postgresql_where=text("season_id IS NOT NULL"),
        ),
        Index(
            "uq_credits_episode_person_role_char_job",
            "episode_id", "person_id", "role", "character_name", "job_title",
            unique=True,
            postgresql_where=text("episode_id IS NOT NULL"),
        ),

        # Fast listing & sorting
        Index("ix_credits_title_kind_billing", "title_id", "kind", "billing_order", postgresql_where=text("title_id IS NOT NULL")),
        Index("ix_credits_season_kind_billing", "season_id", "kind", "billing_order", postgresql_where=text("season_id IS NOT NULL")),
        Index("ix_credits_episode_kind_billing", "episode_id", "kind", "billing_order", postgresql_where=text("episode_id IS NOT NULL")),

        # Useful lookups
        Index("ix_credits_person_role", "person_id", "role"),
        Index("ix_credits_person_kind", "person_id", "kind"),
        Index("ix_credits_created_at", "created_at"),
        Index("ix_credits_meta_gin", "meta", postgresql_using="gin"),
    )

    # Relationships
    person = relationship("Person", back_populates="credits", lazy="selectin", passive_deletes=True)
    title = relationship("Title", back_populates="credits", lazy="selectin", passive_deletes=True)
    season = relationship("Season", back_populates="credits", lazy="selectin", passive_deletes=True)
    episode = relationship("Episode", back_populates="credits", lazy="selectin", passive_deletes=True)

    def __repr__(self) -> str:  # pragma: no cover
        parent = "title" if self.title_id else ("season" if self.season_id else "episode")
        return (
            f"<Credit id={self.id} {parent}={(self.title_id or self.season_id or self.episode_id)} "
            f"person={self.person_id} role={self.role.value}>"
        )
