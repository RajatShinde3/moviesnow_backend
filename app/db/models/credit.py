# app/db/models/credit.py
from __future__ import annotations

"""
🎞️ MoviesNow — Credit Model (Cast & Crew)
=========================================

Associates a **Person** with a specific **Title**, **Season**, or **Episode** in a
well-typed, query-friendly way. Supports cast (actors/voice/guest/cameo) and crew
(director/writer/producer/etc.) with ordering and display metadata.

Design highlights
-----------------
- **Exactly one parent**: a credit belongs to a Title *or* Season *or* Episode
  (enforced via CHECK constraint).
- **Rich typing**: `kind` (cast/crew) + `role` (actor/director/…) + optional
  `department` and `job_title` for fine-grained crew taxonomy.
- **Cast metadata**: `character_name`, `billing_order`, and flags (voice/guest/cameo/uncredited).
- **Dedup protection**: partial unique indexes per parent level to prevent
  duplicate rows for the same (parent, person, role, character/job) tuple.
- **Search/ordering index**: efficient listing by parent + kind + billing_order.
- **Timestamps**: DB-driven UTC `created_at`/`updated_at`.

Relationships
-------------
- `person`    → Person (required)
- `title`     → Title (nullable; one-of parent)
- `season`    → Season (nullable; one-of parent)
- `episode`   → Episode (nullable; one-of parent)

Back-references (define on their models)
----------------------------------------
- Title.credits   = relationship("Credit", back_populates="title", cascade="all, delete-orphan", lazy="selectin")
- Season.credits  = relationship("Credit", back_populates="season", cascade="all, delete-orphan", lazy="selectin")
- Episode.credits = relationship("Credit", back_populates="episode", cascade="all, delete-orphan", lazy="selectin")
- Person.credits  = relationship("Credit", back_populates="person", cascade="all, delete-orphan", lazy="selectin")
"""

from uuid import uuid4
from enum import Enum

from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    CheckConstraint,
    Index,
    Enum as SAEnum,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.base_class import Base


class CreditKind(str, Enum):
    """Top-level credit category."""
    CAST = "cast"
    CREW = "crew"


class CreditRole(str, Enum):
    """
    Common credit roles. Keep this pragmatic—expand as catalog grows.
    (We keep both `kind` and `role`: e.g., kind=CAST role=ACTOR, kind=CREW role=DIRECTOR)
    """
    ACTOR = "actor"
    VOICE = "voice"
    GUEST_STAR = "guest_star"
    CAMEO = "cameo"

    DIRECTOR = "director"
    WRITER = "writer"
    PRODUCER = "producer"
    EXECUTIVE_PRODUCER = "executive_producer"
    SHOWRUNNER = "showrunner"
    CREATOR = "creator"
    COMPOSER = "composer"
    EDITOR = "editor"
    CINEMATOGRAPHER = "cinematographer"
    COSTUME_DESIGNER = "costume_designer"
    VFX_SUPERVISOR = "vfx_supervisor"
    SOUND_MIXER = "sound_mixer"
    MUSIC_SUPERVISOR = "music_supervisor"
    STUNT_COORDINATOR = "stunt_coordinator"
    OTHER = "other"


class Credit(Base):
    """
    A single credit linking a person to a title/season/episode with role metadata.

    Notes
    -----
    - Exactly one of (`title_id`, `season_id`, `episode_id`) must be non-NULL.
    - Use `billing_order` to sort cast lists. Crew typically sorts by `role` then name.
    - Use `credited_as` to preserve on-screen credit strings differing from Person.primary_name.
    """

    __tablename__ = "credits"

    # ─────────────── Identity ───────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4, index=True)

    # ─────────────── Parent (exactly one) ───────────────
    title_id = Column(UUID(as_uuid=True), ForeignKey("titles.id", ondelete="CASCADE"), nullable=True, index=True)
    season_id = Column(UUID(as_uuid=True), ForeignKey("seasons.id", ondelete="CASCADE"), nullable=True, index=True)
    episode_id = Column(UUID(as_uuid=True), ForeignKey("episodes.id", ondelete="CASCADE"), nullable=True, index=True)

    # ─────────────── Person ───────────────
    person_id = Column(UUID(as_uuid=True), ForeignKey("people.id", ondelete="CASCADE"), nullable=False, index=True)

    # ─────────────── Taxonomy ───────────────
    kind = Column(SAEnum(CreditKind, name="credit_kind"), nullable=False)
    role = Column(SAEnum(CreditRole, name="credit_role"), nullable=False)

    # Crew typing (optional, useful for BI and UI grouping)
    department = Column(String(128), nullable=True, doc="High-level department (e.g., 'Directing', 'Writing').")
    job_title = Column(String(128), nullable=True, doc="Display job title (e.g., 'Executive Producer').")

    # Cast metadata
    character_name = Column(String(256), nullable=True)
    billing_order = Column(Integer, nullable=True, index=True, doc="Lower = earlier in billing; cast lists sort by this.")

    # Display overrides
    credited_as = Column(String(256), nullable=True, doc="On-screen credited name (if different from person name).")

    # Flags
    is_uncredited = Column(Boolean, nullable=False, server_default=text("false"))
    is_voice = Column(Boolean, nullable=False, server_default=text("false"))
    is_guest = Column(Boolean, nullable=False, server_default=text("false"))
    is_cameo = Column(Boolean, nullable=False, server_default=text("false"))

    # Aggregates (optional, handy for season/series-level credits)
    episode_count = Column(Integer, nullable=True, doc="For season/title credits: episodes this credit spans.")

    # Extra vendor/ingest metadata
    meta = Column(JSONB, nullable=True)

    # Audit
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __mapper_args__ = {"eager_defaults": True}

    # ─────────────── Constraints & Indexes ───────────────
    __table_args__ = (
        # Exactly one parent is set
        CheckConstraint(
            "(CASE WHEN title_id  IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN season_id IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN episode_id IS NOT NULL THEN 1 ELSE 0 END) = 1",
            name="ck_credit_exactly_one_parent",
        ),
        # Temporal sanity
        CheckConstraint("updated_at >= created_at", name="ck_credits_updated_after_created"),

        # Prevent duplicate credits for the same parent/person/role/character/job
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
    )

    # ─────────────── Relationships ───────────────
    person = relationship("Person", back_populates="credits", lazy="selectin")

    title = relationship("Title", back_populates="credits", lazy="selectin")
    season = relationship("Season", back_populates="credits", lazy="selectin")
    episode = relationship("Episode", back_populates="credits", lazy="selectin")

    def __repr__(self) -> str:  # pragma: no cover
        parent = "title" if self.title_id else "season" if self.season_id else "episode"
        return f"<Credit id={self.id} {parent}={(self.title_id or self.season_id or self.episode_id)} person={self.person_id} role={self.role.value}>"
