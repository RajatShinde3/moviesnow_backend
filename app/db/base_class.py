# app/db/base_class.py
from __future__ import annotations

"""
# MoviesNow — SQLAlchemy Base & Mixins

Production-grade SQLAlchemy 2.0 declarative **Base** with:
- Global **naming conventions** (Alembic-friendly)
- Automatic **snake_case `__tablename__`**
- Helpful `__repr__` for debugging/observability
- Common mixins:
  - `PKMixin` — BIGINT surrogate primary key
  - `TimestampMixin` — `created_at` / `updated_at` (UTC, server-side)
  - `SoftDeleteMixin` — `deleted_at` flag for soft deletes

Usage:
    from app.db.base_class import Base, PKMixin, TimestampMixin

    class Title(PKMixin, TimestampMixin, Base):
        name: Mapped[str] = mapped_column(String(255), unique=True, index=True)

Notes:
- Keep PK as BIGINT for hot paths & DB index perf; switch to UUID/ULID if required
  by your data model (provide a separate mixin in that case).
"""

from datetime import datetime
import re
from typing import Any

from sqlalchemy import BigInteger, DateTime, MetaData, func
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column

# ──────────────────────────────────────────────────────────────────────────────
# 🏷️ Naming conventions (stable constraint names for Alembic)
# ──────────────────────────────────────────────────────────────────────────────

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def _to_snake(name: str) -> str:
    """Convert `CamelCase` / `PascalCase` to `snake_case` for table names."""
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


# ──────────────────────────────────────────────────────────────────────────────
# 🧱 Declarative Base
# ──────────────────────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    """Global declarative base for MoviesNow models."""
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    @declared_attr.directive
    def __tablename__(cls) -> str:  # type: ignore[override]
        # Automatically use snake_case class name as table name
        return _to_snake(cls.__name__)

    def __repr__(self) -> str:  # pragma: no cover (repr convenience)
        # Compact repr: ModelName(id=?, fields…)
        attrs: list[str] = []
        # Show common fields when present
        for key in ("id", "name", "title_id", "asset_id"):
            if hasattr(self, key):
                try:
                    attrs.append(f"{key}={getattr(self, key)!r}")
                except Exception:
                    pass
        joined = ", ".join(attrs)
        return f"{self.__class__.__name__}({joined})"


# ──────────────────────────────────────────────────────────────────────────────
# 🧩 Common mixins
# ──────────────────────────────────────────────────────────────────────────────

class PKMixin:
    """Surrogate BIGINT primary key (auto-increment)."""
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)


class TimestampMixin:
    """
    Server-side timestamps (UTC).
    - `created_at`: set once at insert
    - `updated_at`: set at insert and auto-updated on change
    """
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class SoftDeleteMixin:
    """
    Soft-delete flag via timestamp.
    - `deleted_at` is NULL for active rows; set to UTC time to mark deleted.
    """
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None


__all__ = [
    "Base",
    "PKMixin",
    "TimestampMixin",
    "SoftDeleteMixin",
    "NAMING_CONVENTION",
]
