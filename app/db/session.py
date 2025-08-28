# app/db/session.py
from __future__ import annotations

"""
# MoviesNow — Database Engines & Session Dependencies

Production-grade SQLAlchemy 2.0 setup with **sync** and **async** engines:

- **Sync engine** (`engine`) for Alembic, CLI scripts, one-off jobs.
- **Async engine** (`async_engine`) for FastAPI and background tasks.
- Session factories: `SessionLocal` (sync) and `async_session_maker` (async).
- FastAPI dependencies: `get_db()` and `get_async_db()` with **safe rollback**.
- Utilities:
  - `transactional_async_session()` — async context manager for `session.begin()`.
  - `db_healthcheck()` — quick `SELECT 1` for readiness probes.
  - URL derivation if `ASYNC_DATABASE_URL` isn’t set.

Design notes
------------
- **Expire on commit** disabled to keep objects usable after commit.
- **Pool** settings tuned for API workloads; adjust via env if needed.
- We **don’t** auto-commit in dependencies; callers decide when to commit.
"""

from typing import AsyncGenerator, Generator, Optional
import logging
from contextlib import asynccontextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)

from app.core.config import settings

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# 🔧 Helpers
# ─────────────────────────────────────────────────────────────

def _derive_async_url(sync_url: str) -> str:
    """
    Convert a sync Postgres URL to an asyncpg URL if needed.

    Examples:
        postgresql://user:pass@host/db  -> postgresql+asyncpg://user:pass@host/db
        (returns input unchanged if already async)
    """
    if "+asyncpg" in sync_url or "postgresql+asyncpg" in sync_url:
        return sync_url
    if sync_url.startswith("postgresql://"):
        return sync_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    # Add other RDBMS mappings as required (e.g., MySQL async driver)
    return sync_url


# Resolve URLs with sane fallbacks
SYNC_DATABASE_URL: str = getattr(settings, "DATABASE_URL")
ASYNC_DATABASE_URL: str = getattr(settings, "ASYNC_DATABASE_URL", "") or _derive_async_url(SYNC_DATABASE_URL)


# Pool tuning knobs (adjust per environment if needed)
_POOL_PRE_PING = True
_POOL_RECYCLE = 1800     # seconds
_POOL_TIMEOUT = 30       # seconds
_POOL_SIZE = 10          # base worker pool
_MAX_OVERFLOW = 20       # bursty traffic headroom


# ─────────────────────────────────────────────────────────────
# 🧱 SYNC ENGINE — For Alembic Migrations, CLI Scripts
# ─────────────────────────────────────────────────────────────

engine = create_engine(
    SYNC_DATABASE_URL,
    pool_pre_ping=_POOL_PRE_PING,
    pool_recycle=_POOL_RECYCLE,
    pool_size=_POOL_SIZE,
    max_overflow=_MAX_OVERFLOW,
    pool_timeout=_POOL_TIMEOUT,
    future=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a **sync** SQLAlchemy session.

    Yields:
        Session: A SQLAlchemy ORM session.

    Guarantees:
        - Closes the session after request.
        - Rolls back on exceptions to avoid leaking open transactions.
    """
    db = SessionLocal()
    try:
        yield db
        # Caller decides to commit; many CLI/migration contexts handle their own tx
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ─────────────────────────────────────────────────────────────
# ⚡ ASYNC ENGINE — For FastAPI and Async Workloads
# ─────────────────────────────────────────────────────────────

async_engine: AsyncEngine = create_async_engine(
    ASYNC_DATABASE_URL,
    pool_pre_ping=_POOL_PRE_PING,
    pool_recycle=_POOL_RECYCLE,
    pool_size=_POOL_SIZE,
    max_overflow=_MAX_OVERFLOW,
    pool_timeout=_POOL_TIMEOUT,
    echo=False,  # flip to True temporarily for debugging SQL
    future=True,
)

async_session_maker = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields an **async** SQLAlchemy session.

    Yields:
        AsyncSession: An async ORM session.

    Guarantees:
        - Closes the session after request.
        - Rolls back on exceptions to avoid leaking open transactions.

    Usage:
        async def route(db: AsyncSession = Depends(get_async_db)):
            ...
    """
    async with async_session_maker() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def transactional_async_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager that opens a session and a transaction.

    Example:
        async with transactional_async_session() as session:
            session.add(obj)
            # commits when block exits; rolls back on exception
    """
    async with async_session_maker() as session:
        async with session.begin():
            try:
                yield session
            except Exception:
                # session.begin() will roll back automatically on exception
                raise


async def db_healthcheck() -> bool:
    """
    Quick `SELECT 1` to verify DB connectivity (used by `/readyz`).

    Returns:
        bool: True when a round-trip query succeeds.
    """
    try:
        async with async_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        logger.exception("DB healthcheck failed")
        return False


__all__ = [
    "engine",
    "SessionLocal",
    "get_db",
    "async_engine",
    "async_session_maker",
    "get_async_db",
    "transactional_async_session",
    "db_healthcheck",
]
