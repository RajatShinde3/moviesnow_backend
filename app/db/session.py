# app/db/session.py
from __future__ import annotations

"""
MoviesNow — Database Engines & Session Dependencies

- Async engine/session for FastAPI & tests.
- Sync engine/session are created lazily (only when used), so importing this
  module won't crash if psycopg2 isn't installed in test envs.
"""

from typing import AsyncGenerator, Generator, Optional
import logging
from contextlib import asynccontextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)

from app.core.config import settings

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _derive_async_url(sync_url: str) -> str:
    """Convert a sync Postgres URL to an asyncpg URL if needed."""
    if "+asyncpg" in sync_url or "postgresql+asyncpg" in sync_url:
        return sync_url
    if sync_url.startswith("postgresql://"):
        return sync_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return sync_url

# Resolve URLs
SYNC_DATABASE_URL: str = getattr(settings, "DATABASE_URL")
ASYNC_DATABASE_URL: str = getattr(settings, "ASYNC_DATABASE_URL", "") or _derive_async_url(SYNC_DATABASE_URL)

# Pool knobs
_POOL_PRE_PING = True
_POOL_RECYCLE = 1800
_POOL_TIMEOUT = 30
_POOL_SIZE = 10
_MAX_OVERFLOW = 20

# ─────────────────────────────────────────────────────────────
# ⚡ ASYNC ENGINE — used by app & tests
# ─────────────────────────────────────────────────────────────

async_engine: AsyncEngine = create_async_engine(
    ASYNC_DATABASE_URL,
    pool_pre_ping=_POOL_PRE_PING,
    pool_recycle=_POOL_RECYCLE,
    pool_size=_POOL_SIZE,
    max_overflow=_MAX_OVERFLOW,
    pool_timeout=_POOL_TIMEOUT,
    echo=False,
    future=True,
)

async_session_maker = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async SQLAlchemy session."""
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
    """Async context manager that opens a session and a transaction."""
    async with async_session_maker() as session:
        async with session.begin():
            try:
                yield session
            except Exception:
                raise  # rollback handled by session.begin()

async def db_healthcheck() -> bool:
    """Quick SELECT 1 to verify DB connectivity (used by /readyz)."""
    try:
        async with async_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        logger.exception("DB healthcheck failed")
        return False

# ─────────────────────────────────────────────────────────────
# 🧱 SYNC ENGINE — created lazily (avoids psycopg2 import on import)
# ─────────────────────────────────────────────────────────────

_engine: Optional[Engine] = None
_SessionLocal: Optional[sessionmaker] = None

def get_sync_engine() -> Engine:
    """Create the sync engine on first use (requires psycopg2 or psycopg)."""
    global _engine
    if _engine is None:
        _engine = create_engine(
            SYNC_DATABASE_URL,
            pool_pre_ping=_POOL_PRE_PING,
            pool_recycle=_POOL_RECYCLE,
            pool_size=_POOL_SIZE,
            max_overflow=_MAX_OVERFLOW,
            pool_timeout=_POOL_TIMEOUT,
            future=True,
        )
    return _engine

def get_session_local() -> sessionmaker:
    """Create the sync session factory on first use."""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            bind=get_sync_engine(),
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
        )
    return _SessionLocal

def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a sync SQLAlchemy session.

    NOTE: This initializes the sync engine on first call. If you don't need
    sync DB access (e.g., in tests), don't call this and psycopg2 isn't needed.
    """
    SessionLocal = get_session_local()
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

__all__ = [
    # async
    "async_engine",
    "async_session_maker",
    "get_async_db",
    "transactional_async_session",
    "db_healthcheck",
    # sync (lazy)
    "get_sync_engine",
    "get_session_local",
    "get_db",
]
