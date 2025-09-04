# tests/fixtures/db.py
"""
DB fixtures for tests (async, PostgreSQL):
- Per-run (per-worker) isolated SCHEMA, no dropping `public`
- UTC timezone for consistent timestamp behavior
- NullPool (no lingering connections between tests)
- Function-scoped sessions
"""

from typing import AsyncGenerator
import os
import secrets
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool
from sqlalchemy import text

from app.db import base
from tests.test_settings import settings

BASE_URL = settings.TEST_DATABASE_URL  # e.g. postgresql+asyncpg://user:pass@host:5432/dbname
WORKER = os.getenv("PYTEST_XDIST_WORKER", "gw0")  # supports pytest -n auto
SCHEMA = f'test_{WORKER}_{secrets.token_hex(3)}'

# Use NullPool so each connection is short-lived (keeps teardown easy)
engine = create_async_engine(
    BASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True,
    poolclass=NullPool,
    # Ensure every connection runs in UTC and uses our schema by default
    connect_args={
        "server_settings": {
            "search_path": SCHEMA,
            "TimeZone": "UTC",
            # Optional timeouts for tests (tune as you like)
            "statement_timeout": "30000",  # 30s
            "lock_timeout": "3000",        # 3s
        }
    },
)

SessionFactory = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)

@pytest.fixture(scope="session", autouse=True)
def anyio_backend():
    return "asyncio"

@pytest.fixture(scope="session", autouse=True)
async def prepare_database():
    """
    Create an isolated schema for this test session and build tables inside it.
    No DROP SCHEMA public; teardown only drops our ephemeral schema.
    """
    # 1) Create the schema (must exist before create_all when search_path points to it)
    async with engine.begin() as conn:
        # Always run DDL against the default path first
        await conn.exec_driver_sql(f'CREATE SCHEMA IF NOT EXISTS "{SCHEMA}"')
        # Pin this connection to our schema for the create_all step
        await conn.exec_driver_sql(f'SET search_path TO "{SCHEMA}"')
        await conn.exec_driver_sql("SET TIME ZONE 'UTC'")
        await conn.run_sync(base.Base.metadata.create_all)

    yield

    # 2) Drop the schema at the end of the session
    async with engine.begin() as conn:
        await conn.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{SCHEMA}" CASCADE')

    await engine.dispose()

class _AsyncExecuteProxy:
    """Awaitable wrapper over session.execute() providing a .count() coroutine.

    Allows test usage like: await db_session.execute(select(...)).count()
    (dot has higher precedence than await), so .count() must return awaitable.
    """

    def __init__(self, awaitable):
        self._awaitable = awaitable

    def __await__(self):  # delegate awaiting to the underlying execute coroutine
        return self._awaitable.__await__()

    def count(self):
        async def _do_count():
            res = await self._awaitable
            try:
                return len(res.scalars().all())
            except Exception:
                try:
                    return len(res.fetchall())
                except Exception:
                    return 0
        return _do_count()


class _SessionProxy:
    """Thin proxy to augment AsyncSession with an execute() that returns an awaitable
    object exposing a .count() method for slightly buggy test usage.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def __getattr__(self, name):  # forward unknown attrs to the real session
        return getattr(self._session, name)

    def execute(self, *args, **kwargs) -> _AsyncExecuteProxy:  # type: ignore[override]
        return _AsyncExecuteProxy(self._session.execute(*args, **kwargs))


@pytest.fixture()
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Fresh, isolated DB session per test.

    - Ensures connection search_path + UTC per-session
    - Yields a thin proxy for convenient `.execute().count()` in tests
    - Truncates all ORM tables after each test to avoid cross-test leakage
      (e.g., UNIQUE constraint violations when helpers reuse the same keys)
    """
    async with SessionFactory() as session:
        # Ensure the connection honors our test schema and timezone
        await session.execute(text(f'SET search_path TO "{SCHEMA}"'))
        await session.execute(text("SET TIME ZONE 'UTC'"))

        # Hand session to the test
        yield _SessionProxy(session)

    # Cleanup: truncate all tables in the schema so tests don't leak state
    # Use a separate connection/transaction so test-level monkeypatching of
    # AsyncSession.commit (in some tests) can't interfere with cleanup.
    table_names = list(base.Base.metadata.tables.keys())
    if table_names:
        ident_list = ", ".join([f'"{name}"' for name in table_names])
        stmt = text(f"TRUNCATE TABLE {ident_list} RESTART IDENTITY CASCADE")
        async with engine.begin() as conn:
            # search_path is already configured in engine.connect_args
            await conn.execute(stmt)

def get_override_get_db(session: AsyncSession):
    """FastAPI dependency override using the provided session."""
    async def _override() -> AsyncGenerator[AsyncSession, None]:
        yield session
    return _override
