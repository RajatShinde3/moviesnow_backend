import asyncio
import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

# ───────────────────────────────────────────────
# 📁 Ensure app modules are importable
# ───────────────────────────────────────────────
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.base import Base  # Your SQLAlchemy declarative base
from app.core.config import settings  # Loads environment-based settings

# ───────────────────────────────────────────────
# 📦 Alembic Config
# ───────────────────────────────────────────────
config = context.config

# Choose correct database (test or dev)
DATABASE_URL = (
    settings.TEST_DATABASE_URL
    if os.getenv("USE_TEST_DB") == "1"
    else settings.ASYNC_DATABASE_URL
)

# Ensure Alembic config has the URL (helps tools & offline mode)
if config.config_ini_section:
    config.set_main_option("sqlalchemy.url", DATABASE_URL)

# Configure Alembic logging
if config.config_file_name:
    fileConfig(config.config_file_name)

# For autogeneration
target_metadata = Base.metadata


# ───────────────────────────────────────────────
# 📴 Offline Migrations (generates SQL script)
# ───────────────────────────────────────────────
def run_migrations_offline() -> None:
    """Run Alembic migrations without connecting to the database."""
    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


# ───────────────────────────────────────────────
# 🌐 Online Migrations (live DB migrations)
# ───────────────────────────────────────────────
def do_run_migrations(connection):
    """Actual logic to run migrations with the given DB connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run Alembic migrations with an async SQLAlchemy engine."""
    connectable = create_async_engine(
        DATABASE_URL,
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


# ───────────────────────────────────────────────
# 🚀 Entrypoint
# ───────────────────────────────────────────────
if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
