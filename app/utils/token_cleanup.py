# app/tasks/token_cleanup.py
from __future__ import annotations

"""
MoviesNow — refresh-token cleanup (minimal)
-------------------------------------------
- Async purge of expired and old-revoked refresh tokens
- Single-node/replica-safe via Redis distributed lock
- ENV-tunable retention windows
"""

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import delete, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.token import RefreshToken
from app.db.session import async_session_maker
from app.core.redis_client import redis_wrapper

logger = logging.getLogger("token-cleanup")

# ─────────────────────────────────────────────
# ⚙️ Config (ENV overrides)
# ─────────────────────────────────────────────
@dataclass(frozen=True)
class CleanupConfig:
    retention_expired_days: int = int(os.getenv("TOKEN_CLEANUP_RETENTION_EXPIRED_DAYS", "1"))
    retention_revoked_days: int = int(os.getenv("TOKEN_CLEANUP_RETENTION_REVOKED_DAYS", "7"))
    lock_ttl_seconds: int = int(os.getenv("TOKEN_CLEANUP_LOCK_TTL_SECONDS", "300"))  # 5 min default

_CFG = CleanupConfig()
_LOCK_KEY = "maintenance:token-cleanup:lock"

# ─────────────────────────────────────────────
# 🧮 Execute DELETE with RETURNING (fallback-safe)
# ─────────────────────────────────────────────
async def _execute_delete(session: AsyncSession, stmt) -> int:
    """
    Try DELETE ... RETURNING for accurate counts; fall back to rowcount.
    """
    try:
        stmt = stmt.returning(RefreshToken.id)
        rows = (await session.execute(stmt)).scalars().all()
        await session.commit()
        return len(rows)
    except Exception:
        await session.rollback()
        result = await session.execute(stmt)
        await session.commit()
        return int(getattr(result, "rowcount", 0) or 0)

# ─────────────────────────────────────────────
# 🧹 Public task
# ─────────────────────────────────────────────
async def delete_expired_or_revoked_tokens() -> None:
    """
    Purge tokens that are:
      • expired before now - retention_expired_days
      • revoked with created_at before now - retention_revoked_days
    Wrapped in a Redis lock so only one worker runs at a time.
    """
    # Acquire a safe distributed lock
    async with redis_wrapper.lock(_LOCK_KEY, timeout=_CFG.lock_ttl_seconds, blocking_timeout=2):
        now = datetime.now(timezone.utc)
        expired_cutoff = now - timedelta(days=_CFG.retention_expired_days)
        revoked_cutoff = now - timedelta(days=_CFG.retention_revoked_days)

        async with async_session_maker() as db:
            # 1) Expired long enough ago
            deleted_expired = await _execute_delete(
                db,
                delete(RefreshToken).where(RefreshToken.expires_at < expired_cutoff),
            )

            # 2) Revoked and old enough (use created_at as the conservative cutoff)
            deleted_revoked = await _execute_delete(
                db,
                delete(RefreshToken).where(
                    and_(
                        RefreshToken.is_revoked.is_(True),
                        RefreshToken.created_at < revoked_cutoff,
                    )
                ),
            )

        total = deleted_expired + deleted_revoked
        if total:
            logger.info(
                "Token cleanup: purged=%s (expired=%s, revoked=%s) | cutoffs(expired<%s, revoked<%s)",
                total, deleted_expired, deleted_revoked,
                expired_cutoff.isoformat(), revoked_cutoff.isoformat(),
            )
        else:
            logger.debug("Token cleanup: nothing to purge")

# ─────────────────────────────────────────────
# ⏰ Optional: start scheduler (only if APScheduler is installed)
# ─────────────────────────────────────────────
def start_token_cleanup_scheduler(
    *,
    interval_minutes: Optional[int] = None,
    jitter_seconds: int = int(os.getenv("TOKEN_CLEANUP_JITTER_SECONDS", "15")),
) -> None:
    """
    Start a lightweight APScheduler job if the dependency is available.
    Safe no-op if APScheduler isn't installed.

    Args:
        interval_minutes: override interval; defaults to ENV TOKEN_CLEANUP_INTERVAL_MINUTES or 60.
        jitter_seconds: small randomization to avoid thundering herd.
    """
    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from apscheduler.triggers.interval import IntervalTrigger
    except Exception:
        logger.warning("APScheduler not available; token cleanup scheduler not started")
        return

    minutes = int(
        interval_minutes if interval_minutes is not None
        else os.getenv("TOKEN_CLEANUP_INTERVAL_MINUTES", "60")
    )

    scheduler = AsyncIOScheduler(timezone=timezone.utc)
    scheduler.add_job(
        delete_expired_or_revoked_tokens,
        IntervalTrigger(minutes=minutes, jitter=jitter_seconds, timezone=timezone.utc),
        id="token_cleanup",
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    logger.info("Token cleanup scheduler started | interval=%sm, jitter=%ss", minutes, jitter_seconds)
