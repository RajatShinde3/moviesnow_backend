from __future__ import annotations

"""
JWKS rotation/prune scheduler (optional)
---------------------------------------
Starts lightweight APScheduler jobs to rotate active JWKS keys and prune
retired ones on a configurable cadence. Safe no-op if APScheduler is absent.
"""

import logging
import os
from typing import Optional
from datetime import timezone

from app.services.jwks_service import rotate_key, prune_retired

logger = logging.getLogger("jwks-rotation")


def start_jwks_scheduler(
    *,
    rotate_hours: Optional[int] = None,
    prune_hours: Optional[int] = None,
) -> None:
    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from apscheduler.triggers.interval import IntervalTrigger
    except Exception:
        logger.warning("APScheduler not available; JWKS scheduler not started")
        return

    rot_h = int(rotate_hours if rotate_hours is not None else os.getenv("JWKS_ROTATE_INTERVAL_HOURS", "168"))  # 7d
    prn_h = int(prune_hours if prune_hours is not None else os.getenv("JWKS_PRUNE_INTERVAL_HOURS", "24"))       # 1d

    sched = AsyncIOScheduler(timezone=timezone.utc)

    async def _rotate():
        try:
            info = await rotate_key()
            logger.info("JWKS rotated | kid=%s alg=%s", info.get("kid"), info.get("public_jwk", {}).get("alg"))
        except Exception as e:
            logger.warning("JWKS rotate failed: %s", e)

    async def _prune():
        try:
            removed = await prune_retired()
            if removed:
                logger.info("JWKS pruned | removed=%s", removed)
        except Exception as e:
            logger.warning("JWKS prune failed: %s", e)

    sched.add_job(_rotate, IntervalTrigger(hours=rot_h, timezone=timezone.utc), id="jwks_rotate", max_instances=1, coalesce=True)
    sched.add_job(_prune, IntervalTrigger(hours=prn_h, timezone=timezone.utc), id="jwks_prune", max_instances=1, coalesce=True)
    sched.start()
    logger.info("JWKS scheduler started | rotate=%sh, prune=%sh", rot_h, prn_h)

