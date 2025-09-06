from __future__ import annotations

"""
Dedicated maintenance worker for background schedulers.

Responsibilities:
- Token cleanup (expired/revoked refresh tokens) via APScheduler
- JWKS rotate/prune jobs via APScheduler

Env toggles:
  TOKEN_CLEANUP_SCHEDULER=true|false (default true)
  JWKS_SCHEDULER=true|false (default true)

Run:
  python scripts/worker.py
"""

import asyncio
import logging
import os


def _truthy(name: str, default: str = "true") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def setup_jobs() -> None:
    try:
        if _truthy("TOKEN_CLEANUP_SCHEDULER", "true"):
            from app.utils.token_cleanup import start_token_cleanup_scheduler  # type: ignore

            start_token_cleanup_scheduler()
    except Exception:
        logging.getLogger("worker").exception("Token cleanup scheduler failed to start")

    try:
        if _truthy("JWKS_SCHEDULER", "true"):
            from app.utils.jwks_rotation import start_jwks_scheduler  # type: ignore

            start_jwks_scheduler()
    except Exception:
        logging.getLogger("worker").exception("JWKS scheduler failed to start")


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    setup_jobs()

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.stop()
        loop.close()


if __name__ == "__main__":
    main()

