# tests/conftest.py
"""
Global test bootstrap
- Mounts a mock Redis client into app.core.redis_client
- Makes SlowAPI rate-limiting test-friendly (bypass by default)
- Keeps everything isolated per test run (namespace)
- Exposes a redis_client fixture + an opt-in ratelimit_on fixture
"""

from __future__ import annotations

import os
import random
import importlib
import pytest
import warnings
from sqlalchemy.exc import SAWarning

# ──────────────────────────────────────────────────────────────────────────────
# 🌱 Test env for rate limiting (fast, isolated, bypassed by default)
#   NOTE: These are set BEFORE importing your app/fixtures so they take effect.
# ──────────────────────────────────────────────────────────────────────────────
os.environ.setdefault("RATELIMIT_STORAGE_URI", "memory://")     # in-memory storage for tests
os.environ.setdefault("RATE_LIMIT_ENABLED", "true")             # keep middleware behavior
os.environ.setdefault("RATE_LIMIT_TEST_BYPASS", "1")            # bypass limits unless a test disables it
os.environ.setdefault("RATE_LIMIT_NAMESPACE", f"pytest-{random.getrandbits(32)}")  # isolate counters per run

# If your limiter reads env at import-time, reload it once here (after env set)
try:
    import app.core.limiter as _limiter  # type: ignore
    importlib.reload(_limiter)
except Exception:
    # If limiter imports later in app fixture, this is harmless.
    pass

# ──────────────────────────────────────────────────────────────────────────────
# 🧪 Install mock Redis globally before any tests run
# ──────────────────────────────────────────────────────────────────────────────
from app.core.redis_client import redis_wrapper
from tests.fixtures.mocks.redis import MockRedisClient
redis_wrapper._client = MockRedisClient()   # make the app use the mock client

# Silence relationship overlap SAWarnings from SQLAlchemy during tests
warnings.filterwarnings(
    "ignore",
    category=SAWarning,
    message=r".*conflicts with relationship\(s\):.*",
)

# ──────────────────────────────────────────────────────────────────────────────
# 📦 Pull in the rest of your fixtures (db, app, auth, etc.)
# ──────────────────────────────────────────────────────────────────────────────
from tests.fixtures.db import *          # noqa: F401,F403
from tests.fixtures.app import *         # noqa: F401,F403
from tests.fixtures.auth import *        # noqa: F401,F403
from tests.fixtures.users import *       # noqa: F401,F403
from tests.fixtures.utils import *       # noqa: F401,F403
from tests.fixtures.mocks.email import * # noqa: F401,F403


# ──────────────────────────────────────────────────────────────────────────────
# 🔌 Redis fixture (function-scoped), cleared between tests when supported
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture()
async def redis_client():
    """
    ✅ Use this when you want to inspect or modify Redis directly in a test.
    The mock client is function-scoped here; we clear keys if the mock supports it.
    """
    client = redis_wrapper.client
    # Best-effort pre-clean
    try:
        if hasattr(client, "flushall"):
            await client.flushall()
    except Exception:
        pass
    yield client
    # Best-effort post-clean
    try:
        if hasattr(client, "flushall"):
            await client.flushall()
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# 🚦 Opt-in fixture to actually enforce rate limits in a specific test
#    Usage:
#       def test_something_rate_limited(ratelimit_on, async_client): ...
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture()
def ratelimit_on(monkeypatch):
    """
    Temporarily enable rate limiting for tests that assert 429s. Resets afterward.
    """
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "0")
    try:
        import app.core.limiter as limiter  # type: ignore
        importlib.reload(limiter)           # if limiter reads env at import time
    except Exception:
        pass
    yield
    # restore bypass
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")
    try:
        import app.core.limiter as limiter  # type: ignore
        importlib.reload(limiter)
    except Exception:
        pass
