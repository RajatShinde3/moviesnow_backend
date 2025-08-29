# tests/conftest.py

# 🚨 Load mock Redis before any tests run
from app.core.redis_client import redis_wrapper
from tests.fixtures.mocks.redis import MockRedisClient
redis_wrapper._client = MockRedisClient()  

# 🔧 Import all fixtures
from tests.fixtures.db import *
from tests.fixtures.app import *
from tests.fixtures.auth import *
from tests.fixtures.users import *
from tests.fixtures.utils import *
from tests.fixtures.mocks.email import *
import pytest

@pytest.fixture()
async def redis_client():
    """
    ✅ Fixture: Provides the mock Redis client for use in tests.

    Use this if you want to inspect or modify Redis values directly.
    """
    yield redis_wrapper.client
