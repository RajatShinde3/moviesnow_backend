
import pytest
from app.utils.redis_utils import no_op_rate_limiter
from app.api.v1.routes.orgs.org_member import search_rate_limit_dep
from app.main import app

@pytest.fixture(autouse=True)
def disable_rate_limiting_for_tests():
    """
    ✅ Globally disable rate limiting in all tests unless explicitly overridden.
    """
    app.dependency_overrides[search_rate_limit_dep] = no_op_rate_limiter
    yield
    app.dependency_overrides.pop(search_rate_limit_dep, None)