import uuid
import pytest
from httpx import AsyncClient
from fastapi import Request
from app.utils.redis_utils import rate_limiter
from app.main import app
from app.schemas.enums import OrgRole
from app.schemas.organization import OrgMemberSearchRequest
from app.api.v1.routes.orgs.org_member import search_rate_limit_dep


@pytest.mark.anyio
async def test_search_rate_limited(async_client: AsyncClient, user_with_org, redis_client):
    """
    🔐 Ensure the /search endpoint is rate limited to 5 requests per 10 seconds
    for the same user.
    """
    # 👤 Setup test user
    user, token = await user_with_org(role=OrgRole.ADMIN)
    headers = {"Authorization": f"Bearer {token}"}

    # 🗝️ Create a stable Redis key for this test user
    redis_key = f"ratelimit-test:user:{user.id}"

    def per_user_key(_: Request):
        return redis_key

    # ✅ PLACE THIS HERE:
    app.dependency_overrides[search_rate_limit_dep] = rate_limiter(
        per_user_key, seconds=10, max_calls=5
    )

    try:
        payload = OrgMemberSearchRequest(query="test").model_dump()
        print("\n🚀 Simulating rate-limited /search requests")

        for i in range(6):
            response = await async_client.post("api/v1/org/member/search", json=payload, headers=headers)
            print(f"🔁 Request {i+1} → Status: {response.status_code}")
            if i < 5:
                assert response.status_code == 200
            else:
                assert response.status_code == 429
    finally:
        # 🧹 Cleanup Redis state after test
        await redis_client.delete(redis_key)
        app.dependency_overrides.pop(search_rate_limit_dep, None)
