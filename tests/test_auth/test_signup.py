# tests/test_auth/test_signup.py

import pytest
from httpx import AsyncClient
from fastapi import status
from unittest.mock import AsyncMock, patch
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from tests.utils.factory import make_email
from app.db.models import RefreshToken, User


def _dump_resp(resp, label=""):
    try:
        body = resp.json()
    except Exception:
        body = resp.text
    print(
        f"\n[SIGNUP-TEST]{' '+label if label else ''} "
        f"status={resp.status_code} "
        f"cache_control={resp.headers.get('Cache-Control')} "
        f"ratelimit={resp.headers.get('X-RateLimit-Limit')} "
        f"remaining={resp.headers.get('X-RateLimit-Remaining')} "
        f"retry_after={resp.headers.get('Retry-After')} "
        f"body={body}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# ✅ Happy path — returns tokens, queues email, sets no-store cache headers
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_successful_signup(async_client: AsyncClient, db_session: AsyncSession):
    email = make_email("user1")
    payload = {"email": email, "password": "Test@12345", "full_name": "User One"}

    with patch(
        "app.services.auth.signup_service.send_verification_email",
        new_callable=AsyncMock,
    ) as mocked_send:
        resp = await async_client.post(
            "/api/v1/auth/signup",
            json=payload,
            headers={"X-Forwarded-For": "10.0.0.201"},  # keep route-level limiter happy
        )

    _dump_resp(resp, "successful_signup")

    assert resp.status_code == status.HTTP_201_CREATED, f"{resp.status_code} {resp.text}"

    data = resp.json()
    print("[SIGNUP-TEST] received keys:", list(data.keys()))
    assert data["token_type"] == "bearer"
    assert "access_token" in data and "refresh_token" in data

    # Background email was queued (robust across runners)
    print("[SIGNUP-TEST] mocked_send.await_count:", getattr(mocked_send, "await_count", None))
    if hasattr(mocked_send, "assert_awaited_once"):
        mocked_send.assert_awaited_once()
    else:
        assert mocked_send.called, "Verification email task was not queued"

    # Security headers
    cache_control = resp.headers.get("Cache-Control", "")
    print("[SIGNUP-TEST] cache-control:", cache_control)
    assert "no-store" in cache_control.lower(), "Token responses must not be cacheable"

    # Refresh token persisted in DB
    user = (await db_session.execute(select(User).where(User.email == email))).scalar_one()
    rows = (
        await db_session.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == user.id,
                RefreshToken.is_revoked == False,  # noqa: E712
            )
        )
    ).fetchall()
    print("[SIGNUP-TEST] refresh tokens in DB for user:", len(rows))
    assert len(rows) == 1


# ──────────────────────────────────────────────────────────────────────────────
# ❌ Duplicate email — 400 with precise message
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_signup_duplicate_email(async_client: AsyncClient, create_test_user):
    email = make_email("dupeuser")
    await create_test_user(email=email)

    payload = {"email": email, "password": "AnotherStrongPass123!", "full_name": "Duplicate User"}
    resp = await async_client.post(
        "/api/v1/auth/signup",
        json=payload,
        headers={"X-Forwarded-For": "10.0.0.202"},
    )

    _dump_resp(resp, "duplicate_email")

    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["detail"] == "Email already registered"


# ──────────────────────────────────────────────────────────────────────────────
# ❌ Invalid email format — 400
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_signup_invalid_email_format(async_client: AsyncClient):
    payload = {"email": "not-an-email@", "password": "Test@12345", "full_name": "Bad Email"}
    resp = await async_client.post(
        "/api/v1/auth/signup",
        json=payload,
        headers={"X-Forwarded-For": "10.0.0.203"},
    )

    _dump_resp(resp, "invalid_email")

    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["detail"] == "Invalid email format"


# ──────────────────────────────────────────────────────────────────────────────
# 🔁 Idempotency-Key — second identical request returns cached first response
#    (instead of 400 duplicate)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_signup_idempotency_returns_same_tokens(async_client: AsyncClient, db_session: AsyncSession):
    email = make_email("idem")
    payload = {"email": email, "password": "Test@12345", "full_name": "Idem User"}
    idem_key = "test-idem-key-001"
    headers = {"Idempotency-Key": idem_key, "X-Forwarded-For": "10.0.0.204"}

    # First call creates user and stores snapshot
    r1 = await async_client.post("/api/v1/auth/signup", json=payload, headers=headers)
    _dump_resp(r1, "idempotency_first")
    assert r1.status_code == status.HTTP_201_CREATED, r1.text
    body1 = r1.json()
    print("[SIGNUP-TEST] first access token startswith:", str(body1.get("access_token", ""))[:12])

    # Second call with the same key should return the same token payload (from cache)
    r2 = await async_client.post("/api/v1/auth/signup", json=payload, headers=headers)
    _dump_resp(r2, "idempotency_second")
    assert r2.status_code == status.HTTP_201_CREATED, r2.text
    body2 = r2.json()
    print("[SIGNUP-TEST] second access token startswith:", str(body2.get("access_token", ""))[:12])

    assert body1 == body2, "Idempotent second call must return cached first response"

    # Ensure we still have only one refresh token row for this user in DB
    user = (await db_session.execute(select(User).where(User.email == email))).scalar_one()
    rows = (await db_session.execute(select(RefreshToken).where(RefreshToken.user_id == user.id))).fetchall()
    print("[SIGNUP-TEST] refresh tokens in DB after idempotent second call:", len(rows))
    assert len(rows) == 1


# ──────────────────────────────────────────────────────────────────────────────
# 🚦 Per-route rate limit — 11th request from the same IP is rejected
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_signup_route_rate_limited(async_client: AsyncClient):
    base_headers = {"X-Forwarded-For": "10.0.0.205"}  # same IP to hit the route limit
    # limit is 10/minute (see @rate_limit("10/minute"))
    last_status = None

    for i in range(11):
        payload = {"email": make_email(f"rl-{i}"), "password": "Test@12345", "full_name": f"RL {i}"}
        resp = await async_client.post("/api/v1/auth/signup", json=payload, headers=base_headers)
        print(f"[SIGNUP-TEST] rate-limit attempt={i+1} status={resp.status_code} "
              f"remaining={resp.headers.get('X-RateLimit-Remaining')}")
        last_status = resp.status_code

    # 11th should be 429
    assert last_status == status.HTTP_429_TOO_MANY_REQUESTS
