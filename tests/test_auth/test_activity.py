# tests/test_auth/test_activity.py
from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from typing import Optional
from sqlalchemy import select
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token
from app.db.models.user import User

BASE = "/api/v1/auth"
ACTIVITY = f"{BASE}/activity"
ALERTS_SUB = f"{BASE}/alerts/subscription"
ALERTS_SUBSCRIBE = f"{BASE}/alerts/subscribe"


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def ip_header(seed: int) -> dict[str, str]:
    """
    Make tests look like different clients to dodge per-IP rate limits.
    Ensures valid IPv4 (0..255).
    """
    seed = max(0, min(255, int(seed)))
    return {"X-Forwarded-For": f"127.0.0.{seed}"}

async def bearer(user: User) -> dict[str, str]:
    """
    ACCESS bearer with mfa_authenticated=True (harmless if not required).
    """
    token = await create_access_token(user_id=user.id, mfa_authenticated=True)
    return {"Authorization": f"Bearer {token}"}

def _iso_now(delta: Optional[int] = None) -> str:
    dt = datetime.now(timezone.utc)
    if delta:
        dt = dt + timedelta(seconds=delta)
    return dt.isoformat()


# ─────────────────────────────────────────────────────────────
# GET /auth/activity
# ─────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_activity_fallbacks_to_redis_when_db_empty(
    async_client: AsyncClient, create_test_user, redis_client, db_session: AsyncSession
):
    """
    When DB has no `AuditLog` rows (or the model is unavailable),
    the route should fall back to the Redis ring buffer.
    """
    user = await create_test_user(is_verified=True)
    headers = await bearer(user)

    # Populate Redis ring buffer with mixed actions
    key = f"audit:recent:{user.id}"
    entries = [
        {
            "id": "1",
            "at": _iso_now(-3),
            "action": "LOGIN_SUCCESS",
            "status": "SUCCESS",
            "ip": "198.51.100.10",
            "user_agent": "pytest/ua",
        },
        {
            "id": "2",
            "at": _iso_now(-2),
            "action": "ACCOUNT_PASSWORD_CHANGED",
            "status": "SUCCESS",
            "ip": "198.51.100.11",
            "user_agent": "pytest/ua",
            "meta": {"device": "web"},
        },
        {
            "id": "3",
            "at": _iso_now(-1),
            "action": "MFA_CHALLENGE",
            "status": "SUCCESS",
            "ip": "198.51.100.12",
            "user_agent": "pytest/ua",
        },
    ]

    # Insert entries into Redis
    for e in entries:
        await redis_client.rpush(key, json.dumps(e))

    # Ensure Redis entries are inserted
    assert await redis_client.llen(key) == len(entries), "Redis entries not inserted correctly"

    # Send the request
    r = await async_client.get(ACTIVITY, headers=headers | ip_header(40))
    
    assert r.status_code == 200, r.text
    body = r.json()

    # Ensure the correct number of items are returned from Redis
    assert body["total"] == len(entries), f"Expected {len(entries)} entries, got {body['total']}"

    actions = [it["action"] for it in body["items"]]
    assert {"LOGIN_SUCCESS", "ACCOUNT_PASSWORD_CHANGED", "MFA_CHALLENGE"}.issubset(set(actions))


@pytest.mark.anyio
async def test_activity_limit_and_filters(
    async_client: AsyncClient, create_test_user, redis_client
):
    """
    Limit results and filter by type=auth|security.
    """
    user = await create_test_user(is_verified=True)
    headers = await bearer(user)
    key = f"audit:recent:{user.id}"

    # Clear then insert a small set with mixed categories
    await redis_client.delete(key)
    data = [
        {"id": "a", "at": _iso_now(-5), "action": "LOGIN_SUCCESS", "status": "SUCCESS"},
        {"id": "b", "at": _iso_now(-4), "action": "MFA_CHALLENGE", "status": "SUCCESS"},
        {"id": "c", "at": _iso_now(-3), "action": "ACCOUNT_PASSWORD_CHANGED", "status": "SUCCESS"},
        {"id": "d", "at": _iso_now(-2), "action": "TRUSTED_DEVICE_ADDED", "status": "SUCCESS"},
        {"id": "e", "at": _iso_now(-1), "action": "LOGOUT", "status": "SUCCESS"},
    ]
    for e in data:
        await redis_client.rpush(key, json.dumps(e))

    # Filter: auth
    r1 = await async_client.get(f"{ACTIVITY}?type=auth&limit=10", headers=headers | ip_header(41))
    assert r1.status_code == 200
    acts1 = [it["action"] for it in r1.json()["items"]]
    assert set(acts1).issubset({"LOGIN_SUCCESS", "MFA_CHALLENGE", "REFRESH", "SIGNUP", "LOGOUT", "REAUTH"})

    # Filter: security
    r2 = await async_client.get(f"{ACTIVITY}?type=security&limit=10", headers=headers | ip_header(42))
    assert r2.status_code == 200
    acts2 = [it["action"] for it in r2.json()["items"]]
    # Allow a superset here; we only require that purely-auth events get filtered out
    assert "LOGIN_SUCCESS" not in acts2 and "LOGOUT" not in acts2

    # Limit
    r3 = await async_client.get(f"{ACTIVITY}?type=all&limit=2", headers=headers | ip_header(43))
    assert r3.status_code == 200
    assert r3.json()["total"] == 2


@pytest.mark.anyio
async def test_activity_requires_auth(async_client: AsyncClient):
    r = await async_client.get(ACTIVITY)
    assert r.status_code in (401, 403)


# Optional DB-first test: only runs if `AuditLog` model is present in your app.
@pytest.mark.anyio
async def test_activity_db_first_when_auditlog_available(
    async_client: AsyncClient, create_test_user, db_session: AsyncSession
):
    user = await create_test_user(is_verified=True)
    headers = await bearer(user)

    try:
        from app.db.models.audit_log import AuditLog  # type: ignore
    except Exception:
        pytest.skip("AuditLog model not available in this deployment")

    # Insert AuditLog entries into DB
    row1 = AuditLog(
        user_id=user.id,
        action="LOGIN_SUCCESS",
        status="SUCCESS",
        occurred_at=datetime.now(timezone.utc) - timedelta(seconds=2),
        ip_address="198.51.100.21",
        user_agent="pytest/ua",
        metadata_json=json.dumps({"geo": {"country": "ZZ"}}),
    )
    row2 = AuditLog(
        user_id=user.id,
        action="ACCOUNT_PASSWORD_CHANGED",
        status="SUCCESS",
        occurred_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        ip_address="198.51.100.22",
        user_agent="pytest/ua",
        metadata_json=json.dumps({"device": "web"}),
    )
    db_session.add_all([row1, row2])
    await db_session.commit()

    # Ensure the DB has the data
    assert await db_session.execute(select(AuditLog).filter_by(user_id=user.id)).count() == 2, "DB query failed"

    # Send the request
    r = await async_client.get(ACTIVITY, headers=headers | ip_header(44))
    assert r.status_code == 200
    body = r.json()

    # Ensure that both actions are returned
    acts = [it["action"] for it in body["items"]]
    assert {"LOGIN_SUCCESS", "ACCOUNT_PASSWORD_CHANGED"}.issubset(set(acts))



# ─────────────────────────────────────────────────────────────
# GET /auth/alerts/subscription
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_alerts_subscription_defaults(
    async_client: AsyncClient, create_test_user, redis_client
):
    """
    With no Redis state, the endpoint returns default subscription (all True).
    """
    user = await create_test_user(is_verified=True)
    headers = await bearer(user)

    # Ensure hash is absent
    await redis_client.delete(f"alert:sub:{user.id}")

    r = await async_client.get(ALERTS_SUB, headers=headers | ip_header(50))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body == {
        "new_device": True,
        "new_location": True,
        "impossible_travel": True,
        "email_notifications": True,
    }


@pytest.mark.anyio
async def test_alerts_subscription_requires_auth(async_client: AsyncClient):
    r = await async_client.get(ALERTS_SUB)
    assert r.status_code in (401, 403)


# ─────────────────────────────────────────────────────────────
# POST /auth/alerts/subscribe
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_update_alert_subscription_persists_and_reads_back(
    async_client: AsyncClient, create_test_user, redis_client
):
    user = await create_test_user(is_verified=True)
    headers = await bearer(user)

    payload = {
        "new_device": False,
        "new_location": True,
        "impossible_travel": False,
        "email_notifications": True,
    }
    r1 = await async_client.post(ALERTS_SUBSCRIBE, json=payload, headers=headers | ip_header(51))
    assert r1.status_code == 200, r1.text
    body1 = r1.json()
    assert body1 == payload

    # A GET should reflect persisted values
    r2 = await async_client.get(ALERTS_SUB, headers=headers | ip_header(52))
    assert r2.status_code == 200
    assert r2.json() == payload

    # And the raw Redis hash should have the expected encoding
    h = await redis_client.hgetall(f"alert:sub:{user.id}")
    to_s = lambda b: b.decode() if isinstance(b, (bytes, bytearray)) else str(b)
    decoded = {to_s(k): to_s(v) for k, v in (h or {}).items()}
    assert decoded == {
        "new_device": "0",
        "new_location": "1",
        "impossible_travel": "0",
        "email_notifications": "1",
    }


@pytest.mark.anyio
async def test_update_alert_subscription_requires_auth(async_client: AsyncClient):
    r = await async_client.post(ALERTS_SUBSCRIBE, json={"new_device": True, "new_location": True, "impossible_travel": True, "email_notifications": True})
    assert r.status_code in (401, 403)
