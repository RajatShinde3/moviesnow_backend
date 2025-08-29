# tests/test_live/test_submit_feedback.py

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.db.models.live_sessions import LiveSession
from app.core.redis_client import redis_wrapper

BASE = "/api/v1/course/live/feedback/live-sessions"


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
    title: str = "Test Session",
    start_time: datetime | None = None,
    is_deleted: bool = False,
) -> LiveSession:
    """Create a LiveSession satisfying NOT NULL start/end fields if present."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    st = start_time or now
    et = st + timedelta(hours=1)

    data = dict(title=title, organization_id=org_id)

    # set whichever columns exist in your schema
    for start_attr in ("start_time", "scheduled_at", "starts_at", "start_at"):
        if hasattr(LiveSession, start_attr):
            data[start_attr] = st
            break
    for end_attr in ("end_time", "ends_at"):
        if hasattr(LiveSession, end_attr):
            data[end_attr] = et
            break

    if hasattr(LiveSession, "is_deleted"):
        data["is_deleted"] = is_deleted

    s = LiveSession(**data)
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


def _rl_key(org_id, user_id, session_id) -> str:
    return f"fb:rate:{org_id}:{user_id}:{session_id}"


# -----------------------------------------------------------------------------
# Tests (POST /live-sessions/{session_id}/feedback)
# -----------------------------------------------------------------------------

@pytest.mark.anyio
async def test_submit_feedback__201_create(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    session = await _mk_session(db_session, org_id=org.id)

    payload = {
        "session_id": str(session.id),          # REQUIRED by body model
        "rating": 5,
        "comments": "Great talk!",
        "tags": ["Engaging", "Clear"],
        "feedback_type": "general",
        "source": "web",
    }
    r = await async_client.post(f"{BASE}/{session.id}/feedback", headers=headers, json=payload)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["session_id"] == str(session.id)
    assert body["user_id"] == str(user.id)
    assert body["rating"] == 5


@pytest.mark.anyio
async def test_submit_feedback__404_when_session_not_in_org(async_client: AsyncClient, org_user_with_token):
    _, headers, _org = await org_user_with_token(role=OrgRole.ADMIN)
    sid = uuid4()
    r = await async_client.post(
        f"{BASE}/{sid}/feedback",
        headers=headers,
        json={"session_id": str(sid), "rating": 4},
    )
    assert r.status_code == 404, r.text


@pytest.mark.anyio
async def test_submit_feedback__require_session_started_blocks_until_start(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    future = datetime.now(timezone.utc) + timedelta(hours=1)
    session = await _mk_session(db_session, org_id=org.id, start_time=future)

    # ── DEBUG: initial context
    try:
        local_offset = datetime.now().astimezone().utcoffset()
    except Exception:
        local_offset = None
    print("\nDEBUG submit_feedback__require_session_started_blocks_until_start")
    print(f"DEBUG org_id={org.id} user_id={user.id} session_id={session.id}")
    print(f"DEBUG local_offset={local_offset}")
    print(f"DEBUG future start (naive): {future.isoformat()}  tzinfo={future.tzinfo}")

    # With guard ON and tz=UTC, should 400 before start
    url = f"{BASE}/{session.id}/feedback?require_session_started=true&tz=UTC"
    print(f"DEBUG POST url={url}")
    r = await async_client.post(
        url,
        headers=headers,
        json={"session_id": str(session.id), "rating": 4, "comments": "pre-start"},
    )
    print(f"DEBUG r1.status={r.status_code}")
    print(f"DEBUG r1.headers={dict(r.headers)}")
    print(f"DEBUG r1.body={r.text}")
    assert r.status_code == 400, r.text

    # Move start into the past (and end if present)
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    for attr in ("start_time", "scheduled_at", "starts_at", "start_at"):
        if hasattr(session, attr):
            setattr(session, attr, past)
            print(f"DEBUG set {attr} -> past={past.isoformat()}  tzinfo={past.tzinfo}")
            break
    if hasattr(session, "end_time"):
        session.end_time = past + timedelta(hours=1)
        print(f"DEBUG set end_time -> {(past + timedelta(hours=1)).isoformat()}")

    db_session.add(session)
    await db_session.commit()
    await db_session.refresh(session)

    # ── DEBUG: persisted session times (as read back from DB)
    start_val = None
    for attr in ("start_time", "scheduled_at", "starts_at", "start_at"):
        if hasattr(session, attr):
            start_val = getattr(session, attr)
            print(f"DEBUG persisted {attr}={start_val}  tzinfo={getattr(start_val, 'tzinfo', None)}")
            break
    if hasattr(session, "end_time"):
        print(f"DEBUG persisted end_time={session.end_time}  tzinfo={getattr(session.end_time, 'tzinfo', None)}")

    # Should now be allowed (201)
    r2 = await async_client.post(
        url,
        headers=headers,
        json={"session_id": str(session.id), "rating": 4, "comments": "post-start"},
    )
    print(f"DEBUG r2.status={r2.status_code}")
    print(f"DEBUG r2.headers={dict(r2.headers)}")
    print(f"DEBUG r2.body={r2.text}")
    assert r2.status_code == 201, r2.text



@pytest.mark.anyio
async def test_submit_feedback__rating_validation_422(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    session = await _mk_session(db_session, org_id=org.id)

    # out of range low
    r = await async_client.post(
        f"{BASE}/{session.id}/feedback",
        headers=headers,
        json={"session_id": str(session.id), "rating": 0},
    )
    assert r.status_code == 422

    # out of range high
    r2 = await async_client.post(
        f"{BASE}/{session.id}/feedback",
        headers=headers,
        json={"session_id": str(session.id), "rating": 6},
    )
    assert r2.status_code == 422

    # bad type => route converts and raises 422 "Invalid rating."
    r3 = await async_client.post(
        f"{BASE}/{session.id}/feedback",
        headers=headers,
        json={"session_id": str(session.id), "rating": "bad"},
    )
    assert r3.status_code in (400, 422)


@pytest.mark.anyio
async def test_submit_feedback__409_duplicate_without_allow_update_then_201_with_update(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    session = await _mk_session(db_session, org_id=org.id)

    # First create
    r1 = await async_client.post(
        f"{BASE}/{session.id}/feedback",
        headers=headers,
        json={"session_id": str(session.id), "rating": 3, "comments": "ok"},
    )
    assert r1.status_code == 201, r1.text

    # Clear rate-limit key so the next request exercises duplicate handling
    if redis_wrapper and getattr(redis_wrapper, "client", None):
        await redis_wrapper.client.delete(_rl_key(org.id, user.id, session.id))

    # Duplicate without allow_update => 409
    r2 = await async_client.post(
        f"{BASE}/{session.id}/feedback?allow_update=false",
        headers=headers,
        json={"session_id": str(session.id), "rating": 4, "comments": "try to overwrite"},
    )
    assert r2.status_code == 409, r2.text

    # Clear RL again, then update with allow_update => 201 and updated fields
    if redis_wrapper and getattr(redis_wrapper, "client", None):
        await redis_wrapper.client.delete(_rl_key(org.id, user.id, session.id))

    r3 = await async_client.post(
        f"{BASE}/{session.id}/feedback?allow_update=true",
        headers=headers,
        json={
            "session_id": str(session.id),
            "rating": 4,
            "comments": "UPDATED",
            "tags": ["x", "y"],
            "source": "web",
        },
    )
    assert r3.status_code == 201, r3.text
    body = r3.json()
    assert body["rating"] == 4
    assert "UPDATED" in (body.get("comments") or "")


@pytest.mark.anyio
async def test_submit_feedback__429_rate_limited(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    session = await _mk_session(db_session, org_id=org.id)

    r1 = await async_client.post(
        f"{BASE}/{session.id}/feedback",
        headers=headers,
        json={"session_id": str(session.id), "rating": 5, "comments": "first"},
    )
    assert r1.status_code == 201, r1.text

    # Immediate retry should trip the debounce -> 429
    r2 = await async_client.post(
        f"{BASE}/{session.id}/feedback",
        headers=headers,
        json={"session_id": str(session.id), "rating": 5, "comments": "second"},
    )
    assert r2.status_code == 429, r2.text


@pytest.mark.anyio
async def test_submit_feedback__idempotency_key_returns_409_on_duplicate(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    First call stores the idempotency key; second call with the same key => 409.
    Clear the RL key between requests so idempotency logic runs.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    session = await _mk_session(db_session, org_id=org.id)

    idem = "same-key-123"
    r1 = await async_client.post(
        f"{BASE}/{session.id}/feedback",
        headers={**headers, "Idempotency-Key": idem},
        json={"session_id": str(session.id), "rating": 5, "comments": "idemp-A"},
    )
    assert r1.status_code == 201, r1.text

    # Clear the rate-limit key so the next request reaches the idempotency check
    if redis_wrapper and getattr(redis_wrapper, "client", None):
        await redis_wrapper.client.delete(_rl_key(org.id, user.id, session.id))

    r2 = await async_client.post(
        f"{BASE}/{session.id}/feedback",
        headers={**headers, "Idempotency-Key": idem},
        json={"session_id": str(session.id), "rating": 5, "comments": "idemp-B"},
    )
    assert r2.status_code == 409, r2.text


@pytest.mark.anyio
async def test_submit_feedback__soft_deleted_session_is_404_if_field_exists(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    If LiveSession has is_deleted, submitting feedback to a deleted session should 404.
    """
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    if not hasattr(LiveSession, "is_deleted"):
        pytest.skip("LiveSession.is_deleted not present in this schema")

    session = await _mk_session(db_session, org_id=org.id, is_deleted=True)
    r = await async_client.post(
        f"{BASE}/{session.id}/feedback",
        headers=headers,
        json={"session_id": str(session.id), "rating": 5},
    )
    assert r.status_code == 404, r.text
