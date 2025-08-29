# tests/test_live/test_search_live_feedbacks.py

import pytest
from httpx import AsyncClient
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from sqlalchemy import select

from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.db.models.live_sessions import LiveSession
from app.db.models.live_session_feedback import LiveSessionFeedback


BASE = "/api/v1/course/live/feedback"
SEARCH = f"{BASE}/feedback/search"


# ---------- helpers -----------------------------------------------------------

def _set_if_has(obj, **vals):
    for k, v in vals.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


def _mk_session(org_id):
    now = datetime.now(timezone.utc)
    return LiveSession(
        title="Session A",
        organization_id=org_id,
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(hours=2),
    )


async def _mk_user(db: AsyncSession, email: str, full_name: str = None):
    from app.db.models.user import User
    # reuse if already exists (prevents UNIQUE(email) violation)
    existing = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if existing:
        return existing

    u = User(
        email=email,
        hashed_password="x",
        is_active=True,
        is_verified=True,
        full_name=full_name,
        created_at=datetime.now(timezone.utc),
        **({"updated_at": datetime.now(timezone.utc)} if hasattr(User, "updated_at") else {}),
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


# ---------- tests -------------------------------------------------------------

@pytest.mark.anyio
async def test_search_feedbacks__422_when_invalid_order_by(async_client: AsyncClient, org_user_with_token):
    """
    FastAPI rejects invalid `order_by` at parameter validation time due to Query(..., regex=...),
    so the response is 422 (not 400 from our manual check).
    """
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.get(f"{SEARCH}?order_by=not_a_field", headers=headers)
    assert r.status_code == 422
    # Body should mention the offending field
    assert "order_by" in r.text


@pytest.mark.anyio
async def test_search_feedbacks__empty_ok_and_x_total_count(async_client: AsyncClient, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.get(SEARCH, headers=headers)
    assert r.status_code == 200, r.text
    assert r.headers.get("X-Total-Count") is not None
    body = r.json()
    assert isinstance(body, list)
    assert len(body) == 0


@pytest.mark.anyio
async def test_search_feedbacks__org_scoped_and_filters(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, create_organization_fixture
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Session in our org + another in a different org
    s1 = _mk_session(org.id)
    _set_if_has(s1, created_by=user.id)
    other_org = await create_organization_fixture()
    s_other = _mk_session(other_org.id)

    db_session.add_all([s1, s_other])
    await db_session.commit()
    await db_session.refresh(s1); await db_session.refresh(s_other)

    # Two users
    u1 = await _mk_user(db_session, "u1@example.com", "U1")
    u2 = await _mk_user(db_session, "u2@example.com", "U2")

    f1 = LiveSessionFeedback(session_id=s1.id, user_id=u1.id, rating=5, comments="great", created_at=datetime.now(timezone.utc))
    f2 = LiveSessionFeedback(session_id=s1.id, user_id=u2.id, rating=3, comments="ok", created_at=datetime.now(timezone.utc))
    f_wrong_org = LiveSessionFeedback(session_id=s_other.id, user_id=u1.id, rating=4, comments="other", created_at=datetime.now(timezone.utc))

    db_session.add_all([f1, f2, f_wrong_org])
    await db_session.commit()

    # Filter by session_id (should exclude the other org row)
    r = await async_client.get(f"{SEARCH}?session_id={s1.id}", headers=headers)
    assert r.status_code == 200, r.text
    items = r.json()
    assert len(items) == 2

    # Filter by user_id (reduce to 1)
    r2 = await async_client.get(f"{SEARCH}?session_id={s1.id}&user_id={u1.id}", headers=headers)
    assert r2.status_code == 200, r2.text
    items2 = r2.json()
    assert len(items2) == 1
    assert items2[0]["user_id"] == str(u1.id)


@pytest.mark.anyio
async def test_search_feedbacks__rating_range_filter(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    s = _mk_session(org.id)
    db_session.add(s); await db_session.commit(); await db_session.refresh(s)

    u = await _mk_user(db_session, "r@example.com", "R")
    # Ratings: 2, 4, 5
    db_session.add_all(
        [
            LiveSessionFeedback(session_id=s.id, user_id=u.id, rating=2, comments="bad", created_at=datetime.now(timezone.utc)),
            LiveSessionFeedback(session_id=s.id, user_id=u.id, rating=4, comments="good", created_at=datetime.now(timezone.utc)),
            LiveSessionFeedback(session_id=s.id, user_id=u.id, rating=5, comments="great", created_at=datetime.now(timezone.utc)),
        ]
    )
    await db_session.commit()

    r = await async_client.get(f"{SEARCH}?session_id={s.id}&min_rating=4&max_rating=5", headers=headers)
    assert r.status_code == 200, r.text
    items = r.json()
    assert {it["rating"] for it in items} == {4, 5}


@pytest.mark.anyio
async def test_search_feedbacks__timezone_window_ist(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    s = _mk_session(org.id)
    db_session.add(s); await db_session.commit(); await db_session.refresh(s)

    u1 = await _mk_user(db_session, "t1@example.com", "T1")
    u2 = await _mk_user(db_session, "t2@example.com", "T2")

    # Fixed UTC instants for determinism
    early_utc = datetime(2025, 1, 1, 6, 0, 0)   # 11:30 IST baseline
    late_utc  = datetime(2025, 1, 1, 10, 0, 0)  # 15:30 IST

    db_session.add_all(
        [
            LiveSessionFeedback(session_id=s.id, user_id=u1.id, rating=4, comments="early", created_at=early_utc),
            LiveSessionFeedback(session_id=s.id, user_id=u2.id, rating=5, comments="late", created_at=late_utc),
        ]
    )
    await db_session.commit()

    # Start at 15:00 IST (09:30 UTC) => include only "late" (10:00 UTC)
    start_local = "2025-01-01T15:00:00"
    r = await async_client.get(
        f"{SEARCH}?session_id={s.id}&start_date={start_local}&tz=Asia/Kolkata",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    items = r.json()
    assert len(items) == 1
    assert items[0]["comments"] == "late"


@pytest.mark.anyio
async def test_search_feedbacks__sorting_and_pagination(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    s = _mk_session(org.id)
    db_session.add(s); await db_session.commit(); await db_session.refresh(s)

    u = await _mk_user(db_session, "sort@example.com", "Sorty")

    # Stagger ratings and created_at for deterministic ordering
    t0 = datetime.now(timezone.utc) - timedelta(minutes=30)
    f_low  = LiveSessionFeedback(session_id=s.id, user_id=u.id, rating=2, comments="low",  created_at=t0 + timedelta(minutes=1))
    f_mid  = LiveSessionFeedback(session_id=s.id, user_id=u.id, rating=4, comments="mid",  created_at=t0 + timedelta(minutes=2))
    f_high = LiveSessionFeedback(session_id=s.id, user_id=u.id, rating=5, comments="high", created_at=t0 + timedelta(minutes=3))

    db_session.add_all([f_low, f_mid, f_high])
    await db_session.commit()

    # order_by=rating asc
    r1 = await async_client.get(f"{SEARCH}?session_id={s.id}&order_by=rating&order_dir=asc", headers=headers)
    assert r1.status_code == 200, r1.text
    items1 = r1.json()
    assert [i["comments"] for i in items1] == ["low", "mid", "high"]

    # order_by=rating desc
    r2 = await async_client.get(f"{SEARCH}?session_id={s.id}&order_by=rating&order_dir=desc", headers=headers)
    assert r2.status_code == 200, r2.text
    items2 = r2.json()
    assert [i["comments"] for i in items2] == ["high", "mid", "low"]

    # Pagination: limit 2, then offset 2
    r3 = await async_client.get(f"{SEARCH}?session_id={s.id}&order_by=rating&order_dir=desc&limit=2&offset=0", headers=headers)
    r4 = await async_client.get(f"{SEARCH}?session_id={s.id}&order_by=rating&order_dir=desc&limit=2&offset=2", headers=headers)
    assert r3.status_code == 200 and r4.status_code == 200
    items3, items4 = r3.json(), r4.json()
    assert [i["comments"] for i in items3] == ["high", "mid"]
    assert [i["comments"] for i in items4] == ["low"]

    # X-Total-Count should reflect total rows (3)
    assert r1.headers.get("X-Total-Count") == "3"


@pytest.mark.anyio
async def test_search_feedbacks__inverted_dates_are_swapped(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    When start_date > end_date, the endpoint swaps them. We explicitly request ASC order
    so the expected order is deterministic (A then B).
    """
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    s = _mk_session(org.id)
    db_session.add(s); await db_session.commit(); await db_session.refresh(s)

    u = await _mk_user(db_session, "inv@example.com", "Inv")

    a = LiveSessionFeedback(session_id=s.id, user_id=u.id, rating=3, comments="A", created_at=datetime(2025, 3, 1, 10, 0, 0))
    b = LiveSessionFeedback(session_id=s.id, user_id=u.id, rating=4, comments="B", created_at=datetime(2025, 3, 2, 10, 0, 0))
    c = LiveSessionFeedback(session_id=s.id, user_id=u.id, rating=5, comments="C", created_at=datetime(2025, 3, 3, 10, 0, 0))
    db_session.add_all([a, b, c])
    await db_session.commit()

    r = await async_client.get(
        f"{SEARCH}?session_id={s.id}"
        f"&start_date=2025-03-03T00:00:00&end_date=2025-03-01T00:00:00&tz=UTC"
        f"&order_by=created_at&order_dir=asc",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    items = r.json()
    assert [i["comments"] for i in items] == ["A", "B"]
