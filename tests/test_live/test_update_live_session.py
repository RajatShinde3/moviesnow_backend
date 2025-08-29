import pytest
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.db.models.live_sessions import LiveSession, LiveSessionStatus

# Keep aligned with your router mount
BASE = "/api/v1/course/live/session"


# ----------------------------- helpers -----------------------------

def _utcnow_naive() -> datetime:
    """
    Naive (no tzinfo) 'UTC' timestamp for environments where columns are
    TIMESTAMP WITHOUT TIME ZONE. Use datetime.now(timezone.utc) so asyncpg
    doesn't try to mix aware/naive during encoding.
    """
    return datetime.now(timezone.utc).replace(microsecond=0)

async def _mk_session(
    db: AsyncSession,
    *,
    org_id: UUID,
    title: str = "S1",
    start: datetime | None = None,
    end: datetime | None = None,
    instructor_id: UUID | None = None,
) -> LiveSession:
    """
    Create a minimal valid LiveSession row using **naive UTC** datetimes.
    """
    start = (start or (_utcnow_naive() + timedelta(hours=1))).replace(microsecond=0)
    end = (end or (start + timedelta(hours=1))).replace(microsecond=0)
    s = LiveSession(
        title=title,
        organization_id=org_id,
        start_time=start,
        end_time=end,
        instructor_id=instructor_id,
        status=LiveSessionStatus.SCHEDULED,
    )
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


# ------------------------------ tests ------------------------------

@pytest.mark.anyio
async def test_update_session__200_happy_path_and_etag(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Happy path: update non-time fields with matching If-Match.
    ETag should rotate after a real update.
    """
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    # Fetch baseline ETag
    r0 = await async_client.get(f"{BASE}/{s.id}", headers=headers)
    assert r0.status_code == 200
    etag_before = r0.headers.get("ETag")
    assert etag_before

    # Update only non-time fields so we don't persist tz-aware datetimes
    payload = {"title": "Renamed", "description": "Updated desc"}

    r = await async_client.put(
        f"{BASE}/{s.id}",
        headers={**headers, "If-Match": etag_before},
        json=payload,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["title"] == "Renamed"
    assert body["description"] == "Updated desc"

    etag_after = r.headers.get("ETag")
    assert etag_after and etag_after != etag_before


@pytest.mark.anyio
async def test_update_session__400_no_fields(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    PUT with empty body should 400 ("No fields to update").
    """
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    r = await async_client.put(f"{BASE}/{s.id}", headers=headers, json={})
    assert r.status_code == 400
    assert "No fields to update" in r.text


@pytest.mark.anyio
async def test_update_session__412_if_match_mismatch(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    If-Match provided and doesn't match -> 412.
    """
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    r = await async_client.put(
        f"{BASE}/{s.id}",
        headers={**headers, "If-Match": "bogus-etag"},
        json={"title": "Try update"},
    )
    assert r.status_code == 412


@pytest.mark.anyio
async def test_update_session__404_wrong_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Session belongs to another org -> 404.
    """
    admin1, headers1, org1 = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org1.id, instructor_id=admin1.id)

    # Different org
    _, headers2, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    r = await async_client.put(f"{BASE}/{s.id}", headers=headers2, json={"title": "Nope"})
    assert r.status_code == 404


@pytest.mark.anyio
async def test_update_session__time_rules(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Time validations:
      - Only one of start/end -> 400
      - end <= start -> 400
      - duration > max -> 400
    (All short-circuit before DB commit, so safe to send naive datetimes.)
    """
    from app.api.v1.course.live.sessions import _MAX_DURATION_HOURS

    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    base_start = (_utcnow_naive() + timedelta(hours=2)).replace(microsecond=0)
    base_end = (base_start + timedelta(hours=1)).replace(microsecond=0)

    # only end_time
    r1 = await async_client.put(
        f"{BASE}/{s.id}",
        headers=headers,
        json={"end_time": base_end.isoformat()},
    )
    assert r1.status_code == 400

    # end <= start
    r2 = await async_client.put(
        f"{BASE}/{s.id}",
        headers=headers,
        json={
            "start_time": base_start.isoformat(),
            "end_time": (base_start - timedelta(minutes=1)).isoformat(),
        },
    )
    assert r2.status_code == 400

    # duration > max
    too_long_end = base_start + timedelta(hours=_MAX_DURATION_HOURS + 1)
    r3 = await async_client.put(
        f"{BASE}/{s.id}",
        headers=headers,
        json={
            "start_time": base_start.isoformat(),
            "end_time": too_long_end.isoformat(),
        },
    )
    assert r3.status_code == 400


@pytest.mark.anyio
async def test_update_session__409_instructor_overlap_on_time_change(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Updating times that would overlap another session for the same instructor -> 409.
    (Overlap check runs before persisting any changes.)
    """
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    t = (_utcnow_naive() + timedelta(hours=1)).replace(microsecond=0)

    # s1: [t, t+60]
    s1 = await _mk_session(
        db_session, org_id=org.id, title="S1", start=t, end=t + timedelta(minutes=60), instructor_id=admin.id
    )
    # s2: [t+30, t+120]
    _ = await _mk_session(
        db_session, org_id=org.id, title="S2", start=t + timedelta(minutes=30),
        end=t + timedelta(minutes=120), instructor_id=admin.id
    )

    # Update s1 → [t+45, t+90] (still overlaps S2)
    r = await async_client.put(
        f"{BASE}/{s1.id}",
        headers=headers,
        json={
            "start_time": (t + timedelta(minutes=45)).replace(microsecond=0).isoformat(),
            "end_time": (t + timedelta(minutes=90)).replace(microsecond=0).isoformat(),
        },
    )
    assert r.status_code == 409


@pytest.mark.anyio
async def test_update_session__200_noop_returns_current(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    No-op update: sending identical non-time field returns the current session (200).
    Avoid sending time fields here to prevent unnecessary tz conversions.
    """
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    start = (_utcnow_naive() + timedelta(hours=1)).replace(microsecond=0)
    end = (start + timedelta(hours=1)).replace(microsecond=0)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, start=start, end=end, title="Same")

    # PUT identical title (no actual change)
    r = await async_client.put(
        f"{BASE}/{s.id}",
        headers=headers,
        json={"title": "Same"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["title"] == "Same"
