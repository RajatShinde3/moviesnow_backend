import pytest
from uuid import UUID
from datetime import datetime, timedelta, timezone

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.live_sessions import LiveSession, LiveSessionStatus
from app.schemas.enums import OrgRole

BASE = "/api/v1/course/live/session"


# ------------------------------
# Helpers
# ------------------------------
def _utcnow_naive() -> datetime:
    # Naive UTC to avoid TIMESTAMP WITHOUT TIME ZONE driver issues
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
    t0 = _utcnow_naive()
    start = start or (t0 + timedelta(hours=1))
    end = end or (start + timedelta(hours=1))

    s = LiveSession(
        title=title,
        organization_id=org_id,
        start_time=start,      # naive datetimes
        end_time=end,          # naive datetimes
        status=LiveSessionStatus.SCHEDULED,
        instructor_id=instructor_id,
    )
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


# ------------------------------
# Tests
# ------------------------------
@pytest.mark.anyio
async def test_delete_session__204_happy_path(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    r = await async_client.delete(f"{BASE}/{s.id}", headers=headers)
    assert r.status_code == 204

    # After delete, GET should be 404 (org-scoped + is_deleted filter)
    r2 = await async_client.get(f"{BASE}/{s.id}", headers=headers)
    assert r2.status_code == 404


@pytest.mark.anyio
async def test_delete_session__412_if_match_mismatch(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    # Fetch current ETag then send a bogus one
    r0 = await async_client.get(f"{BASE}/{s.id}", headers=headers)
    assert r0.status_code == 200
    assert r0.headers.get("ETag")

    r = await async_client.delete(
        f"{BASE}/{s.id}", headers={**headers, "If-Match": "not-the-right-etag"}
    )
    assert r.status_code == 412

    # Still present
    r2 = await async_client.get(f"{BASE}/{s.id}", headers=headers)
    assert r2.status_code == 200


@pytest.mark.anyio
async def test_delete_session__204_if_match_ok(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    r0 = await async_client.get(f"{BASE}/{s.id}", headers=headers)
    assert r0.status_code == 200
    etag = r0.headers.get("ETag")
    assert etag

    r = await async_client.delete(f"{BASE}/{s.id}", headers={**headers, "If-Match": etag})
    assert r.status_code == 204

    r2 = await async_client.get(f"{BASE}/{s.id}", headers=headers)
    assert r2.status_code == 404


@pytest.mark.anyio
async def test_delete_session__404_wrong_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Create in org1 (admin1)
    admin1, headers1, org1 = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    s = await _mk_session(db_session, org_id=org1.id, instructor_id=admin1.id)

    # Caller from a different org
    _, headers2, _ = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    r = await async_client.delete(f"{BASE}/{s.id}", headers=headers2)
    assert r.status_code == 404

    # Org1 can still see it
    r2 = await async_client.get(f"{BASE}/{s.id}", headers=headers1)
    assert r2.status_code == 200


@pytest.mark.anyio
async def test_delete_session__404_already_deleted(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    # Patch now_utc used by the route to return naive datetime (avoid tz-aware writes)
    import app.api.v1.course.live.sessions as sessions_api
    monkeypatch.setattr(sessions_api, "now_utc", lambda: _utcnow_naive())

    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    r1 = await async_client.delete(f"{BASE}/{s.id}", headers=headers)
    assert r1.status_code == 204

    r2 = await async_client.delete(f"{BASE}/{s.id}", headers=headers)
    assert r2.status_code == 404


@pytest.mark.anyio
async def test_delete_session__403_requires_permission(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Create as an admin so the row exists…
    admin, admin_headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    # …but call DELETE as a low-privileged user (INTERN)
    _, intern_headers, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    r = await async_client.delete(f"{BASE}/{s.id}", headers=intern_headers)
    assert r.status_code == 403

    # Still present for admin
    r2 = await async_client.get(f"{BASE}/{s.id}", headers=admin_headers)
    assert r2.status_code == 200


@pytest.mark.anyio
async def test_delete_session__sets_deleted_flags_and_timestamps(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    If the model exposes `deleted_at` and/or `updated_at`, ensure they're set.
    We patch now_utc in the route to return **naive** UTC to avoid driver errors
    when the DB column is TIMESTAMP WITHOUT TIME ZONE.
    """
    import app.api.v1.course.live.sessions as sessions_api
    monkeypatch.setattr(sessions_api, "now_utc", lambda: _utcnow_naive())

    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    r = await async_client.delete(f"{BASE}/{s.id}", headers=headers)
    assert r.status_code == 204

    row = (
        await db_session.execute(select(LiveSession).where(LiveSession.id == s.id))
    ).scalar_one()

    assert row.is_deleted is True
    # Only assert timestamp fields if they exist on this model in your env
    if hasattr(row, "deleted_at"):
        assert getattr(row, "deleted_at") is not None
    if hasattr(row, "updated_at"):
        assert getattr(row, "updated_at") is not None
