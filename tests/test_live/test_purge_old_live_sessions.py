# tests/test_live/test_purge_old_live_sessions.py
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.live_sessions import LiveSession, LiveSessionStatus
from app.schemas.enums import OrgRole  # adjust import if your OrgRole is elsewhere

BASE = "/api/v1/course/live/session"


# --- time helpers (naive UTC) -------------------------------------------------

def _utcnow_naive() -> datetime:
    # naive (no tzinfo) to match TIMESTAMP WITHOUT TIME ZONE columns
    return datetime.now(timezone.utc).replace(microsecond=0)


# --- seed helper --------------------------------------------------------------

async def _mk_session(
    db: AsyncSession,
    *,
    org_id: UUID,
    title: str = "PurgeMe",
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    deleted: bool = False,
    deleted_days_ago: Optional[int] = None,
    legal_hold: bool = False,
) -> LiveSession:
    """
    Create a LiveSession row with naive-UTC datetimes and optional soft-delete.
    """
    start = start or (_utcnow_naive() + timedelta(hours=1))
    end = end or (start + timedelta(hours=1))
    created = _utcnow_naive()
    updated = created

    ls = LiveSession(
        title=title,
        organization_id=org_id,
        start_time=start,
        end_time=end,
        status=LiveSessionStatus.SCHEDULED,
        is_deleted=deleted,
        legal_hold=legal_hold if hasattr(LiveSession, "legal_hold") else False,
    )

    # set timestamps if model exposes them
    if hasattr(LiveSession, "created_at"):
        setattr(ls, "created_at", created)
    if hasattr(LiveSession, "updated_at"):
        setattr(ls, "updated_at", updated)

    if deleted:
        if hasattr(LiveSession, "deleted_at"):
            da = _utcnow_naive() - timedelta(days=(deleted_days_ago or 40))
            setattr(ls, "deleted_at", da)

    db.add(ls)
    await db.commit()
    await db.refresh(ls)
    return ls


# --- monkeypatch helpers ------------------------------------------------------

@pytest.fixture
def patch_naive_now(monkeypatch):
    """
    Make purge route use naive-UTC now() so DB comparisons to TIMESTAMP WITHOUT TIME ZONE are safe.
    """
    import app.api.v1.course.live.sessions as sessions_api
    monkeypatch.setattr(sessions_api, "now_utc", lambda: _utcnow_naive())
    yield


@pytest.fixture
def patch_retention(monkeypatch):
    """
    Allow tests to set the default retention returned by get_live_retention_days.
    """
    import app.api.v1.course.live.sessions as sessions_api

    def _set_retention(days: int):
        monkeypatch.setattr(sessions_api, "get_live_retention_days", lambda db, org_id: asyncio.Future())
        # we need to return an awaitable resolving to `days`
        async def _ret():
            return days
        monkeypatch.setattr(sessions_api, "get_live_retention_days", lambda db, org_id: _ret())

    return _set_retention


# ============ TESTS ===========================================================

@pytest.mark.anyio
async def test_purge__403_for_non_admin(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now, patch_retention):
    # non-admin user
    _, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    # seed one eligible row
    await _mk_session(db_session, org_id=org.id, deleted=True, deleted_days_ago=60)

    # default retention (patched) doesn't matter for 403
    patch_retention(30)

    r = await async_client.delete(f"{BASE}/purge-old", headers=headers)
    assert r.status_code == 403


@pytest.mark.anyio
async def test_purge__dry_run_counts_but_keeps_rows(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now, patch_retention):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    # Eligible: deleted 60d ago
    s1 = await _mk_session(db_session, org_id=org.id, deleted=True, deleted_days_ago=60, title="eligible")
    # Not eligible: not deleted
    _ = await _mk_session(db_session, org_id=org.id, deleted=False, title="not-deleted")
    # Not eligible: deleted recently (5d ago)
    _ = await _mk_session(db_session, org_id=org.id, deleted=True, deleted_days_ago=5, title="recently-deleted")
    # Not eligible: legal hold (if column exists)
    s_hold = await _mk_session(db_session, org_id=org.id, deleted=True, deleted_days_ago=60, legal_hold=True, title="hold")

    patch_retention(30)

    r = await async_client.delete(f"{BASE}/purge-old?dry_run=true", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dry_run"] is True
    assert body["purged_count"] == 1
    assert str(s1.id) in body["sample_ids"]
    assert str(s_hold.id) not in body["sample_ids"]  # legal hold excluded

    # verify the eligible row is still there (no hard delete on dry_run)
    rs = await db_session.execute(select(LiveSession).where(LiveSession.id == s1.id))
    assert rs.scalar_one_or_none() is not None


@pytest.mark.anyio
async def test_purge__hard_delete_removes_rows_in_batches(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now, patch_retention):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    # 25 eligible (older than retention), 5 ineligible (recent)
    eligible = [await _mk_session(db_session, org_id=org.id, deleted=True, deleted_days_ago=60, title=f"E{i}") for i in range(25)]
    _recent = [await _mk_session(db_session, org_id=org.id, deleted=True, deleted_days_ago=2, title=f"R{i}") for i in range(5)]

    patch_retention(30)

    # Use small batch size to ensure multiple batches (3 batches: 10, 10, 5)
    r = await async_client.delete(f"{BASE}/purge-old?batch_size=10", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["purged_count"] == 25
    assert body["batches_run"] in (3, )  # 10+10+5

    # verify all eligible rows are gone
    ids = [s.id for s in eligible]
    rs = await db_session.execute(select(LiveSession.id).where(LiveSession.id.in_(ids)))
    remaining = {row[0] for row in rs.all()}
    assert remaining == set()  # all purged

    # verify recent ones remain
    rs2 = await db_session.execute(select(LiveSession).where(LiveSession.title.like("R%")))
    assert len(rs2.scalars().all()) == 5


@pytest.mark.anyio
async def test_purge__max_batches_cap_limits_deletion(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now, patch_retention):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    # 25 eligible rows
    ids = []
    for i in range(25):
        s = await _mk_session(db_session, org_id=org.id, deleted=True, deleted_days_ago=60, title=f"C{i}")
        ids.append(s.id)

    patch_retention(30)

    # batch_size=10, max_batches=2 -> should delete only 20, leaving 5
    r = await async_client.delete(f"{BASE}/purge-old?batch_size=10&max_batches=2", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["purged_count"] == 20
    assert body["batches_run"] == 2

    rs = await db_session.execute(select(LiveSession.id).where(LiveSession.id.in_(ids)))
    remaining = {row[0] for row in rs.all()}
    assert len(remaining) == 5  # 5 left due to cap


@pytest.mark.anyio
async def test_purge__days_override_wins_over_org_setting(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now, patch_retention):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    # default retention from org would be 100d (so NOT eligible)
    patch_retention(100)

    # deleted 7 days ago → eligible only if days override is <=7
    s = await _mk_session(db_session, org_id=org.id, deleted=True, deleted_days_ago=7)

    # Override days=5 (cutoff = now-5d) should NOT purge (7d is older than cutoff? Wait: deleted_at < now-5d -> True, so eligible)
    # So with days=5, 7-days-old IS eligible; with default 100 it's NOT. This verifies override is used.
    r = await async_client.delete(f"{BASE}/purge-old?dry_run=true&days=5", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["retention_days"] == 5
    assert body["purged_count"] == 1
    assert str(s.id) in body["sample_ids"]

    # And confirm it wasn't actually deleted due to dry_run
    rs = await db_session.execute(select(LiveSession).where(LiveSession.id == s.id))
    assert rs.scalar_one_or_none() is not None


@pytest.mark.anyio
async def test_purge__sample_ids_bounded_to_100(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now, patch_retention):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    # 130 eligible rows
    for i in range(130):
        await _mk_session(db_session, org_id=org.id, deleted=True, deleted_days_ago=60, title=f"S{i}")

    patch_retention(30)

    r = await async_client.delete(f"{BASE}/purge-old?dry_run=true&batch_size=500", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["purged_count"] == 130
    assert len(body["sample_ids"]) <= 100


@pytest.mark.anyio
async def test_purge__legal_hold_not_purged(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now, patch_retention):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    # one held, one eligible
    s_hold = await _mk_session(db_session, org_id=org.id, deleted=True, deleted_days_ago=60, legal_hold=True, title="HOLD")
    s_ok = await _mk_session(db_session, org_id=org.id, deleted=True, deleted_days_ago=60, legal_hold=False, title="OK")

    patch_retention(30)

    r = await async_client.delete(f"{BASE}/purge-old", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["purged_count"] == 1

    # held remains
    rs = await db_session.execute(select(LiveSession.id).where(LiveSession.id == s_hold.id))
    assert rs.scalar_one_or_none() is not None

    # ok was purged
    rs2 = await db_session.execute(select(LiveSession.id).where(LiveSession.id == s_ok.id))
    assert rs2.scalar_one_or_none() is None


@pytest.mark.anyio
async def test_purge__response_fields_and_cutoff_shape(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, patch_naive_now, patch_retention):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    # one eligible to ensure non-zero path
    _ = await _mk_session(db_session, org_id=org.id, deleted=True, deleted_days_ago=45)

    patch_retention(30)

    r = await async_client.delete(f"{BASE}/purge-old?dry_run=true", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()

    # presence of keys
    for key in ("detail", "retention_days", "cutoff", "dry_run", "batches_run", "purged_count", "sample_ids"):
        assert key in body

    # cutoff should be ISO-ish; .fromisoformat should parse (naive or offset)
    parsed = datetime.fromisoformat(body["cutoff"])
    assert isinstance(parsed, datetime)
    assert body["retention_days"] == 30
    assert body["detail"].lower().startswith("dry run")
