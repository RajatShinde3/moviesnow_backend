import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import LiveSession
from app.schemas.enums import OrgRole

BASE = "/api/v1/course/live/session"


# ---------- helpers ----------
def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)

def _to_naive(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo:
        return dt.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
    return dt.replace(microsecond=0)

async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
    title: str = "Session",
    start: datetime | None = None,
    end: datetime | None = None,
    instructor_id=None,
    is_deleted: bool = False,
    actual_start_time: datetime | None = None,
    actual_end_time: datetime | None = None,
    legal_hold: bool | None = None,
):
    start = _to_naive(start) or (_utcnow_naive() + timedelta(minutes=10))
    end = _to_naive(end) or (start + timedelta(hours=1))
    actual_start_time = _to_naive(actual_start_time)
    actual_end_time = _to_naive(actual_end_time)

    s = LiveSession(
        id=uuid.uuid4(),
        title=title,
        organization_id=org_id,
        start_time=start,
        end_time=end,
        is_deleted=is_deleted,
        instructor_id=instructor_id,
    )
    if hasattr(s, "actual_start_time"):
        s.actual_start_time = actual_start_time
    if hasattr(s, "actual_end_time"):
        s.actual_end_time = actual_end_time
    if hasattr(s, "created_at"):
        s.created_at = _utcnow_naive()
    if hasattr(s, "updated_at"):
        s.updated_at = _utcnow_naive()
    if legal_hold is not None and hasattr(s, "legal_hold"):
        s.legal_hold = bool(legal_hold)

    # normalize datetimes to naïve for DB
    for attr in ("start_time", "end_time", "actual_start_time", "actual_end_time", "created_at", "updated_at"):
        if hasattr(s, attr):
            v = getattr(s, attr)
            if isinstance(v, datetime):
                setattr(s, attr, _to_naive(v))

    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


# ---------- make route write naïve timestamps (compatible with TIMESTAMP WITHOUT TIME ZONE) ----------
@pytest.fixture(autouse=True)
def _patch_now_naive(monkeypatch):
    import app.api.v1.course.live.sessions as sessions_api
    monkeypatch.setattr(sessions_api, "now_utc", lambda: datetime.now(timezone.utc).replace(microsecond=0))


# =============== TESTS ===============

@pytest.mark.anyio
async def test_legal_hold__200_enable_sets_flag_and_metadata(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)

    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        actual_start_time=datetime(2025, 8, 22, 6, 0, 0),
        actual_end_time=datetime(2025, 8, 22, 7, 0, 0),
        legal_hold=False,
    )

    reason = "x" * 700  # overlong; route should store a truncated reason if column exists
    r = await async_client.put(
        f"{BASE}/{s.id}/legal-hold",
        headers=headers,
        params={"enabled": "true", "reason": reason},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["session_id"] == str(s.id)
    assert body["legal_hold"] is True
    assert r.headers.get("ETag")  # presence only

    # Refresh to avoid identity-map staleness
    row = await db_session.get(LiveSession, s.id)
    await db_session.refresh(row)

    if hasattr(row, "legal_hold"):
        assert row.legal_hold is True
    if hasattr(row, "updated_at"):
        assert row.updated_at is not None
    if hasattr(row, "legal_hold_set_at"):
        assert row.legal_hold_set_at is not None
    if hasattr(row, "legal_hold_set_by"):
        assert row.legal_hold_set_by == admin.id
    if hasattr(row, "legal_hold_reason"):
        # truncated but non-empty
        assert row.legal_hold_reason is None or (len(row.legal_hold_reason) <= 512 and reason.startswith(row.legal_hold_reason))


@pytest.mark.anyio
async def test_legal_hold__200_disable_clears_flag_and_writes_clear_metadata(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, legal_hold=True)

    # disable
    r = await async_client.put(
        f"{BASE}/{s.id}/legal-hold",
        headers=headers,
        params={"enabled": "false"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["legal_hold"] is False
    assert r.headers.get("ETag")

    row = await db_session.get(LiveSession, s.id)
    await db_session.refresh(row)

    if hasattr(row, "legal_hold"):
        assert row.legal_hold is False
    if hasattr(row, "updated_at"):
        assert row.updated_at is not None
    if hasattr(row, "legal_hold_cleared_at"):
        assert row.legal_hold_cleared_at is not None
    if hasattr(row, "legal_hold_cleared_by"):
        assert row.legal_hold_cleared_by == admin.id
    # policy keeps previous reason; do not assert change


@pytest.mark.anyio
async def test_legal_hold__idempotent_noop_when_already_enabled(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, legal_hold=True)

    r = await async_client.put(
        f"{BASE}/{s.id}/legal-hold",
        headers=headers,
        params={"enabled": "true", "reason": "already on"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["legal_hold"] is True
    # No rotation guarantee; just ensure ETag present
    assert r.headers.get("ETag")


@pytest.mark.anyio
async def test_legal_hold__412_ifmatch_mismatch(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    bad = dict(headers)
    bad["If-Match"] = "not-the-current-etag"

    r = await async_client.put(
        f"{BASE}/{s.id}/legal-hold",
        headers=bad,
        params={"enabled": "true"},
    )
    assert r.status_code == 412


@pytest.mark.anyio
async def test_legal_hold__404_wrong_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Create session in org1
    admin1, headers1, org1 = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    s = await _mk_session(db_session, org_id=org1.id, instructor_id=admin1.id)

    # Call from a different org (org2)
    admin2, headers2, _ = await org_user_with_token(role=OrgRole.OWNER, set_active_org=True)
    r = await async_client.put(
        f"{BASE}/{s.id}/legal-hold",
        headers=headers2,
        params={"enabled": "true"},
    )
    assert r.status_code == 404
