# tests/test_live/test_force_purge_live_session.py
import uuid
from datetime import datetime, timezone, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.live_sessions import LiveSession
from app.db.models.live_session_attendance import LiveSessionAttendance
from app.db.models.live_session_feedback import LiveSessionFeedback
from app.db.models.session_access_log import SessionAccessLog
from app.schemas.enums import OrgRole

BASE = "/api/v1/course/live/session"


# ---------- tiny datetime helpers (DB stores naive UTC) ----------
def _naive_utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)

def _to_naive(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
    return dt.replace(microsecond=0)


# ---------- factory ----------
async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
    instructor_id=None,
    is_deleted: bool = False,
    start: datetime | None = None,
    end: datetime | None = None,
):
    start = _to_naive(start) or (_naive_utc_now() + timedelta(minutes=5))
    end = _to_naive(end) or (start + timedelta(hours=1))

    s = LiveSession(
        id=uuid.uuid4(),
        organization_id=org_id,
        title="Purge Me",
        start_time=start,
        end_time=end,
        is_deleted=is_deleted,
        instructor_id=instructor_id,
    )
    if hasattr(s, "created_at"):
        s.created_at = _naive_utc_now()
    if hasattr(s, "updated_at"):
        s.updated_at = _naive_utc_now()
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s

async def _soft_delete_session(db: AsyncSession, s: LiveSession):
    s.is_deleted = True
    if hasattr(s, "deleted_at"):
        s.deleted_at = _naive_utc_now()
    if hasattr(s, "updated_at"):
        s.updated_at = _naive_utc_now()
    await db.commit()
    await db.refresh(s)

async def _add_attendance(db: AsyncSession, *, session_id, user_id):
    # joined_at is stored as TIMESTAMP WITH TIME ZONE in some schemas; give aware → ORM will handle write.
    joined_aw = datetime(2025, 8, 22, 6, 0, 0, tzinfo=timezone.utc)
    row = LiveSessionAttendance(
        id=uuid.uuid4(),
        session_id=session_id,
        user_id=user_id,
        joined_at=joined_aw,
        attended_duration_minutes=10,
        is_present=True if hasattr(LiveSessionAttendance, "is_present") else None,
    )
    if hasattr(row, "created_at"):
        row.created_at = _naive_utc_now()
    if hasattr(row, "updated_at"):
        row.updated_at = _naive_utc_now()
    db.add(row)
    await db.commit()
    return row

async def _add_feedback(db: AsyncSession, *, session_id, user_id):
    row = LiveSessionFeedback(
        id=uuid.uuid4(),
        session_id=session_id,
        user_id=user_id,
        rating=5,
        tags=["ok"],
        is_deleted=False,
    )
    db.add(row)
    await db.commit()
    return row


async def _add_access_log(db: AsyncSession, *, org_id, session_id, user_id):
    import uuid

    # only include fields that actually exist on this schema
    fields = {
        "id": uuid.uuid4(),
        "session_id": session_id,
        "user_id": user_id,
    }
    # org column name varies across schemas: org_id vs organization_id
    if hasattr(SessionAccessLog, "org_id"):
        fields["org_id"] = org_id
    elif hasattr(SessionAccessLog, "organization_id"):
        fields["organization_id"] = org_id

    if hasattr(SessionAccessLog, "ip_address"):
        fields["ip_address"] = "127.0.0.1"
    if hasattr(SessionAccessLog, "user_agent"):
        fields["user_agent"] = "pytest"

    row = SessionAccessLog(**fields)

    # Use NAIVE timestamps for WITHOUT TIME ZONE columns
    naive_fixed = datetime(2025, 8, 22, 6, 0, 0)  # no tzinfo
    if hasattr(row, "accessed_at"):
        row.accessed_at = naive_fixed
    if hasattr(row, "created_at"):
        row.created_at = _naive_utc_now()  # your helper that returns naive utc
    if hasattr(row, "updated_at"):
        row.updated_at = _naive_utc_now()
    if hasattr(row, "is_deleted"):
        row.is_deleted = False

    db.add(row)
    await db.commit()
    return row


# ---------- async stubs for feature flag / external cleanup ----------
async def _allow_feature_flag(_db, _org_id):
    return True

async def _deny_feature_flag(_db, _org_id):
    return False

async def _cleanup_ok(org_id, session_id):
    return {"org_id": str(org_id), "session_id": str(session_id), "ok": True}

async def _cleanup_fail(org_id, session_id):
    raise RuntimeError("boom")


# =========================
#          TESTS
# =========================
@pytest.mark.anyio
async def test_purge__403_feature_flag_disabled(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    import app.api.v1.course.live.sessions as sessions_api
    monkeypatch.setattr(sessions_api, "force_purge_allowed", _deny_feature_flag)

    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, is_deleted=True)

    r = await async_client.delete(f"{BASE}/{s.id}/purge", headers=headers)
    assert r.status_code == 403, r.text


@pytest.mark.anyio
async def test_purge__400_requires_soft_delete_by_default(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    import app.api.v1.course.live.sessions as sessions_api
    monkeypatch.setattr(sessions_api, "force_purge_allowed", _allow_feature_flag)

    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, is_deleted=False)

    r = await async_client.delete(f"{BASE}/{s.id}/purge", headers=headers)
    assert r.status_code == 400, r.text
    # still exists
    assert await db_session.get(LiveSession, s.id) is not None


@pytest.mark.anyio
async def test_purge__200_allows_direct_purge_when_require_soft_deleted_false(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    import app.api.v1.course.live.sessions as sessions_api
    monkeypatch.setattr(sessions_api, "force_purge_allowed", _allow_feature_flag)

    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, is_deleted=False)

    r = await async_client.delete(
        f"{BASE}/{s.id}/purge?require_soft_deleted=false", headers=headers
    )
    assert r.status_code == 200, r.text
    # parent gone
    assert await db_session.get(LiveSession, s.id) is None


@pytest.mark.anyio
async def test_purge__423_blocked_by_legal_hold_without_override_and_200_with_override(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    import app.api.v1.course.live.sessions as sessions_api
    monkeypatch.setattr(sessions_api, "force_purge_allowed", _allow_feature_flag)

    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, is_deleted=True)

    # set legal hold on the session
    s.legal_hold = True
    await db_session.commit()

    r1 = await async_client.delete(f"{BASE}/{s.id}/purge", headers=headers)
    assert r1.status_code == 423, r1.text
    assert await db_session.get(LiveSession, s.id) is not None  # not deleted

    r2 = await async_client.delete(
        f"{BASE}/{s.id}/purge?override_legal_hold=true", headers=headers
    )
    assert r2.status_code == 200, r2.text
    assert await db_session.get(LiveSession, s.id) is None


@pytest.mark.anyio
async def test_purge__412_ifmatch_mismatch_preserves_row(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    import app.api.v1.course.live.sessions as sessions_api
    monkeypatch.setattr(sessions_api, "force_purge_allowed", _allow_feature_flag)

    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, is_deleted=True)

    # send bogus If-Match → expect 412
    r = await async_client.delete(
        f"{BASE}/{s.id}/purge",
        headers={**headers, "If-Match": "bogus"},
    )
    assert r.status_code == 412, r.text
    # still exists
    assert await db_session.get(LiveSession, s.id) is not None


@pytest.mark.anyio
async def test_purge__200_deletes_children_and_calls_external_cleanup(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    import app.api.v1.course.live.sessions as sessions_api
    monkeypatch.setattr(sessions_api, "force_purge_allowed", _allow_feature_flag)
    # stub external cleanup (called, and result returned)
    called = {"n": 0, "args": None}
    async def _cleanup(org_id, session_id):
        called["n"] += 1
        called["args"] = (org_id, session_id)
        return {"ok": True}
    monkeypatch.setattr(sessions_api, "cleanup_external_artifacts", _cleanup)

    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, is_deleted=True)

    # add child data
    await _add_attendance(db_session, session_id=s.id, user_id=admin.id)
    await _add_feedback(db_session, session_id=s.id, user_id=admin.id)
    await _add_access_log(db_session, org_id=org.id, session_id=s.id, user_id=admin.id)

    r = await async_client.delete(f"{BASE}/{s.id}/purge", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["deleted_children"]["attendance"] >= 1
    assert body["deleted_children"]["feedback"] >= 1
    assert body["deleted_children"]["access_logs"] >= 1
    assert body.get("external_cleanup") is not None

    # parent + children gone
    assert await db_session.get(LiveSession, s.id) is None
    (att_count,) = (await db_session.execute(select(func.count(LiveSessionAttendance.id)))).one()
    (fb_count,) = (await db_session.execute(select(func.count(LiveSessionFeedback.id)))).one()
    (log_count,) = (await db_session.execute(select(func.count(SessionAccessLog.id)))).one()
    assert att_count == 0 and fb_count == 0 and log_count == 0

    # external called once with org+session
    assert called["n"] == 1 and called["args"][0] == org.id and called["args"][1] == s.id


@pytest.mark.anyio
async def test_purge__200_external_cleanup_failure_is_non_fatal(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    import app.api.v1.course.live.sessions as sessions_api
    monkeypatch.setattr(sessions_api, "force_purge_allowed", _allow_feature_flag)
    monkeypatch.setattr(sessions_api, "cleanup_external_artifacts", _cleanup_fail)

    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, is_deleted=True)

    r = await async_client.delete(f"{BASE}/{s.id}/purge", headers=headers)
    assert r.status_code == 200, r.text
    assert await db_session.get(LiveSession, s.id) is None


@pytest.mark.anyio
async def test_purge__404_wrong_org_returns_not_found(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    import app.api.v1.course.live.sessions as sessions_api
    monkeypatch.setattr(sessions_api, "force_purge_allowed", _allow_feature_flag)

    # session in org1
    admin1, headers1, org1 = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s1 = await _mk_session(db_session, org_id=org1.id, instructor_id=admin1.id, is_deleted=True)

    # call from a different org
    _, headers2, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.delete(f"{BASE}/{s1.id}/purge", headers=headers2)
    assert r.status_code == 404, r.text
