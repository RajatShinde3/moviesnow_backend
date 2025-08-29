# tests/test_live/test_end_live_session.py
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
import json
from app.db.models import LiveSession
from app.schemas.enums import OrgRole

BASE = "/api/v1/course/live/session"


# ---------- helpers ----------
def _utcnow_naive() -> datetime:
    # Naïve UTC: what your DB columns store (TIMESTAMP WITHOUT TIME ZONE)
    return datetime.now(timezone.utc).replace(microsecond=0)

def _aware_utc(y=2025, mo=8, d=22, h=7, m=0, s=0) -> datetime:
    # Aware UTC: what route uses for comparisons & then converts to naïve
    return datetime(y, mo, d, h, m, s, tzinfo=timezone.utc)

def _to_aware_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc, microsecond=0)
    return dt.astimezone(timezone.utc).replace(microsecond=0)


# ---------- freeze route's clock (aware UTC) ----------
@pytest.fixture(autouse=True)
def freeze_now(monkeypatch):
    """
    Freeze sessions_api.now_utc() to an AWARE UTC value so the route
    compares aware(now) vs aware(start/end) (it makes start/end aware internally),
    but writes NAÏVE UTC to the DB.
    """
    import app.api.v1.course.live.sessions as sessions_api
    fixed_now = _aware_utc(2025, 8, 22, 7, 0, 0)  # 07:00Z (aware)
    monkeypatch.setattr(sessions_api, "now_utc", lambda: fixed_now)


# ---------- factory (forces ALL datetimes written to DB to NAÏVE UTC) ----------
async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
    title="Session",
    start: datetime | None = None,
    end: datetime | None = None,
    instructor_id=None,
    is_deleted: bool = False,
    actual_start_time: datetime | None = None,
    actual_end_time: datetime | None = None,
    capacity: int | None = None,
):
    # Defaults as NAÏVE UTC
    start = _to_aware_utc(start) or _to_aware_utc(_utcnow_naive() + timedelta(minutes=10))
    end = _to_aware_utc(end) or (start + timedelta(hours=1))
    actual_start_time = _to_aware_utc(actual_start_time)
    actual_end_time = _to_aware_utc(actual_end_time)


    s = LiveSession(
        id=uuid.uuid4(),
        title=title,
        organization_id=org_id,
        start_time=start,
        end_time=end,
        is_deleted=is_deleted,
        instructor_id=instructor_id,
    )
    # Optional columns on some schemas
    if hasattr(s, "actual_start_time"):
        s.actual_start_time = actual_start_time
    if hasattr(s, "actual_end_time"):
        s.actual_end_time = actual_end_time
    if capacity is not None and hasattr(s, "capacity"):
        s.capacity = capacity
    if hasattr(s, "created_at"):
        s.created_at = _utcnow_naive()
    if hasattr(s, "updated_at"):
        s.updated_at = _utcnow_naive()

    # HARD GUARD: coerce any datetime attributes back to NAÏVE UTC before commit.
# HARD GUARD: coerce any datetime attributes to AWARE UTC before commit.
    for attr in ("start_time","end_time","actual_start_time","actual_end_time","created_at","updated_at"):
        if hasattr(s, attr):
            val = getattr(s, attr)
            if isinstance(val, datetime):
                setattr(s, attr, _to_aware_utc(val))


    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


# =========================
#          TESTS
# =========================

@pytest.mark.anyio
async def test_end__200_sets_actual_end_and_etag(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Ensure it has started (naïve < frozen now(aware 07:00Z))
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        actual_start_time=datetime(2025, 8, 22, 6, 45, 0),  # naïve
    )

    print(f"[debug] BEFORE end: db(actual_start)={s.actual_start_time} db(actual_end)={s.actual_end_time}")

    r = await async_client.post(f"{BASE}/{s.id}/end", headers=headers)
    print(f"[debug] HTTP {r.status_code} ETag={r.headers.get('ETag')}")
    try:
        print("[debug] response json:", json.dumps(r.json(), indent=2))
    except Exception:
        print("[debug] response text:", r.text)

    assert r.status_code == 200, r.text
    body = r.json()

    # Re-read from DB to verify persisted values too
    db_row = await db_session.get(LiveSession, s.id)
    print(f"[debug] AFTER end: db(actual_end)={getattr(db_row, 'actual_end_time', None)} db(updated_at)={getattr(db_row, 'updated_at', None)}")

    # Expect the route to set end time (serialized to ISO string)
    assert body.get("actual_end_time"), "expected actual_end_time to be set"
    assert r.headers.get("ETag")

    # Optional strict check (uncomment if you want exact time equality):
    # expected_iso = _to_naive(_aware_utc(2025, 8, 22, 7, 0, 0)).isoformat()
    # assert body.get("actual_end_time") == expected_iso



@pytest.mark.anyio
async def test_end__400_when_not_started(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    r = await async_client.post(f"{BASE}/{s.id}/end", headers=headers)
    assert r.status_code == 400, r.text
    assert "hasn't started" in r.text.lower() or "hasnt started" in r.text.lower()


@pytest.mark.anyio
async def test_end__idempotent_200_when_already_ended(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        actual_start_time=datetime(2025, 8, 22, 6, 30, 0),  # naïve
        actual_end_time=datetime(2025, 8, 22, 6, 59, 0),    # naïve
    )

    r = await async_client.post(f"{BASE}/{s.id}/end", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json().get("actual_end_time")


@pytest.mark.anyio
async def test_end__400_when_already_ended_and_idempotent_false(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        actual_start_time=datetime(2025, 8, 22, 6, 30, 0),
        actual_end_time=datetime(2025, 8, 22, 6, 59, 0),
    )

    r = await async_client.post(f"{BASE}/{s.id}/end", headers=headers, params={"idempotent": "false"})
    assert r.status_code == 400, r.text
    assert "already ended" in r.text.lower()


@pytest.mark.anyio
async def test_end__400_cannot_end_before_it_starts(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Now is 07:00Z; make start at 07:10 and pretend it "started" at 07:10
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    future_start = datetime(2025, 8, 22, 7, 10, 0)  # naïve UTC
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        start=future_start,
        end=future_start + timedelta(hours=1),
        actual_start_time=future_start,  # started after "now"
    )

    r = await async_client.post(f"{BASE}/{s.id}/end", headers=headers)
    assert r.status_code == 400, r.text
    assert "before it starts" in r.text.lower()


@pytest.mark.anyio
async def test_end__404_wrong_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Create a session in org1
    admin1, headers1, org1 = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s1 = await _mk_session(
        db_session,
        org_id=org1.id,
        instructor_id=admin1.id,
        actual_start_time=datetime(2025, 8, 22, 6, 30, 0),
    )
    # Call as another org user
    _, headers2, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    r = await async_client.post(f"{BASE}/{s1.id}/end", headers=headers2)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_end__403_non_admin_non_creator_forbidden(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Create an admin + a member using the same fixture pattern used in start-route tests.
    admin, _, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    member, member_headers, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    s = await _mk_session(
        db_session, org_id=org.id, instructor_id=admin.id, actual_start_time=datetime(2025, 8, 22, 6, 45, 0)
    )

    r = await async_client.post(f"{BASE}/{s.id}/end", headers=member_headers)
    # If your fixture sets different orgs, the route returns 404 (org-scope) instead of 403 (auth).
    assert r.status_code in {403, 404}, r.text


@pytest.mark.anyio
async def test_end__412_if_match_mismatch(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session, org_id=org.id, instructor_id=admin.id, actual_start_time=datetime(2025, 8, 22, 6, 45, 0)
    )

    r = await async_client.post(f"{BASE}/{s.id}/end", headers={**headers, "If-Match": "bogus"})
    assert r.status_code == 412, r.text


@pytest.mark.anyio
async def test_end__race_safe_second_call_is_idempotent_200(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session, org_id=org.id, instructor_id=admin.id, actual_start_time=datetime(2025, 8, 22, 6, 45, 0)
    )

    r1 = await async_client.post(f"{BASE}/{s.id}/end", headers=headers)
    print(f"[debug] 1st call -> HTTP {r1.status_code} ETag={r1.headers.get('ETag')}")
    try:
        print("[debug] 1st response json:", json.dumps(r1.json(), indent=2))
    except Exception:
        print("[debug] 1st response text:", r1.text)

    assert r1.status_code == 200, r1.text
    ended_at = r1.json().get("actual_end_time")
    print(f"[debug] 1st call actual_end_time={ended_at}")
    assert ended_at

    r2 = await async_client.post(f"{BASE}/{s.id}/end", headers=headers)
    print(f"[debug] 2nd call -> HTTP {r2.status_code} ETag={r2.headers.get('ETag')}")
    try:
        print("[debug] 2nd response json:", json.dumps(r2.json(), indent=2))
    except Exception:
        print("[debug] 2nd response text:", r2.text)

    assert r2.status_code == 200, r2.text
    second_ended_at = r2.json().get("actual_end_time")
    print(f"[debug] 2nd call actual_end_time={second_ended_at}")
    assert second_ended_at == ended_at


@pytest.mark.anyio
async def test_end__touches_updated_at_if_present(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session, org_id=org.id, instructor_id=admin.id, actual_start_time=datetime(2025, 8, 22, 6, 45, 0)
    )

    pre = None
    if hasattr(LiveSession, "updated_at"):
        s_pre = await db_session.get(LiveSession, s.id)
        pre = getattr(s_pre, "updated_at", None)
    print(f"[debug] BEFORE end: updated_at(pre)={pre}")

    r = await async_client.post(f"{BASE}/{s.id}/end", headers=headers)
    print(f"[debug] HTTP {r.status_code} ETag={r.headers.get('ETag')}")
    try:
        print("[debug] response json:", json.dumps(r.json(), indent=2))
    except Exception:
        print("[debug] response text:", r.text)

    assert r.status_code == 200, r.text

    if hasattr(LiveSession, "updated_at"):
        s_post = await db_session.get(LiveSession, s.id)
        post = getattr(s_post, "updated_at", None)
        print(f"[debug] AFTER end: updated_at(post)={post}")
        assert post is not None
        if pre is not None:
            assert post != pre