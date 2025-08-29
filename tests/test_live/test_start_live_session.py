# tests/test_live/test_start_live_session.py
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

def _aware_utc(y=2025, mo=8, d=22, h=7, m=0, s=0) -> datetime:
    return datetime(y, mo, d, h, m, s, tzinfo=timezone.utc)

def _to_naive(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
    return dt.replace(microsecond=0)


# ---------- freeze route's clock (aware UTC) ----------
@pytest.fixture(autouse=True)
def freeze_now(monkeypatch):
    """
    Freeze sessions_api.now_utc() to an AWARE UTC value so the route
    compares aware(now) vs aware(start/end) (it makes start/end aware internally).
    """
    import app.api.v1.course.live.sessions as sessions_api
    fixed_now = _aware_utc(2025, 8, 22, 7, 0, 0)
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

    # HARD GUARD: coerce any datetime attributes that might have been
    # touched by model defaults/listeners back to NAÏVE UTC before commit.
    for attr in (
        "start_time",
        "end_time",
        "actual_start_time",
        "actual_end_time",
        "created_at",
        "updated_at",
    ):
        if hasattr(s, attr):
            val = getattr(s, attr)
            if isinstance(val, datetime):
                setattr(s, attr, _to_naive(val))

    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


# =========================
#          TESTS
# =========================

@pytest.mark.anyio
async def test_start__200_sets_actual_start_and_etag(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    r = await async_client.post(f"{BASE}/{s.id}/start", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("actual_start_time"), "expected actual_start_time to be set"
    assert r.headers.get("ETag")


@pytest.mark.anyio
async def test_start__403_before_scheduled_when_allow_early_false(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    def _iso(dt: datetime | None) -> str:
        if not dt:
            return "None"
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()

    def _parse_iso_z(s: str | None) -> datetime | None:
        if not s:
            return None
        # Body uses ISO 8601 with trailing Z → normalize for fromisoformat
        return datetime.fromisoformat(s.replace("Z", "+00:00"))

    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # future (NAÏVE); route should convert to aware UTC before comparing to aware now_utc()
    future = datetime(2025, 8, 22, 9, 0, 0)  # naïve UTC
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        start=future,
        end=future + timedelta(hours=1),
    )

    # --- DEBUG: what we're sending and environment time context ---
    try:
        local_off = datetime.now().astimezone().utcoffset()
    except Exception:
        local_off = None
    print("\nDEBUG start__403_before_scheduled_when_allow_early_false")
    print(f"DEBUG local offset: {local_off}")
    print(f"DEBUG future (naive, intended UTC): {future.isoformat()}")
    print(f"DEBUG created session id: {s.id}")

    # Hit the route with allow_early=false
    r = await async_client.post(f"{BASE}/{s.id}/start", headers=headers, params={"allow_early": "false"})

    # --- DEBUG: response inspection ---
    print(f"DEBUG response.status={r.status_code}")
    print(f"DEBUG response.headers={{'ETag': {r.headers.get('ETag')!r}}}")
    body_txt = r.text or ""
    print(f"DEBUG raw body: {body_txt[:500]}")

    # Try to parse JSON body for time fields (even if status is 200)
    try:
        body = r.json()
    except Exception:
        body = {}

    st = _parse_iso_z(body.get("start_time"))
    et = _parse_iso_z(body.get("end_time"))
    ast = _parse_iso_z(body.get("actual_start_time"))
    aet = _parse_iso_z(body.get("actual_end_time"))

    print(f"DEBUG parsed.start_time={_iso(st)}  end_time={_iso(et)}")
    print(f"DEBUG parsed.actual_start_time={_iso(ast)}  actual_end_time={_iso(aet)}")

    # If the route incorrectly allowed a start, we’ll see actual_start_time set.
    # Keeping the original asserts:
    assert r.status_code == 403, r.text
    assert "before scheduled start_time" in r.text



@pytest.mark.anyio
async def test_start__idempotent_200_when_already_started(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        actual_start_time=datetime(2025, 8, 22, 6, 50, 0),  # naïve
    )

    r = await async_client.post(f"{BASE}/{s.id}/start", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json().get("actual_start_time")


@pytest.mark.anyio
async def test_start__400_when_already_started_and_idempotent_false(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        actual_start_time=datetime(2025, 8, 22, 6, 59, 0),
    )

    r = await async_client.post(f"{BASE}/{s.id}/start", headers=headers, params={"idempotent": "false"})
    assert r.status_code == 400, r.text
    assert "already started" in r.text.lower()


@pytest.mark.anyio
async def test_start__409_if_already_ended(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        actual_end_time=datetime(2025, 8, 22, 6, 0, 0),
    )

    r = await async_client.post(f"{BASE}/{s.id}/start", headers=headers)
    assert r.status_code == 409, r.text
    assert "already ended" in r.text.lower()


@pytest.mark.anyio
async def test_start__404_wrong_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # session in org1
    admin1, headers1, org1 = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s1 = await _mk_session(db_session, org_id=org1.id, instructor_id=admin1.id)
    # caller from another org
    _, headers2, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    r = await async_client.post(f"{BASE}/{s1.id}/start", headers=headers2)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_start__403_non_admin_non_creator_forbidden(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Depending on the fixture, the second user may land in a different org.
    # If same org → 403 (forbidden). If different org → 404 (not found).
    admin, _, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    member, member_headers, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    r = await async_client.post(f"{BASE}/{s.id}/start", headers=member_headers)
    assert r.status_code in (403, 404), r.text


@pytest.mark.anyio
async def test_start__412_if_match_mismatch(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    r = await async_client.post(f"{BASE}/{s.id}/start", headers={**headers, "If-Match": "bogus"})
    assert r.status_code == 412, r.text


@pytest.mark.anyio
async def test_start__race_safe_second_call_is_idempotent_200(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    r1 = await async_client.post(f"{BASE}/{s.id}/start", headers=headers)
    assert r1.status_code == 200, r1.text
    started_at = r1.json().get("actual_start_time")
    assert started_at

    r2 = await async_client.post(f"{BASE}/{s.id}/start", headers=headers)
    assert r2.status_code == 200, r2.text
    assert r2.json().get("actual_start_time") == started_at


@pytest.mark.anyio
async def test_start__touches_updated_at_if_present(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    pre = None
    if hasattr(LiveSession, "updated_at"):
        s = await db_session.get(LiveSession, s.id)
        pre = getattr(s, "updated_at", None)

    r = await async_client.post(f"{BASE}/{s.id}/start", headers=headers)
    assert r.status_code == 200, r.text

    if hasattr(LiveSession, "updated_at"):
        s2 = await db_session.get(LiveSession, s.id)
        post = getattr(s2, "updated_at", None)
        assert post is not None
        if pre is not None:
            assert post != pre
