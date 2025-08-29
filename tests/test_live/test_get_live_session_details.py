# tests/test_live/test_get_live_session_details.py
import uuid
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime, parsedate_to_datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import LiveSession
from app.schemas.enums import OrgRole

BASE = "/api/v1/course/live/session"


# ---------- small helpers ----------

def _naive_utc_now():
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
    instructor_id=None,
    title="Session",
    is_deleted: bool = False,
    start: datetime | None = None,
    end: datetime | None = None,
    created_at: datetime | None = None,
    updated_at: datetime | None = None,
):
    # normalize inputs to NAIVE UTC (seconds)
    start = _to_naive(start) or (_naive_utc_now() + timedelta(minutes=10))
    end = _to_naive(end) or (start + timedelta(hours=1))
    created_at = _to_naive(created_at) or _naive_utc_now()
    updated_at = _to_naive(updated_at) or created_at

    s = LiveSession(
        id=uuid.uuid4(),
        title=title,
        organization_id=org_id,
        start_time=start,
        end_time=end,
        is_deleted=is_deleted,
        instructor_id=instructor_id,
    )

    # optional columns on some schemas
    if hasattr(s, "created_at"):
        s.created_at = created_at
    if hasattr(s, "updated_at"):
        s.updated_at = updated_at

    # force all datetime fields on the model to be NAIVE before commit
    for attr in ("start_time", "end_time", "created_at", "updated_at"):
        if hasattr(s, attr):
            val = getattr(s, attr)
            if isinstance(val, datetime):
                setattr(s, attr, _to_naive(val))

    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s

def _httpdate(dt: datetime) -> str:
    """Format an aware UTC datetime as HTTP-date (RFC 7231)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    # second precision
    dt = dt.replace(microsecond=0)
    return format_datetime(dt)  # e.g., 'Fri, 22 Aug 2025 07:00:00 GMT'


# =========================
#           TESTS
# =========================

@pytest.mark.anyio
async def test_get__200_returns_session_and_headers(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # choose a stable last-modified source
    created = datetime(2025, 8, 22, 7, 0, 0)  # naive
    updated = datetime(2025, 8, 22, 7, 5, 0)  # naive
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        created_at=created,
        updated_at=updated,
    )

    r = await async_client.get(f"{BASE}/{s.id}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == str(s.id)

    # Always expect ETag
    assert r.headers.get("ETag")

    # Last-Modified only if model exposes created_at/updated_at (route sets it when available)
    if hasattr(LiveSession, "updated_at") or hasattr(LiveSession, "created_at"):
        assert r.headers.get("Last-Modified")


@pytest.mark.anyio
async def test_get__404_wrong_org_and_soft_deleted(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Create in org1
    admin1, headers1, org1 = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s1 = await _mk_session(db_session, org_id=org1.id, instructor_id=admin1.id)

    # Call as org2 → 404 (org scoping)
    _, headers2, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r_wrong_org = await async_client.get(f"{BASE}/{s1.id}", headers=headers2)
    assert r_wrong_org.status_code == 404

    # Soft-deleted → 404 even for same org
    s2 = await _mk_session(db_session, org_id=org1.id, instructor_id=admin1.id, is_deleted=True)
    r_deleted = await async_client.get(f"{BASE}/{s2.id}", headers=headers1)
    assert r_deleted.status_code == 404


@pytest.mark.anyio
async def test_get__304_if_none_match_matches(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    r1 = await async_client.get(f"{BASE}/{s.id}", headers=headers)
    assert r1.status_code == 200
    etag = r1.headers.get("ETag")
    assert etag

    # second call with If-None-Match → 304
    h2 = dict(headers)
    h2["If-None-Match"] = etag
    r2 = await async_client.get(f"{BASE}/{s.id}", headers=h2)
    assert r2.status_code == 304


@pytest.mark.anyio
async def test_get__200_when_if_none_match_is_different(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    h = dict(headers)
    h["If-None-Match"] = "bogus-etag"
    r = await async_client.get(f"{BASE}/{s.id}", headers=h)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_get__304_if_modified_since_when_not_modified(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    If-Modified-Since uses last_modified (updated_at or created_at) at second precision.
    When IMS >= last_modified → 304
    """
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Set a deterministic last_modified
    created = datetime(2025, 8, 22, 7, 0, 0)
    updated = datetime(2025, 8, 22, 7, 10, 0)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        created_at=created,
        updated_at=updated,
    )

    # server will choose updated_at if present; otherwise created_at
    last_mod = updated if hasattr(LiveSession, "updated_at") else created
    ims = _httpdate(last_mod)  # equal → not modified

    h = dict(headers)
    h["If-Modified-Since"] = ims
    r = await async_client.get(f"{BASE}/{s.id}", headers=h)
    assert r.status_code == 304


@pytest.mark.anyio
async def test_get__200_if_modified_since_before_last_mod(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    created = datetime(2025, 8, 22, 7, 0, 0)
    updated = datetime(2025, 8, 22, 7, 10, 0)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        created_at=created,
        updated_at=updated,
    )

    last_mod = updated if hasattr(LiveSession, "updated_at") else created
    ims = _httpdate(last_mod - timedelta(seconds=1))  # older → should be treated as "modified"

    print(f"\nDEBUG expected_last_mod(local): {last_mod.isoformat()}  |  IMS sent: {ims}")

    h = dict(headers)
    h["If-Modified-Since"] = ims
    r = await async_client.get(f"{BASE}/{s.id}", headers=h)

    lm_hdr = r.headers.get("Last-Modified")
    etag = r.headers.get("ETag")
    print(f"DEBUG status={r.status_code}  ETag={etag}  Last-Modified(header)={lm_hdr}")

    # Parse dates and show the exact comparison that should drive 200 vs 304
    try:
        ims_dt = parsedate_to_datetime(ims) if ims else None
        lm_dt = parsedate_to_datetime(lm_hdr) if lm_hdr else None
        print(f"DEBUG parsed ims_dt={ims_dt}  lm_dt={lm_dt}")
        if ims_dt and lm_dt:
            ims_sec = ims_dt.replace(microsecond=0)
            lm_sec = lm_dt.replace(microsecond=0)
            print(f"DEBUG second-precision ims={ims_sec}  lm={lm_sec}  ims>=lm? {ims_sec >= lm_sec}")
    except Exception as e:
        print(f"DEBUG date-parse error: {e!r}")

    if r.status_code != 200:
        # Show body to understand 304/other responses
        print(f"DEBUG body: {r.text}")

    assert r.status_code == 200



@pytest.mark.anyio
async def test_get__ignores_bad_if_modified_since_format(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    h = dict(headers)
    h["If-Modified-Since"] = "not-a-date"
    r = await async_client.get(f"{BASE}/{s.id}", headers=h)
    # Bad IMS should not block the response
    assert r.status_code == 200


@pytest.mark.anyio
async def test_get__etag_precedence_over_if_modified_since(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Route checks If-None-Match first.
    If ETag matches → 304 even if IMS would otherwise yield 200.
    """
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)

    r1 = await async_client.get(f"{BASE}/{s.id}", headers=headers)
    etag = r1.headers.get("ETag")
    assert etag

    # Both headers present; matching ETag should win → 304
    h = dict(headers)
    h["If-None-Match"] = etag
    h["If-Modified-Since"] = _httpdate(_naive_utc_now().replace(tzinfo=timezone.utc))  # arbitrary
    r2 = await async_client.get(f"{BASE}/{s.id}", headers=h)
    assert r2.status_code == 304
