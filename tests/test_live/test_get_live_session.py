# tests/test_live/test_get_live_session.py

import pytest
from httpx import AsyncClient
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole, LiveSessionStatus
from app.db.models.organization import Organization
from app.db.models.live_sessions import LiveSession

BASE = "/api/v1/course/live/session"


# ----------------- helpers -----------------

def _utcnow_naive() -> datetime:
    """UTC now with no tzinfo, no micros (matches TIMESTAMP WITHOUT TIME ZONE)."""
    return datetime.now(timezone.utc).replace(microsecond=0)

def _to_naive_utc(dt: datetime | None) -> datetime | None:
    """Coerce any datetime to naive UTC (drop tzinfo)."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None, microsecond=0)
    return dt.replace(microsecond=0)

async def _ensure_org(db: AsyncSession) -> Organization:
    org = Organization(
        name=f"org-{uuid4().hex[:6]}",
        slug=f"org-{uuid4().hex[:6]}",
        is_active=True,
    )
    db.add(org)
    await db.commit()
    await db.refresh(org)
    return org

async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
    title="S1",
    start: datetime | None = None,
    end: datetime | None = None,
    status=LiveSessionStatus.SCHEDULED,
    is_deleted=False,
):
    start = _to_naive_utc(start) or (_utcnow_naive() + timedelta(hours=1))
    end = _to_naive_utc(end) or (start + timedelta(hours=1))
    s = LiveSession(
        title=title,
        organization_id=org_id,
        start_time=start,     # naive UTC → OK for TIMESTAMP WITHOUT TZ
        end_time=end,         # naive UTC → OK for TIMESTAMP WITHOUT TZ
        status=status,
        is_deleted=is_deleted,
    )
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


# ----------------- tests -----------------

@pytest.mark.anyio
async def test_get_session__200_happy_path(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    _, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id)

    r = await async_client.get(f"{BASE}/{s.id}", headers=headers)
    assert r.status_code == 200, r.text

    body = r.json()
    assert UUID(body["id"]) == s.id
    assert body["title"] == "S1"
    assert r.headers.get("ETag")
    assert r.headers.get("Last-Modified")


@pytest.mark.anyio
async def test_get_session__404_wrong_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    _, headers_a, org_a = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    org_b = await _ensure_org(db_session)
    s_b = await _mk_session(db_session, org_id=org_b.id)

    r = await async_client.get(f"{BASE}/{s_b.id}", headers=headers_a)
    assert r.status_code == 404
    assert "not found" in r.text.lower()


@pytest.mark.anyio
async def test_get_session__404_soft_deleted(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, is_deleted=True)

    r = await async_client.get(f"{BASE}/{s.id}", headers=headers)
    assert r.status_code == 404
    assert "not found" in r.text.lower()


@pytest.mark.anyio
async def test_get_session__304_if_none_match(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id)

    r1 = await async_client.get(f"{BASE}/{s.id}", headers=headers)
    assert r1.status_code == 200
    etag = r1.headers.get("ETag")
    assert etag

    r2 = await async_client.get(f"{BASE}/{s.id}", headers={**headers, "If-None-Match": etag})
    assert r2.status_code == 304
    assert r2.content in (b"", None)


@pytest.mark.anyio
async def test_get_session__304_if_modified_since_equal_or_later(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id)

    r1 = await async_client.get(f"{BASE}/{s.id}", headers=headers)
    assert r1.status_code == 200
    last_mod = r1.headers.get("Last-Modified")
    assert last_mod

    # Same timestamp → 304
    r2 = await async_client.get(f"{BASE}/{s.id}", headers={**headers, "If-Modified-Since": last_mod})
    assert r2.status_code == 304

    # Reusing same header again should also 304
    r3 = await async_client.get(f"{BASE}/{s.id}", headers={**headers, "If-Modified-Since": last_mod})
    assert r3.status_code == 304


@pytest.mark.anyio
async def test_get_session__200_if_modified_since_in_past_or_bad_header(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id)

    r_old = await async_client.get(
        f"{BASE}/{s.id}",
        headers={**headers, "If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"},
    )
    assert r_old.status_code == 200

    r_bad = await async_client.get(
        f"{BASE}/{s.id}", headers={**headers, "If-Modified-Since": "not-a-date"}
    )
    assert r_bad.status_code == 200


@pytest.mark.anyio
async def test_get_session__precedence_if_none_match_over_ims(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    ETag check should win over If-Modified-Since when both are present.
    """
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id)

    r1 = await async_client.get(f"{BASE}/{s.id}", headers=headers)
    assert r1.status_code == 200
    etag = r1.headers["ETag"]

    r2 = await async_client.get(
        f"{BASE}/{s.id}",
        headers={
            **headers,
            "If-None-Match": etag,
            "If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT",
        },
    )
    assert r2.status_code == 304
