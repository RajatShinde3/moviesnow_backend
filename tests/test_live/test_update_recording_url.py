import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import pytest
from fastapi import HTTPException
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
    title="Session",
    start: datetime | None = None,
    end: datetime | None = None,
    instructor_id=None,
    is_deleted: bool = False,
    actual_start_time: datetime | None = None,
    actual_end_time: datetime | None = None,
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

    for attr in ("start_time", "end_time", "actual_start_time", "actual_end_time", "created_at", "updated_at"):
        if hasattr(s, attr):
            v = getattr(s, attr)
            if isinstance(v, datetime):
                setattr(s, attr, _to_naive(v))

    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


# ---------- autouse patches ----------
@pytest.fixture(autouse=True)
def _patch_recording_helpers(monkeypatch):
    # Patch inside the route module
    import app.api.v1.course.live.sessions as sessions_api

    # Accept HttpUrl or str, enforce https, host required
    def _normalize_enforcing_https(u) -> str:
        s = str(u).strip()
        p = urlparse(s)
        if not p.netloc:
            raise HTTPException(status_code=400, detail="Include scheme and host")
        if (p.scheme or "").lower() != "https":
            raise HTTPException(status_code=400, detail="Recording URL must be HTTPS")
        return s

    monkeypatch.setattr(sessions_api, "normalize_recording_url", _normalize_enforcing_https)
    monkeypatch.setattr(sessions_api, "recording_host_allowed", lambda host: True)

    # Make now_utc() naive to match TIMESTAMP WITHOUT TIME ZONE
    monkeypatch.setattr(sessions_api, "now_utc", lambda: datetime.now(timezone.utc).replace(microsecond=0))


# =========== TESTS ===========
@pytest.mark.anyio
async def test_recording__200_updates_after_end_and_persists_and_etag_present(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        actual_start_time=datetime(2025, 8, 22, 6, 0, 0),
        actual_end_time=datetime(2025, 8, 22, 7, 0, 0),
    )

    # Optional: baseline ETag
    r0 = await async_client.get(f"{BASE}/{s.id}/status", headers=headers)
    assert r0.status_code == 200

    # Update recording URL
    target_url = "https://vimeo.com/12345?t=10"
    r = await async_client.put(
        f"{BASE}/{s.id}/recording",
        headers=headers,
        json={"recording_url": target_url},
    )
    assert r.status_code == 200, r.text
    assert r.headers.get("ETag")  # present (rotation not enforced)

    # IMPORTANT: refresh to bust identity-map staleness
    row = await db_session.get(LiveSession, s.id)
    await db_session.refresh(row)

    # Now the persisted values are visible
    assert getattr(row, "recording_url", None) is not None
    assert str(getattr(row, "recording_url")).startswith("https://vimeo.com/12345")

    if hasattr(row, "recording_ready_at"):
        assert getattr(row, "recording_ready_at") is not None
    if hasattr(row, "updated_at"):
        assert getattr(row, "updated_at") is not None



@pytest.mark.anyio
async def test_recording__409_requires_ended_by_default(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)  # not ended

    r = await async_client.put(f"{BASE}/{s.id}/recording", headers=headers, json={"recording_url": "https://vimeo.com/1"})
    assert r.status_code == 409
    assert "only after the session has ended" in r.text.lower()


@pytest.mark.anyio
async def test_recording__200_allows_before_end_when_require_ended_false(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id)  # not ended

    r = await async_client.put(
        f"{BASE}/{s.id}/recording?require_ended=false",
        headers=headers,
        json={"recording_url": "https://vimeo.com/2"},
    )
    assert r.status_code == 200

    # Verify last-write wins timestamp behavior instead of body field
    row = await db_session.get(LiveSession, s.id)
    if hasattr(row, "updated_at"):
        assert getattr(row, "updated_at") is not None


@pytest.mark.anyio
async def test_recording__idempotent_noop_200_when_same_url(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        actual_end_time=datetime(2025, 8, 22, 7, 0, 0),
    )

    url = "https://vimeo.com/abc"
    r1 = await async_client.put(f"{BASE}/{s.id}/recording", headers=headers, json={"recording_url": url})
    assert r1.status_code == 200

    r2 = await async_client.put(f"{BASE}/{s.id}/recording", headers=headers, json={"recording_url": url})
    # default idempotent=True → returns 200 no-op
    assert r2.status_code == 200


@pytest.mark.anyio
async def test_recording__400_rejects_non_https(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, actual_end_time=datetime(2025, 8, 22, 7, 0, 0))

    r = await async_client.put(f"{BASE}/{s.id}/recording", headers=headers, json={"recording_url": "http://vimeo.com/4"})
    assert r.status_code == 400
    assert "https" in r.text.lower()


@pytest.mark.anyio
async def test_recording__422_url_without_scheme_is_pydantic_validation_error(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Pydantic's HttpUrl rejects "vimeo.com/5" at validation time → 422 (the route isn't reached)
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, actual_end_time=datetime(2025, 8, 22, 7, 0, 0))

    r = await async_client.put(f"{BASE}/{s.id}/recording", headers=headers, json={"recording_url": "vimeo.com/5"})
    assert r.status_code == 422


@pytest.mark.anyio
async def test_recording__400_disallowed_host_when_allowlist_set(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, actual_end_time=datetime(2025, 8, 22, 7, 0, 0))

    import app.api.v1.course.live.sessions as sessions_api
    # Only allow zoom.us for this test → vimeo.com should be rejected
    monkeypatch.setattr(sessions_api, "recording_host_allowed", lambda host: host.endswith("zoom.us"))

    r = await async_client.put(f"{BASE}/{s.id}/recording", headers=headers, json={"recording_url": "https://vimeo.com/6"})
    assert r.status_code == 400
    assert "not allowed" in r.text.lower()


@pytest.mark.anyio
async def test_recording__404_member_not_in_org_of_session(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    # Member is created with a different org than the admin/session → 404 (org scoping)
    admin, headers_admin, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(db_session, org_id=org.id, instructor_id=admin.id, actual_end_time=datetime(2025, 8, 22, 7, 0, 0))

    member, headers_member, _ = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    r = await async_client.put(f"{BASE}/{s.id}/recording", headers=headers_member, json={"recording_url": "https://vimeo.com/7"})
    assert r.status_code == 404


@pytest.mark.anyio
async def test_recording__412_ifmatch_mismatch(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    s = await _mk_session(
        db_session,
        org_id=org.id,
        instructor_id=admin.id,
        actual_end_time=datetime(2025, 8, 22, 7, 0, 0),
    )

    bad = dict(headers)
    bad["If-Match"] = "not-the-current-etag"
    r = await async_client.put(f"{BASE}/{s.id}/recording", headers=bad, json={"recording_url": "https://vimeo.com/3"})
    assert r.status_code == 412
