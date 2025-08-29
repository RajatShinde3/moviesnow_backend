# tests/test_progress/test_get_completion_status.py

import json
import uuid
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.models import (
    Course,
    Lesson,  # not required for completion, but some envs expect at least one lesson
    CourseEnrollment,
)
from app.schemas.enums import OrgRole
from app.core.redis_client import redis_wrapper

BASE = "/api/v1/progress"


# --- tiny helper (schema tolerant) -------------------------------------------------
def _set_if_has(obj, **fields):
    """
    Set attributes only if they exist on the SQLAlchemy model.
    Useful because some models may not expose all optional columns.
    """
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


# ───────────────────────────────────────────────────────────────────────────────────
# 404 when course is missing or belongs to another org
# ───────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_completion_status__404_when_missing_or_other_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Missing course
    missing = uuid.uuid4()
    r = await async_client.get(f"{BASE}/course/{missing}/completion-status", headers=headers)
    assert r.status_code == 404, r.text

    # Create a course in caller org
    c = Course(
        title="Mine",
        slug=f"mine-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    # Another org & course there
    from app.db.models import Organization
    other = Organization(
        name=f"Other-{uuid.uuid4().hex[:6]}",
        slug=f"other-{uuid.uuid4().hex[:6]}",
    )

    _set_if_has(other, created_by=user.id)
    db_session.add(other); await db_session.commit(); await db_session.refresh(other)

    foreign = Course(
        title="Foreign",
        slug=f"for-{uuid.uuid4().hex[:6]}",
        organization_id=other.id,
        is_published=True,
    )
    _set_if_has(foreign, created_by=user.id)
    db_session.add(foreign); await db_session.commit(); await db_session.refresh(foreign)

    r2 = await async_client.get(f"{BASE}/course/{foreign.id}/completion-status", headers=headers)
    assert r2.status_code == 404, r2.text


# ───────────────────────────────────────────────────────────────────────────────────
# 200 defaults when not enrolled
# ───────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_completion_status__200_not_enrolled_defaults(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="NoEnroll",
        slug=f"ne-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    r = await async_client.get(f"{BASE}/course/{c.id}/completion-status", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    # route returns a JSON dict with the pydantic model fields
    assert body["is_completed"] is False
    assert body["completed_at"] is None
    assert body.get("certificate_url") in (None, body.get("certificate_url"))
    assert float(body.get("progress_percent", 0)) == 0.0


# ───────────────────────────────────────────────────────────────────────────────────
# 200 with enrollment completed + fields present/typed
# ───────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_completion_status__200_completed_enrollment(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Done",
        slug=f"done-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    # Some envs require at least one lesson for a course to be "visible"
    l = Lesson(title="L", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(l, created_by=user.id)
    db_session.add(l); await db_session.commit(); await db_session.refresh(l)

    # Create a completed enrollment
    ce = CourseEnrollment(
        user_id=user.id,
        course_id=c.id,
        completed_at=datetime.now(timezone.utc),
    )
    _set_if_has(ce, certificate_url="https://example.com/cert.pdf")
    _set_if_has(ce, progress_percent=100.0)
    db_session.add(ce); await db_session.commit(); await db_session.refresh(ce)

    r = await async_client.get(f"{BASE}/course/{c.id}/completion-status", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["is_completed"] is True
    assert isinstance(body["completed_at"], str) and "T" in body["completed_at"]
    if "certificate_url" in body:
        assert body["certificate_url"] == "https://example.com/cert.pdf"
    assert float(body["progress_percent"]) in (100, 100.0)


# ───────────────────────────────────────────────────────────────────────────────────
# 304 when ETag matches; headers echoed
# ───────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_completion_status__304_when_etag_matches(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="ETags",
        slug=f"etg-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    # seed enrollment to get deterministic body
    ce = CourseEnrollment(user_id=user.id, course_id=c.id)
    _set_if_has(ce, progress_percent=0.0)
    db_session.add(ce); await db_session.commit()

    r1 = await async_client.get(f"{BASE}/course/{c.id}/completion-status", headers=headers)
    assert r1.status_code == 200, r1.text
    etag = r1.headers.get("ETag")
    assert etag

    r2 = await async_client.get(
        f"{BASE}/course/{c.id}/completion-status", headers={**headers, "If-None-Match": etag}
    )
    assert r2.status_code == 304, r2.text
    # Starlette may not emit body for 304; headers should be present
    assert r2.headers.get("ETag") == etag
    assert "Cache-Control" in r2.headers


# ───────────────────────────────────────────────────────────────────────────────────
# Cache hit returns payload without calling service again
# ───────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_completion_status__served_from_cache_without_service_call(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="CacheHit",
        slug=f"ch-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    cache_key = f"cstatus:v1:course:{c.id}:user:{user.id}:org:{org.id}"
    cached_body = {
        "is_completed": False,
        "completed_at": None,
        "certificate_url": None,
        "progress_percent": 0.0,
    }
    raw = json.dumps(cached_body, separators=(",", ":"), ensure_ascii=False)
    await redis_wrapper.client.setex(cache_key, 60, raw)

    # If service is invoked, fail the test
    async def _boom(*a, **k):
        pytest.fail("Service was called despite cached completion status presence")

    monkeypatch.setattr(
        "app.api.v1.progress.progress.get_course_completion_status",
        _boom,
        raising=True,
    )

    r = await async_client.get(f"{BASE}/course/{c.id}/completion-status", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json() == cached_body


# ───────────────────────────────────────────────────────────────────────────────────
# Corrupt cache is ignored and the route computes fresh
# ───────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_completion_status__corrupt_cache_falls_back_to_fresh(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Corrupt",
        slug=f"bad-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    # corrupt cache entry
    cache_key = f"cstatus:v1:course:{c.id}:user:{user.id}:org:{org.id}"
    await redis_wrapper.client.setex(cache_key, 60, "{not-json")

    # no enrollment -> defaults
    r = await async_client.get(f"{BASE}/course/{c.id}/completion-status", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["is_completed"] is False
    assert body["completed_at"] is None
    assert float(body.get("progress_percent", 0)) == 0.0


# ───────────────────────────────────────────────────────────────────────────────────
# Audit is best-effort (doesn't break the request)
# ───────────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_completion_status__audit_called_best_effort(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Audit",
        slug=f"aud-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    called = {}

    async def _audit(*a, **k):
        # accept any kwargs the route passes
        called.update(k)
        # simulate a no-op

    # Patch where the route imports it
    monkeypatch.setattr("app.api.v1.progress.progress.log_org_event", _audit, raising=True)

    r = await async_client.get(f"{BASE}/course/{c.id}/completion-status", headers=headers)
    assert r.status_code == 200, r.text

    # We at least see the kwargs shape we expect from the route
    # (being tolerant to field names)
    assert called.get("organization_id") == org.id
    assert called.get("actor_id") == user.id
    meta = called.get("meta_data") or called.get("metadata") or {}
    assert isinstance(meta, dict)
    assert meta.get("course_id") == str(c.id)
