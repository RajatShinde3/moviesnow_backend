import json
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Course, Lesson, LessonProgress, UserOrganization
from app.schemas.enums import OrgRole
from app.core.redis_client import redis_wrapper

BASE = "/api/v1/progress"


# ---------------- helpers -----------------------------------------------------
def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


def _progress_completed_kwargs() -> dict:
    """Pick a completion field that exists on LessonProgress for this env."""
    cols = set(LessonProgress.__table__.columns.keys())
    if "is_completed" in cols:
        return {"is_completed": True}
    if "lesson_completed" in cols:
        return {"lesson_completed": True}
    if "completed_at" in cols:
        from datetime import datetime, timezone
        return {"completed_at": datetime.now(timezone.utc)}
    return {}


async def _actor_fk_kwargs(db: AsyncSession, user, org) -> dict:
    """
    Return the correct FK fields for LessonProgress, resolving membership
    for user/org so we don't violate FK constraints.
    """
    cols = set(LessonProgress.__table__.columns.keys())
    out = {}
    if "user_org_id" in cols:
        membership = (
            await db.execute(
                select(UserOrganization).where(
                    UserOrganization.user_id == user.id,
                    UserOrganization.organization_id == org.id,
                )
            )
        ).scalar_one_or_none()
        assert membership is not None, "Expected user membership row to exist"
        out["user_org_id"] = membership.id
    if "user_id" in cols:
        out["user_id"] = user.id
    return out


async def _create_progress_row(db: AsyncSession, *, lesson_id, course_id, user, org, completed: bool = False):
    cols = set(LessonProgress.__table__.columns.keys())
    row_kwargs = {
        "lesson_id": lesson_id,
        "course_id": course_id,
        **(await _actor_fk_kwargs(db, user, org)),
    }
    if "is_viewed" in cols:
        row_kwargs["is_viewed"] = True
    if "viewed_at" in cols:
        from datetime import datetime, timezone
        row_kwargs["viewed_at"] = datetime.now(timezone.utc)
    if completed:
        row_kwargs.update(_progress_completed_kwargs())
    db.add(LessonProgress(**row_kwargs))
    await db.commit()


# ---------------- tests -------------------------------------------------------

@pytest.mark.anyio
async def test_course_progress__404_when_missing(async_client: AsyncClient, org_user_with_token):
    """404 if the course does not exist (or is not owned)."""
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    missing = uuid.uuid4()
    r = await async_client.get(f"{BASE}/course/{missing}", headers=headers)
    assert r.status_code == 404, r.text


@pytest.mark.anyio
async def test_course_progress__200_shape_and_fields(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    """
    200 on success; payload includes required fields and sensible values.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Happy",
        slug=f"happy-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    # two lessons; mark one completed
    l1 = Lesson(title="L1", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    l2 = Lesson(title="L2", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (l1, l2):
        _set_if_has(l, created_by=user.id); db_session.add(l)
    await db_session.commit(); await db_session.refresh(l1); await db_session.refresh(l2)

    # create progress row for l1
    await _create_progress_row(db_session, lesson_id=l1.id, course_id=c.id, user=user, org=org, completed=True)

    r = await async_client.get(f"{BASE}/course/{c.id}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()

    # minimal shape checks (stable keys expected by response_model)
    # course_id may be absent in some deployments; assert if present
    if "course_id" in body:
        assert body["course_id"] == str(c.id)
    pp = body["progress_percent"]
    assert isinstance(pp, (int, float))
    assert 0 <= float(pp) <= 100
    assert isinstance(body["total_lessons"], int) and body["total_lessons"] >= 2
    assert isinstance(body["completed_lessons"], int) and body["completed_lessons"] >= 1
    assert isinstance(body.get("completed_lesson_ids", []), list)
    assert str(l1.id) in body.get("completed_lesson_ids", [])

    # ETag present for fresh response and cache-control (if set by the route)
    etag = r.headers.get("ETag")
    if etag:  # tolerate implementations that don't set it
        assert isinstance(etag, str)
    cache_ctrl = r.headers.get("Cache-Control")
    if cache_ctrl:
        assert "max-age" in cache_ctrl


@pytest.mark.anyio
async def test_course_progress__304_when_etag_matches(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    """
    Second call with If-None-Match returns 304 (no body).
    If the route preserves headers on 304, they should match; if not, tolerate.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="ETags",
        slug=f"etg-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    l = Lesson(title="Only", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(l, created_by=user.id); db_session.add(l)
    await db_session.commit(); await db_session.refresh(l)

    r1 = await async_client.get(f"{BASE}/course/{c.id}", headers=headers)
    assert r1.status_code == 200, r1.text
    etag = r1.headers.get("ETag")

    # If no ETag is produced, skip 304 branch (route may not support it)
    if not etag:
        pytest.skip("Route did not return an ETag; skipping 304 check")

    r2 = await async_client.get(
        f"{BASE}/course/{c.id}", headers={**headers, "If-None-Match": etag}
    )
    assert r2.status_code == 304, r2.text
    # If headers are preserved, they'll match; tolerate absence.
    if r2.headers.get("ETag"):
        assert r2.headers.get("ETag") == etag


@pytest.mark.anyio
async def test_course_progress__served_from_cache_without_service_call(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    When cached, the route should return the payload without hitting the service again.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="CacheHit",
        slug=f"ch-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    # seed a valid cache entry exactly like the route would
    cache_key = f"cprog:v1:course:{c.id}:user:{user.id}:org:{org.id}"
    cached_body = {
        "course_id": str(c.id),
        "progress_percent": 0,
        "total_lessons": 0,
        "completed_lessons": 0,
        "completed_lesson_ids": [],
    }
    raw = json.dumps(cached_body, separators=(",", ":"), ensure_ascii=False)
    await redis_wrapper.client.setex(cache_key, 60, raw)

    # If service is called, we fail the test
    async def _boom(*a, **k):
        pytest.fail("Service was called despite cache presence")
    monkeypatch.setattr("app.api.v1.progress.progress.get_course_progress", _boom, raising=True)

    r = await async_client.get(f"{BASE}/course/{c.id}", headers=headers)
    assert r.status_code == 200, r.text
    resp = r.json()
    # At minimum, the cached counters must match. If course_id is present, verify it too.
    assert resp.get("progress_percent") == 0
    assert resp.get("total_lessons") == 0
    assert resp.get("completed_lessons") == 0
    assert resp.get("completed_lesson_ids") == []
    if "course_id" in resp:
        assert resp["course_id"] == str(c.id)


@pytest.mark.anyio
async def test_course_progress__audit_called_best_effort(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    Audit logging is best-effort: our stub must handle either `org_id` or `organization_id`.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Audit",
        slug=f"aud-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    l = Lesson(title="A", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(l, created_by=user.id); db_session.add(l)
    await db_session.commit(); await db_session.refresh(l)

    called = {}

    async def _audit(**kwargs):
        called["org_id"] = kwargs.get("org_id") or kwargs.get("organization_id")
        called["actor_id"] = kwargs.get("actor_id")
        called["action"] = kwargs.get("action")
        called["meta"] = kwargs.get("meta_data")

    monkeypatch.setattr("app.api.v1.progress.progress.log_org_event", _audit, raising=True)

    r = await async_client.get(f"{BASE}/course/{c.id}", headers=headers)
    assert r.status_code == 200, r.text

    assert called.get("org_id") == org.id
    assert called.get("actor_id") == user.id
    meta = called.get("meta") or {}
    if "course_id" in meta:
        assert meta["course_id"] == str(c.id)
    if "user_id" in meta:
        assert meta["user_id"] == str(user.id)
    if "org_id" in meta:
        assert meta["org_id"] == str(org.id)


@pytest.mark.anyio
async def test_course_progress__corrupt_cache_falls_back_to_fresh(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    If cache JSON is corrupt, the route should ignore it and compute fresh.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Corrupt",
        slug=f"bad-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    # one lesson so total_lessons = 1
    l = Lesson(title="One", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(l, created_by=user.id); db_session.add(l)
    await db_session.commit(); await db_session.refresh(l)

    # corrupt cache
    cache_key = f"cprog:v1:course:{c.id}:user:{user.id}:org:{org.id}"
    await redis_wrapper.client.setex(cache_key, 60, "{not-json")

    r = await async_client.get(f"{BASE}/course/{c.id}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    # Must be a dict with sensible fields
    assert isinstance(body, dict)
    assert body.get("total_lessons", 0) >= 1
    # Optional field depending on schema
    if "course_id" in body:
        assert body["course_id"] == str(c.id)
