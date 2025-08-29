# tests/test_progress/test_reset_progress.py

import uuid
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Course,
    Lesson,
    LessonProgress,
    UserOrganization,
)
from app.schemas.enums import OrgRole
from app.core.redis_client import redis_wrapper

BASE = "/api/v1/progress"


# ---------- small helpers (schema tolerant) -----------------------------------
def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


async def _user_org_membership_id(db: AsyncSession, user, org) -> uuid.UUID | None:
    """Return membership row id for (user, organization), or None if absent."""
    row = (
        await db.execute(
            select(UserOrganization).where(
                UserOrganization.user_id == user.id,
                UserOrganization.organization_id == org.id,
            )
        )
    ).scalar_one_or_none()
    return getattr(row, "id", None) if row else None


def _progress_completed_kwargs() -> dict:
    cols = set(LessonProgress.__table__.columns.keys())
    if "is_completed" in cols:
        return {"is_completed": True}
    if "lesson_completed" in cols:
        return {"lesson_completed": True}
    if "completed_at" in cols:
        return {"completed_at": datetime.now(timezone.utc)}
    return {}


async def _create_progress_row(
    db: AsyncSession,
    *,
    lesson_id,
    course_id,
    user,
    org,
    completed: bool = False,
):
    """Insert a LessonProgress row for the given user/org in a schema-tolerant way."""
    cols = set(LessonProgress.__table__.columns.keys())
    row = {"lesson_id": lesson_id, "course_id": course_id}

    # actor columns
    if "user_id" in cols:
        row["user_id"] = user.id
    if "user_org_id" in cols:
        memb_id = await _user_org_membership_id(db, user, org)
        if memb_id is not None:
            row["user_org_id"] = memb_id

    # viewed niceties
    if "is_viewed" in cols:
        row["is_viewed"] = True
    if "viewed_at" in cols:
        row["viewed_at"] = datetime.now(timezone.utc)

    if completed:
        row.update(_progress_completed_kwargs())

    db.add(LessonProgress(**row))
    await db.commit()


# ---------- tests --------------------------------------------------------------


@pytest.mark.anyio
async def test_reset__404_when_course_missing_or_other_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    404 if the course does not exist OR belongs to another organization.
    We create a course in a different org and attempt to reset from caller's org.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Foreign org + course
    _, _, other_org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    foreign = Course(
        title="Foreign",
        slug=f"foreign-{uuid.uuid4().hex[:6]}",
        organization_id=other_org.id,
        is_published=True,
    )
    _set_if_has(foreign, created_by=user.id)
    db_session.add(foreign)
    await db_session.commit()
    await db_session.refresh(foreign)

    r = await async_client.delete(f"{BASE}/course/{foreign.id}/reset", headers=headers)
    assert r.status_code == 404, r.text


@pytest.mark.anyio
async def test_reset__204_deletes_only_this_course_and_invalidates_cache(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    204 on success; removes only rows for this course and this user;
    leaves other course rows intact; invalidates course progress cache key; audits best-effort.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Two courses in same org
    c1 = Course(
        title="C1",
        slug=f"c1-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    c2 = Course(
        title="C2",
        slug=f"c2-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    for c in (c1, c2):
        _set_if_has(c, created_by=user.id)
        db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c1)
    await db_session.refresh(c2)

    # Lessons
    l1 = Lesson(title="L1", order=1, is_published=True, course_id=c1.id, organization_id=org.id)
    l2 = Lesson(title="L2", order=1, is_published=True, course_id=c2.id, organization_id=org.id)
    for l in (l1, l2):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(l1)
    await db_session.refresh(l2)

    # Progress rows for this user in both courses
    await _create_progress_row(db_session, lesson_id=l1.id, course_id=c1.id, user=user, org=org, completed=True)
    await _create_progress_row(db_session, lesson_id=l2.id, course_id=c2.id, user=user, org=org, completed=True)

    # Seed cache entry that should be invalidated
    cache_key = f"cprog:v1:course:{c1.id}:user:{user.id}:org:{org.id}"
    await redis_wrapper.client.setex(cache_key, 60, '{"ok":true}')
    deleted_key = {"val": None}

    async def _fake_del(key):
        deleted_key["val"] = key
        return 1

    monkeypatch.setattr(redis_wrapper.client, "delete", _fake_del, raising=True)

    # Track audit call (best-effort)
    audit_called = {}

    async def _audit(**kwargs):
        audit_called.update(kwargs)
        return None

    # IMPORTANT: match the route's import/kwargs names
    import app.api.v1.progress.progress as progress_mod
    monkeypatch.setattr(progress_mod, "log_org_event", _audit, raising=True)

    # Call reset on c1
    r = await async_client.delete(f"{BASE}/course/{c1.id}/reset", headers=headers)
    assert r.status_code == 204, r.text

    # c1 progress gone
    row_c1 = (
        await db_session.execute(
            select(LessonProgress).where(LessonProgress.lesson_id == l1.id)
        )
    ).scalar_one_or_none()
    assert row_c1 is None

    # c2 progress still present
    row_c2 = (
        await db_session.execute(
            select(LessonProgress).where(LessonProgress.lesson_id == l2.id)
        )
    ).scalar_one_or_none()
    assert row_c2 is not None

    # cache invalidation attempted with expected key
    assert deleted_key["val"] == cache_key

    # audit called best-effort with expected bits
    # route uses organization_id, actor_id, meta_data={"course_id": ...}
    assert str(c1.id) in str(audit_called.get("meta_data", {}))
    assert audit_called.get("organization_id") == org.id
    assert audit_called.get("actor_id") == user.id


@pytest.mark.anyio
async def test_reset__204_when_no_lessons_is_nop_and_still_204(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    If the course has no lessons, deletion is a no-op but still returns 204.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Empty",
        slug=f"empty-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)

    # Ensure no exceptions if cache client is missing delete/raises
    def _boom(*a, **k):
        raise RuntimeError("cache down")

    monkeypatch.setattr(redis_wrapper.client, "delete", _boom, raising=False)

    r = await async_client.delete(f"{BASE}/course/{c.id}/reset", headers=headers)
    assert r.status_code == 204, r.text


@pytest.mark.anyio
async def test_reset__204_ignores_cache_errors_and_audits_best_effort(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    Even if cache delete raises, we still return 204; audit called best-effort.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Audit",
        slug=f"a-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)

    l = Lesson(title="X", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(l, created_by=user.id)
    db_session.add(l)
    await db_session.commit()
    await db_session.refresh(l)

    await _create_progress_row(db_session, lesson_id=l.id, course_id=c.id, user=user, org=org, completed=True)

    # make cache delete explode
    async def _boom(*a, **k):
        raise RuntimeError("cache outage")

    monkeypatch.setattr(redis_wrapper.client, "delete", _boom, raising=True)

    audit_called = {}

    async def _audit(**kwargs):
        audit_called.update(kwargs)
        return None

    import app.api.v1.progress.progress as progress_mod
    monkeypatch.setattr(progress_mod, "log_org_event", _audit, raising=True)

    r = await async_client.delete(f"{BASE}/course/{c.id}/reset", headers=headers)
    assert r.status_code == 204

    # rows for c are gone
    row = (
        await db_session.execute(
            select(LessonProgress).where(LessonProgress.lesson_id == l.id)
        )
    ).scalar_one_or_none()
    assert row is None

    # audit best-effort called
    assert audit_called.get("organization_id") == org.id
    assert audit_called.get("actor_id") == user.id
    assert str(c.id) in str(audit_called.get("meta_data", {}))
