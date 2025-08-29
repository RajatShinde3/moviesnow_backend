# tests/test_lessons/test_skip_soft_unlock.py

import uuid
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Course,
    Lesson,
    LessonUnlockCondition,
    LessonProgress,
    UserOrganization,
)
from app.schemas.enums import OrgRole

BASE = "/api/v1/lessons"


# --- small helper (local copy to avoid cross-test imports) --------------------
def _set_if_has(obj, **fields):
    """
    Set attributes only if they exist on the SQLAlchemy model.
    Useful because some models may not expose all optional columns.
    """
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


# --- progress helpers (schema-tolerant) --------------------------------------
def _progress_completed_kwargs() -> dict:
    """
    Choose completion field(s) that exist in the current LessonProgress table.
    """
    cols = set(LessonProgress.__table__.columns.keys())
    if "is_completed" in cols:
        return {"is_completed": True}
    if "lesson_completed" in cols:
        return {"lesson_completed": True}
    if "completed_at" in cols:
        # naive UTC is fine; DB layer typically accepts TZ-aware too
        return {"completed_at": datetime.now(timezone.utc)}
    # If none of the known columns exist, returning {} means
    # "any progress row counts as done" for our route logic.
    return {}


def _actor_fk_kwargs(active_user_org) -> dict:
    """
    Pick the right foreign key to tie LessonProgress to the caller.
    """
    cols = set(LessonProgress.__table__.columns.keys())
    if "user_org_id" in cols:
        return {"user_org_id": active_user_org.id}
    if "user_id" in cols:
        return {"user_id": active_user_org.user_id}
    return {}


async def _create_progress_row(
    db: AsyncSession,
    *,
    lesson_id,
    course_id,
    active_user_org,
    completed: bool = False,
    soft_skipped: bool = False,
):
    cols = set(LessonProgress.__table__.columns.keys())
    row_kwargs = {
        "lesson_id": lesson_id,
        "course_id": course_id,
        **_actor_fk_kwargs(active_user_org),
    }
    # niceties the route might set
    if "is_viewed" in cols:
        row_kwargs["is_viewed"] = True
    if "viewed_at" in cols:
        row_kwargs["viewed_at"] = datetime.now(timezone.utc)

    if completed:
        row_kwargs.update(_progress_completed_kwargs())

    if soft_skipped:
        # prefer dedicated boolean columns if present
        for name in ["soft_unlock_skipped", "soft_skipped", "skipped_soft_unlock"]:
            if name in cols:
                row_kwargs[name] = True
                break
        else:
            # fallback to metadata JSON
            if "metadata" in cols:
                row_kwargs["metadata"] = {"soft_unlock_skipped": True}

    db.add(LessonProgress(**row_kwargs))
    await db.commit()


# -----------------------------------------------------------------------------


@pytest.mark.anyio
async def test_soft_skip__404_when_missing(async_client: AsyncClient, org_user_with_token, monkeypatch):
    """
    404 if the lesson does not exist.
    """
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # allow access checks to pass if the lesson existed
    async def _allow(*a, **k): return True

    monkeypatch.setattr(
        "app.api.v1.lessons.unlocks.can_access_course",
        _allow,
        raising=True,
    )

    missing = uuid.uuid4()
    r = await async_client.post(f"{BASE}/{missing}/skip-soft-unlock", headers=headers)
    assert r.status_code == 404, r.text


@pytest.mark.anyio
async def test_soft_skip__403_when_not_enrolled_or_invisible(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    403 when the caller cannot access the course (simulated via can_access_course=False).
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Course + lesson in caller's org (org check passes)
    c = Course(
        title="NoAccess",
        slug=f"noacc-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="Target", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(target, created_by=user.id)
    db_session.add(target); await db_session.commit(); await db_session.refresh(target)

    # deny at the access gate
    async def _deny(*a, **k): return False

    monkeypatch.setattr(
        "app.api.v1.lessons.unlocks.can_access_course",
        _deny,
        raising=True,
    )

    r = await async_client.post(f"{BASE}/{target.id}/skip-soft-unlock", headers=headers)
    assert r.status_code == 403, r.text


@pytest.mark.anyio
async def test_soft_skip__400_when_hard_prereq_incomplete(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    400 when at least one hard prerequisite is not completed.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    async def _allow(*a, **k): return True
    monkeypatch.setattr(
        "app.api.v1.lessons.unlocks.can_access_course",
        _allow,
        raising=True,
    )

    c = Course(
        title="HardReq",
        slug=f"hard-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    a = Lesson(title="A", order=1, is_published=True, course_id=c.id, organization_id=org.id)  # hard prereq
    target = Lesson(title="T", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (a, target):
        _set_if_has(l, created_by=user.id); db_session.add(l)
    await db_session.commit(); await db_session.refresh(a); await db_session.refresh(target)

    # A -> T (hard)
    db_session.add(LessonUnlockCondition(
        source_lesson_id=a.id, target_lesson_id=target.id, course_id=c.id, soft_unlock=False
    ))
    await db_session.commit()

    r = await async_client.post(f"{BASE}/{target.id}/skip-soft-unlock", headers=headers)
    assert r.status_code == 400, r.text
    body = r.json()
    assert "Cannot skip" in body["detail"]


@pytest.mark.anyio
async def test_soft_skip__200_no_conditions(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    200 and unlocked when the lesson has no unlock conditions.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    async def _allow(*a, **k): return True
    monkeypatch.setattr(
        "app.api.v1.lessons.unlocks.can_access_course",
        _allow,
        raising=True,
    )

    c = Course(
        title="NoConds",
        slug=f"nc-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    t = Lesson(title="T", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(t, created_by=user.id)
    db_session.add(t); await db_session.commit(); await db_session.refresh(t)

    r = await async_client.post(f"{BASE}/{t.id}/skip-soft-unlock", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["lesson_id"] == str(t.id)
    assert body["is_unlocked"] is True
    assert "No unlock conditions" in " ".join(body.get("reasons", []))


@pytest.mark.anyio
async def test_soft_skip__200_when_only_soft_prereqs(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    200 and unlocked when only soft prereqs remain (and we acknowledge/override them).
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    async def _allow(*a, **k): return True
    monkeypatch.setattr(
        "app.api.v1.lessons.unlocks.can_access_course",
        _allow,
        raising=True,
    )

    c = Course(
        title="SoftReq",
        slug=f"soft-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    s = Lesson(title="S", order=1, is_published=True, course_id=c.id, organization_id=org.id)  # soft prereq
    t = Lesson(title="T", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (s, t):
        _set_if_has(l, created_by=user.id); db_session.add(l)
    await db_session.commit(); await db_session.refresh(s); await db_session.refresh(t)

    # S -> T (soft)
    db_session.add(LessonUnlockCondition(
        source_lesson_id=s.id, target_lesson_id=t.id, course_id=c.id, soft_unlock=True
    ))
    await db_session.commit()

    r = await async_client.post(f"{BASE}/{t.id}/skip-soft-unlock", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["lesson_id"] == str(t.id)
    assert body["is_unlocked"] is True
    # reason mentions the acknowledgement
    assert any("acknowledged" in r.lower() or "overridden" in r.lower() for r in body.get("reasons", []))


@pytest.mark.anyio
async def test_soft_skip__200_when_hard_done_but_soft_remaining(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    """
    200 when hard prereqs are completed but soft ones remain.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    async def _allow(*a, **k): return True
    monkeypatch.setattr(
        "app.api.v1.lessons.unlocks.can_access_course",
        _allow,
        raising=True,
    )

    c = Course(
        title="MixReqs",
        slug=f"mix-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    hard = Lesson(title="H", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    soft = Lesson(title="S", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    t = Lesson(title="T", order=3, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (hard, soft, t):
        _set_if_has(l, created_by=user.id); db_session.add(l)
    await db_session.commit(); await db_session.refresh(hard); await db_session.refresh(soft); await db_session.refresh(t)

    # H (hard) and S (soft) -> T
    db_session.add_all([
        LessonUnlockCondition(source_lesson_id=hard.id, target_lesson_id=t.id, course_id=c.id, soft_unlock=False),
        LessonUnlockCondition(source_lesson_id=soft.id, target_lesson_id=t.id, course_id=c.id, soft_unlock=True),
    ])
    await db_session.commit()

    # Fetch the UserOrganization membership for this user/org
    user_org_membership = (
        await db_session.execute(
            select(UserOrganization).where(
                UserOrganization.user_id == user.id,
                UserOrganization.organization_id == org.id,
            )
        )
    ).scalar_one()

    # Mark hard prerequisite as completed for this actor (use membership, not Organization)
    await _create_progress_row(
        db_session,
        lesson_id=hard.id,
        course_id=c.id,
        active_user_org=user_org_membership,
        completed=True,
    )

    r = await async_client.post(f"{BASE}/{t.id}/skip-soft-unlock", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["lesson_id"] == str(t.id)
    assert body["is_unlocked"] is True
    assert any("acknowledged" in r.lower() or "overridden" in r.lower() for r in body.get("reasons", []))
