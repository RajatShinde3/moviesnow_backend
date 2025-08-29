# tests/test_lessons/test_delete_unlock_condition.py

import uuid
import pytest
from httpx import AsyncClient

from app.db.models import Course, Lesson, LessonUnlockCondition
from app.schemas.enums import OrgRole

BASE = "/api/v1/lessons/lesson-unlock-conditions"


def _set_if_has(obj, **fields):
    """Set model fields only if they exist on the object (safe helper for tests)."""
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


@pytest.mark.anyio
async def test_delete_unlock__200_ok_and_invalidates_cache(
    async_client: AsyncClient, db_session, org_user_with_token, monkeypatch
):
    """
    200 when deleted successfully; ensures cache invalidation is invoked.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Course & lessons in caller's org
    c = Course(
        title="Own",
        slug=f"own-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    a = Lesson(title="A", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    b = Lesson(title="B", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (a, b):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(a); await db_session.refresh(b)

    cond = LessonUnlockCondition(
        source_lesson_id=a.id,
        target_lesson_id=b.id,
        course_id=c.id,
        soft_unlock=True,
    )
    db_session.add(cond); await db_session.commit(); await db_session.refresh(cond)

    # Track invalidation call (patch the function where the route imports it)
    called = {}
    async def _fake_invalidate(course_id, *args, **kwargs):
        called["course_id"] = course_id
        return 0

    monkeypatch.setattr(
        "app.api.v1.lessons.unlocks.invalidate_unlock_related_caches",
        _fake_invalidate,
        raising=True,
    )

    r = await async_client.delete(f"{BASE}/{cond.id}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    # MessageResponse should use 'message'
    assert body["message"] == "Unlock condition deleted successfully."
    assert called.get("course_id") == c.id


@pytest.mark.anyio
async def test_delete_unlock__404_when_condition_missing(
    async_client: AsyncClient, org_user_with_token
):
    """
    404 if the unlock condition does not exist.
    """
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    missing_id = uuid.uuid4()

    r = await async_client.delete(f"{BASE}/{missing_id}", headers=headers)
    assert r.status_code == 404, r.text
    assert r.json()["detail"]


@pytest.mark.anyio
async def test_delete_unlock__403_when_condition_in_other_org(
    async_client: AsyncClient, db_session, org_user_with_token
):
    """
    403 if the unlock condition belongs to a course in a different organization.
    """
    # Caller from Org A
    user_a, headers_a, org_a = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    # Create Org B for ownership mismatch
    _, _, org_b = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c_b = Course(
        title="Other",
        slug=f"other-{uuid.uuid4().hex[:8]}",
        organization_id=org_b.id,
        is_published=True,
    )
    _set_if_has(c_b, created_by=user_a.id)
    db_session.add(c_b); await db_session.commit(); await db_session.refresh(c_b)

    la = Lesson(title="LA", order=1, is_published=True, course_id=c_b.id, organization_id=org_b.id)
    lb = Lesson(title="LB", order=2, is_published=True, course_id=c_b.id, organization_id=org_b.id)
    for l in (la, lb):
        _set_if_has(l, created_by=user_a.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(la); await db_session.refresh(lb)

    cond_b = LessonUnlockCondition(
        source_lesson_id=la.id,
        target_lesson_id=lb.id,
        course_id=c_b.id,
        soft_unlock=False,
    )
    db_session.add(cond_b); await db_session.commit(); await db_session.refresh(cond_b)

    # Org A tries to delete Org B's condition -> 403
    r = await async_client.delete(f"{BASE}/{cond_b.id}", headers=headers_a)
    assert r.status_code == 403, r.text
    assert r.json()["detail"]
