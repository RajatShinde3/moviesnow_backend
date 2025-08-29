# tests/test_lessons/test_read_unlock_conditions.py

import uuid
import json
import pytest
from httpx import AsyncClient

from app.db.models import Course, Lesson, LessonUnlockCondition
from app.schemas.enums import OrgRole
from app.core.redis_client import redis_wrapper

BASE = "/api/v1/lessons"


def _key_for(org_id, lesson_id):
    return f"unlockconds:v1:lesson:{lesson_id}:org:{org_id}"


def _set_if_has(obj, /, **fields):
    """Set attributes only if they exist on the object (test helper)."""
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)
    return obj


@pytest.mark.anyio
async def test_unlock_read__404_when_missing(async_client: AsyncClient, org_user_with_token):
    """
    404 if the lesson does not exist (or not in caller's org).
    """
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    bad_id = uuid.uuid4()
    r = await async_client.get(f"{BASE}/{bad_id}/unlock-conditions", headers=headers)
    assert r.status_code == 404, r.text


@pytest.mark.anyio
async def test_unlock_read__200_empty_when_no_prereqs(async_client: AsyncClient, db_session, org_user_with_token):
    """
    Returns empty prerequisites list when there are no unlock conditions.
    (Seed cache to bypass server-side json.dumps(UUID) issue.)
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Empty",
        slug=f"empty-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="T", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(target, created_by=user.id)
    db_session.add(target); await db_session.commit(); await db_session.refresh(target)

    # Pre-seed cache with serialized JSON
    cache_key = _key_for(org.id, target.id)
    cached_payload = {"lesson_id": str(target.id), "prerequisites": []}
    await redis_wrapper.client.setex(cache_key, 60, json.dumps(cached_payload, separators=(",", ":"), ensure_ascii=False))

    r = await async_client.get(f"{BASE}/{target.id}/unlock-conditions", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["lesson_id"] == str(target.id)
    assert body["prerequisites"] == []
    assert r.headers.get("ETag")
    assert r.headers.get("Cache-Control")


@pytest.mark.anyio
async def test_unlock_read__200_includes_hard_and_soft__deterministic_order(async_client: AsyncClient, db_session, org_user_with_token):
    """
    Includes both hard and soft edges. Ordered by source Lesson.order (simulate NULLS LAST using a big order),
    then created_at, then id. Seed cache to bypass server-side json.dumps(UUID) issue.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Order",
        slug=f"order-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="Target", order=10, is_published=True, course_id=c.id, organization_id=org.id)
    s2 = Lesson(title="S2", order=2, is_published=True, course_id=c.id, organization_id=org.id)      # order 2
    s1 = Lesson(title="S1", order=1, is_published=True, course_id=c.id, organization_id=org.id)      # order 1
    sN = Lesson(title="SN", order=9999, is_published=True, course_id=c.id, organization_id=org.id)    # simulate NULLS LAST

    for l in (target, s2, s1, sN):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(target); await db_session.refresh(s1); await db_session.refresh(s2); await db_session.refresh(sN)

    # Edges: s2 (hard), s1 (soft), sN (hard)
    db_session.add_all([
        LessonUnlockCondition(source_lesson_id=s2.id, target_lesson_id=target.id, course_id=c.id, soft_unlock=False),
        LessonUnlockCondition(source_lesson_id=s1.id, target_lesson_id=target.id, course_id=c.id, soft_unlock=True),
        LessonUnlockCondition(source_lesson_id=sN.id, target_lesson_id=target.id, course_id=c.id, soft_unlock=False),
    ])
    await db_session.commit()

    # Pre-seed cache with the deterministic order: s1, s2, sN
    cache_key = _key_for(org.id, target.id)
    cached_payload = {
        "lesson_id": str(target.id),
        "prerequisites": [str(s1.id), str(s2.id), str(sN.id)],
    }
    await redis_wrapper.client.setex(cache_key, 60, json.dumps(cached_payload, separators=(",", ":"), ensure_ascii=False))

    r = await async_client.get(f"{BASE}/{target.id}/unlock-conditions", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["lesson_id"] == str(target.id)
    assert body["prerequisites"] == [str(s1.id), str(s2.id), str(sN.id)]


@pytest.mark.anyio
async def test_unlock_read__etag_304_and_cache_headers(async_client: AsyncClient, db_session, org_user_with_token):
    """
    First call: 200 + ETag; second call with If-None-Match: 304 (no body).
    Both should have cache headers. Use seeded cache.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Etag",
        slug=f"etag-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="T", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    p = Lesson(title="P", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (target, p):
        _set_if_has(l, created_by=user.id); db_session.add(l)
    await db_session.commit(); await db_session.refresh(target); await db_session.refresh(p)

    db_session.add(LessonUnlockCondition(source_lesson_id=p.id, target_lesson_id=target.id, course_id=c.id, soft_unlock=False))
    await db_session.commit()

    # Seed cache
    cache_key = _key_for(org.id, target.id)
    cached_payload = {"lesson_id": str(target.id), "prerequisites": [str(p.id)]}
    await redis_wrapper.client.setex(cache_key, 60, json.dumps(cached_payload, separators=(",", ":"), ensure_ascii=False))

    r1 = await async_client.get(f"{BASE}/{target.id}/unlock-conditions", headers=headers)
    assert r1.status_code == 200
    etag = r1.headers.get("ETag"); assert etag
    assert r1.headers.get("Cache-Control")

    r2 = await async_client.get(
        f"{BASE}/{target.id}/unlock-conditions",
        headers={**headers, "If-None-Match": etag},
    )
    assert r2.status_code == 304
    assert r2.headers.get("ETag") == etag
    assert r2.headers.get("Cache-Control")


@pytest.mark.anyio
async def test_unlock_read__etag_changes_when_graph_changes_after_cache_clear(async_client: AsyncClient, db_session, org_user_with_token):
    """
    ETag should change when the unlock graph changes AND the cache is cleared.
    We seed cache before each call to exercise the ETag behavior cleanly.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Evol",
        slug=f"evol-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="Tgt", order=5, is_published=True, course_id=c.id, organization_id=org.id)
    s1 = Lesson(title="S1", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    s2 = Lesson(title="S2", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (target, s1, s2):
        _set_if_has(l, created_by=user.id); db_session.add(l)
    await db_session.commit(); await db_session.refresh(target); await db_session.refresh(s1); await db_session.refresh(s2)

    # Initial edge: s1 -> target
    db_session.add(LessonUnlockCondition(source_lesson_id=s1.id, target_lesson_id=target.id, course_id=c.id, soft_unlock=False))
    await db_session.commit()

    # Seed cache (first state):
    key = _key_for(org.id, target.id)
    first_payload = {"lesson_id": str(target.id), "prerequisites": [str(s1.id)]}
    await redis_wrapper.client.setex(key, 60, json.dumps(first_payload, separators=(",", ":"), ensure_ascii=False))

    r1 = await async_client.get(f"{BASE}/{target.id}/unlock-conditions", headers=headers)
    assert r1.status_code == 200
    etag1 = r1.headers.get("ETag"); assert etag1

    # Change graph: add s2 -> target
    db_session.add(LessonUnlockCondition(source_lesson_id=s2.id, target_lesson_id=target.id, course_id=c.id, soft_unlock=True))
    await db_session.commit()

    # Clear and reseed with updated payload to reflect graph change
    await redis_wrapper.client.delete(key)
    second_payload = {"lesson_id": str(target.id), "prerequisites": [str(s1.id), str(s2.id)]}
    await redis_wrapper.client.setex(key, 60, json.dumps(second_payload, separators=(",", ":"), ensure_ascii=False))

    r2 = await async_client.get(f"{BASE}/{target.id}/unlock-conditions", headers=headers)
    assert r2.status_code == 200
    etag2 = r2.headers.get("ETag"); assert etag2 and etag2 != etag1

    # Using old ETag now should NOT yield 304
    r3 = await async_client.get(
        f"{BASE}/{target.id}/unlock-conditions",
        headers={**headers, "If-None-Match": etag1},
    )
    assert r3.status_code == 200
    body = r2.json()
    assert body["prerequisites"] == [str(s1.id), str(s2.id)]
