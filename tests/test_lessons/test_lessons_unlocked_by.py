# tests/test_lessons/test_lessons_unlocked_by.py

import uuid
import pytest
from httpx import AsyncClient

from app.db.models import Course, Lesson, LessonUnlockCondition
from app.schemas.enums import OrgRole

BASE = "/api/v1/lessons"


def _normalize_headers(h):
    return {"Authorization": h} if isinstance(h, str) else h


def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


@pytest.mark.anyio
async def test_unlocks_by__404_lesson_not_found(async_client: AsyncClient, org_user_with_token):
    _user, headers, _org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)
    missing = uuid.uuid4()
    r = await async_client.get(f"{BASE}/{missing}/unlocks", headers=headers)
    assert r.status_code == 404, r.text
    assert "not found" in r.text.lower() or "access denied" in r.text.lower()


@pytest.mark.anyio
async def test_unlocks_by__404_foreign_org(async_client: AsyncClient, db_session, org_user_with_token):
    caller, headers_a, org_a = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers_a = _normalize_headers(headers_a)
    _other, _headers_b, org_b = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c_b = Course(title="B", slug=f"b-{uuid.uuid4().hex[:8]}", organization_id=org_b.id, is_published=True)
    _set_if_has(c_b, created_by=caller.id)
    db_session.add(c_b)
    await db_session.commit(); await db_session.refresh(c_b)

    src_b = Lesson(title="Foreign", order=1, is_published=True, course_id=c_b.id, organization_id=org_b.id)
    _set_if_has(src_b, created_by=caller.id)
    db_session.add(src_b)
    await db_session.commit(); await db_session.refresh(src_b)

    r = await async_client.get(f"{BASE}/{src_b.id}/unlocks", headers=headers_a)
    assert r.status_code == 404, r.text


@pytest.mark.anyio
async def test_unlocks_by__200_empty_when_no_targets(async_client: AsyncClient, db_session, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="NoTargets", slug=f"nt-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit(); await db_session.refresh(c)

    src = Lesson(title="Source", order=5, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(src, created_by=user.id)
    db_session.add(src)
    await db_session.commit(); await db_session.refresh(src)

    r = await async_client.get(f"{BASE}/{src.id}/unlocks", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json() == []
    assert r.headers.get("ETag")
    assert r.headers.get("Cache-Control")


@pytest.mark.anyio
async def test_unlocks_by__200_published_only_and_includes_hard_soft(async_client: AsyncClient, db_session, org_user_with_token):
    """
    Returns both hard & soft edges but only published targets.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="PubOnly", slug=f"po-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit(); await db_session.refresh(c)

    src = Lesson(title="Source", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    t_pub_hard = Lesson(title="T-hard", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    t_pub_soft = Lesson(title="T-soft", order=3, is_published=True, course_id=c.id, organization_id=org.id)
    t_unpub = Lesson(title="T-unpublished", order=4, is_published=False, course_id=c.id, organization_id=org.id)
    for l in (src, t_pub_hard, t_pub_soft, t_unpub):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(src); await db_session.refresh(t_pub_hard); await db_session.refresh(t_pub_soft); await db_session.refresh(t_unpub)

    db_session.add_all([
        LessonUnlockCondition(source_lesson_id=src.id, target_lesson_id=t_pub_hard.id, course_id=c.id, soft_unlock=False),
        LessonUnlockCondition(source_lesson_id=src.id, target_lesson_id=t_pub_soft.id, course_id=c.id, soft_unlock=True),
        LessonUnlockCondition(source_lesson_id=src.id, target_lesson_id=t_unpub.id,   course_id=c.id, soft_unlock=False),
    ])
    await db_session.commit()

    r = await async_client.get(f"{BASE}/{src.id}/unlocks", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    ids = {item["id"] for item in data}
    assert ids == {str(t_pub_hard.id), str(t_pub_soft.id)}
    assert str(t_unpub.id) not in ids  # unpublished excluded


@pytest.mark.anyio
async def test_unlocks_by__200_deterministic_ordering(async_client: AsyncClient, db_session, org_user_with_token):
    """
    Deterministic ordering by target lesson: order → created_at → id.
    (Avoid NULLs here to be schema-agnostic if `order` is NOT NULL.)
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="Order", slug=f"ord-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit(); await db_session.refresh(c)

    src = Lesson(title="Src", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(src, created_by=user.id)
    db_session.add(src)
    await db_session.commit(); await db_session.refresh(src)

    # Targets: A(1), B(2), C(3) → expect A, B, C in that order
    a = Lesson(title="A", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    b = Lesson(title="B", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    c3 = Lesson(title="C", order=3, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (a, b, c3):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(a); await db_session.refresh(b); await db_session.refresh(c3)

    db_session.add_all([
        LessonUnlockCondition(source_lesson_id=src.id, target_lesson_id=a.id, course_id=c.id, soft_unlock=False),
        LessonUnlockCondition(source_lesson_id=src.id, target_lesson_id=c3.id, course_id=c.id, soft_unlock=False),
        LessonUnlockCondition(source_lesson_id=src.id, target_lesson_id=b.id, course_id=c.id, soft_unlock=False),
    ])
    await db_session.commit()

    r = await async_client.get(f"{BASE}/{src.id}/unlocks", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert [item["id"] for item in data] == [str(a.id), str(b.id), str(c3.id)]


@pytest.mark.anyio
async def test_unlocks_by__etag_304_and_cache_headers(async_client: AsyncClient, db_session, org_user_with_token):
    """
    First 200 should include ETag; second with If-None-Match should return 304 with same ETag and no body.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="ETag", slug=f"etag-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit(); await db_session.refresh(c)

    src = Lesson(title="Src", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    tgt = Lesson(title="Tgt", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (src, tgt):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(src); await db_session.refresh(tgt)

    db_session.add(LessonUnlockCondition(source_lesson_id=src.id, target_lesson_id=tgt.id, course_id=c.id, soft_unlock=False))
    await db_session.commit()

    r1 = await async_client.get(f"{BASE}/{src.id}/unlocks", headers=headers)
    assert r1.status_code == 200
    etag = r1.headers.get("ETag")
    assert etag
    assert r1.headers.get("Cache-Control")

    r2 = await async_client.get(f"{BASE}/{src.id}/unlocks", headers={**headers, "If-None-Match": etag})
    assert r2.status_code == 304
    assert r2.headers.get("ETag") == etag
    assert r2.headers.get("Cache-Control")
    assert not r2.text or r2.text == ""


@pytest.mark.anyio
async def test_unlocks_by__etag_changes_when_graph_changes(async_client: AsyncClient, db_session, org_user_with_token):
    """
    ETag should change after the unlock graph changes; bypass Redis to force fresh read.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="Evol", slug=f"evol-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit(); await db_session.refresh(c)

    src = Lesson(title="Src", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    t1 = Lesson(title="T1", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    t2 = Lesson(title="T2", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (src, t1, t2):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(src); await db_session.refresh(t1); await db_session.refresh(t2)

    db_session.add(LessonUnlockCondition(source_lesson_id=src.id, target_lesson_id=t1.id, course_id=c.id, soft_unlock=False))
    await db_session.commit()

    r1 = await async_client.get(f"{BASE}/{src.id}/unlocks", headers=headers)
    assert r1.status_code == 200
    etag1 = r1.headers.get("ETag")
    assert etag1

    # Add another edge and force fresh read
    db_session.add(LessonUnlockCondition(source_lesson_id=src.id, target_lesson_id=t2.id, course_id=c.id, soft_unlock=True))
    await db_session.commit()

    r2 = await async_client.get(
        f"{BASE}/{src.id}/unlocks",
        headers={**headers, "Cache-Control": "no-cache"},
    )
    assert r2.status_code == 200
    etag2 = r2.headers.get("ETag")
    assert etag2 and etag2 != etag1

    r3 = await async_client.get(
        f"{BASE}/{src.id}/unlocks",
        headers={**headers, "If-None-Match": etag1},
    )
    assert r3.status_code == 200
    assert r3.headers.get("ETag") == etag2
