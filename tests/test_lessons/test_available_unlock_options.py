# tests/test_lessons/test_available_unlock_options.py

import uuid
import pytest
from httpx import AsyncClient

from app.db.models import Course, Lesson, LessonUnlockCondition
from app.schemas.enums import OrgRole

BASE = "/api/v1/lessons"


# ── helpers ─────────────────────────────────────────────────────────────────

def _normalize_headers(h):
    return {"Authorization": h} if isinstance(h, str) else h


def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


# ── tests ───────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_availopts__404_not_found(async_client: AsyncClient, org_user_with_token):
    """
    404 when the target lesson doesn't exist.
    """
    _user, headers, _org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    missing = uuid.uuid4()
    r = await async_client.get(f"{BASE}/{missing}/available-unlock-options", headers=headers)
    assert r.status_code == 404, r.text


@pytest.mark.anyio
async def test_availopts__403_foreign_org(async_client: AsyncClient, db_session, org_user_with_token):
    """
    403 when the lesson exists but belongs to a different org (route explicitly returns 403).
    """
    caller, headers_a, org_a = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers_a = _normalize_headers(headers_a)

    _other, _headers_b, org_b = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Lesson in org B
    c_b = Course(title="B", slug=f"b-{uuid.uuid4().hex[:8]}", organization_id=org_b.id, is_published=True)
    _set_if_has(c_b, created_by=caller.id)
    db_session.add(c_b)
    await db_session.commit(); await db_session.refresh(c_b)

    target_b = Lesson(title="Foreign", order=1, is_published=True, course_id=c_b.id, organization_id=org_b.id)
    _set_if_has(target_b, created_by=caller.id)
    db_session.add(target_b)
    await db_session.commit(); await db_session.refresh(target_b)

    r = await async_client.get(f"{BASE}/{target_b.id}/available-unlock-options", headers=headers_a)
    assert r.status_code == 403, r.text


@pytest.mark.anyio
async def test_availopts__200_empty_when_no_candidates(async_client: AsyncClient, db_session, org_user_with_token):
    """
    200 with [] when there are no eligible lessons in the course (only target exists).
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="Empty", slug=f"emp-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="Target", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(target, created_by=user.id)
    db_session.add(target)
    await db_session.commit(); await db_session.refresh(target)

    r = await async_client.get(f"{BASE}/{target.id}/available-unlock-options", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json() == []
    assert r.headers.get("ETag")
    assert r.headers.get("Cache-Control")


@pytest.mark.anyio
async def test_availopts__filters_self_unpublished_other_course_and_already_used(async_client: AsyncClient, db_session, org_user_with_token):
    """
    Excludes:
      - the target itself
      - unpublished lessons
      - lessons from another course
      - lessons already used as prerequisites for the target
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    # Two courses in same org
    c1 = Course(title="C1", slug=f"c1-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    c2 = Course(title="C2", slug=f"c2-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c1, created_by=user.id); _set_if_has(c2, created_by=user.id)
    db_session.add_all([c1, c2])
    await db_session.commit(); await db_session.refresh(c1); await db_session.refresh(c2)

    # Target in course 1
    target = Lesson(title="Target", order=5, is_published=True, course_id=c1.id, organization_id=org.id)
    # Eligible candidates in course 1 (published)
    a = Lesson(title="A", order=1, is_published=True, course_id=c1.id, organization_id=org.id)
    b = Lesson(title="B", order=2, is_published=True, course_id=c1.id, organization_id=org.id)
    # Unpublished in course 1
    unpub = Lesson(title="U", order=3, is_published=False, course_id=c1.id, organization_id=org.id)
    # Other course (should be excluded)
    other_course = Lesson(title="OC", order=1, is_published=True, course_id=c2.id, organization_id=org.id)

    for l in (target, a, b, unpub, other_course):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(target); await db_session.refresh(a); await db_session.refresh(b)
    await db_session.refresh(unpub); await db_session.refresh(other_course)

    # Mark 'a' as already-used prerequisite for target → should be excluded
    db_session.add(LessonUnlockCondition(source_lesson_id=a.id, target_lesson_id=target.id, course_id=c1.id, soft_unlock=False))
    await db_session.commit()

    r = await async_client.get(f"{BASE}/{target.id}/available-unlock-options", headers=headers)
    assert r.status_code == 200, r.text
    ids = [item["id"] for item in r.json()]
    # Expect only 'b' to remain
    assert ids == [str(b.id)]
    # Sanity: excluded candidates are not present
    for excluded in (target.id, a.id, unpub.id, other_course.id):
        assert str(excluded) not in ids


@pytest.mark.anyio
async def test_availopts__excludes_downstream_to_prevent_cycles(async_client: AsyncClient, db_session, org_user_with_token):
    """
    Excludes any lesson that is downstream from the target (would create a cycle).
    Construct graph: target -> X -> Y. X and Y must be excluded; Z (unrelated) should remain.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="Graph", slug=f"g-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="Target", order=10, is_published=True, course_id=c.id, organization_id=org.id)
    x = Lesson(title="X", order=11, is_published=True, course_id=c.id, organization_id=org.id)
    y = Lesson(title="Y", order=12, is_published=True, course_id=c.id, organization_id=org.id)
    z = Lesson(title="Z", order=13, is_published=True, course_id=c.id, organization_id=org.id)  # unrelated; eligible
    for l in (target, x, y, z):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(target); await db_session.refresh(x); await db_session.refresh(y); await db_session.refresh(z)

    # Build downstream chain: target -> X, X -> Y
    db_session.add_all([
        LessonUnlockCondition(source_lesson_id=target.id, target_lesson_id=x.id, course_id=c.id, soft_unlock=False),
        LessonUnlockCondition(source_lesson_id=x.id, target_lesson_id=y.id, course_id=c.id, soft_unlock=False),
    ])
    await db_session.commit()

    r = await async_client.get(f"{BASE}/{target.id}/available-unlock-options", headers=headers)
    assert r.status_code == 200, r.text
    ids = [item["id"] for item in r.json()]
    assert ids == [str(z.id)], f"expected only Z eligible, got {ids}"


@pytest.mark.anyio
async def test_availopts__deterministic_ordering(async_client: AsyncClient, db_session, org_user_with_token):
    """
    Ordering by: order (non-NULL first) → created_at → id.
    Use distinct order values to avoid relying on timestamp tie-breakers.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="Order", slug=f"ord-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="Target", order=99, is_published=True, course_id=c.id, organization_id=org.id)
    a = Lesson(title="A", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    b = Lesson(title="B", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    d = Lesson(title="D", order=4, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (target, a, b, d):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(target); await db_session.refresh(a); await db_session.refresh(b); await db_session.refresh(d)

    # No disqualifiers; all three should be eligible, ordered A(1), B(2), D(4)
    r = await async_client.get(f"{BASE}/{target.id}/available-unlock-options", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert [item["id"] for item in data] == [str(a.id), str(b.id), str(d.id)]


@pytest.mark.anyio
async def test_availopts__etag_304_and_cache_headers(async_client: AsyncClient, db_session, org_user_with_token):
    """
    First request returns 200 + ETag; second with If-None-Match returns 304 with no body.
    NOTE: If your route returns `None` after setting status 304, FastAPI will raise a
    ResponseValidationError. The robust fix is to return a bare Starlette Response on 304.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="ETag", slug=f"etag-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="Target", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    l1 = Lesson(title="L1", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    db_session.add_all([target, l1])
    await db_session.commit()
    await db_session.refresh(target); await db_session.refresh(l1)

    r1 = await async_client.get(f"{BASE}/{target.id}/available-unlock-options", headers=headers)
    assert r1.status_code == 200, r1.text
    etag = r1.headers.get("ETag")
    assert etag
    assert r1.headers.get("Cache-Control")

    r2 = await async_client.get(
        f"{BASE}/{target.id}/available-unlock-options",
        headers={**headers, "If-None-Match": etag},
    )
    assert r2.status_code == 304
    assert r2.headers.get("ETag") == etag
    assert r2.headers.get("Cache-Control")
    assert not r2.text or r2.text == ""


@pytest.mark.anyio
@pytest.mark.xfail(reason="Route lacks cache-bypass; add Cache-Control: no-cache handling to assert ETag changes immediately.")
async def test_availopts__etag_changes_when_graph_changes(async_client: AsyncClient, db_session, org_user_with_token):
    """
    Illustrates expected behavior after implementing a cache bypass (e.g., honor 'Cache-Control: no-cache').
    After modifying the candidate set, ETag should change on the next fetch.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="Evol", slug=f"evol-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="Target", order=5, is_published=True, course_id=c.id, organization_id=org.id)
    a = Lesson(title="A", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    db_session.add_all([target, a])
    await db_session.commit()
    await db_session.refresh(target); await db_session.refresh(a)

    r1 = await async_client.get(f"{BASE}/{target.id}/available-unlock-options", headers=headers)
    assert r1.status_code == 200
    etag1 = r1.headers.get("ETag")
    assert etag1

    # Add a new eligible lesson 'b' which should appear after bypassing cache
    b = Lesson(title="B", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(b, created_by=user.id)
    db_session.add(b)
    await db_session.commit(); await db_session.refresh(b)

    # EXPECTED once route supports bypass:
    r2 = await async_client.get(
        f"{BASE}/{target.id}/available-unlock-options",
        headers={**headers, "Cache-Control": "no-cache"},
    )
    assert r2.status_code == 200
    etag2 = r2.headers.get("ETag")
    assert etag2 and etag2 != etag1
