# tests/test_lessons/test_prereq_blocked_by.py

import uuid
import pytest
from httpx import AsyncClient

from app.db.models import (
    Course,
    Lesson,
    LessonUnlockCondition,
)
from app.schemas.enums import OrgRole

BASE = "/api/v1/lessons"


# ── helpers ─────────────────────────────────────────────────────────────────

def _normalize_headers(h):
    # Some fixtures may return a plain "Authorization" string; httpx expects a mapping.
    if isinstance(h, str):
        return {"Authorization": h}
    return h


def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


# ── tests ───────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_blocked_by__404_lesson_not_found(async_client: AsyncClient, org_user_with_token):
    """
    404 when lesson doesn't exist (route contract).
    """
    _user, headers, _org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    missing = uuid.uuid4()
    r = await async_client.get(f"{BASE}/{missing}/blocked-by", headers=headers)
    assert r.status_code == 404, r.text
    assert "not found" in r.text.lower() or "access denied" in r.text.lower()


@pytest.mark.anyio
async def test_blocked_by__404_foreign_org(async_client: AsyncClient, db_session, org_user_with_token):
    """
    404 when lesson exists but belongs to a different org (route collapses to 'not found or access denied').
    """
    # Caller in org A
    caller, headers_a, org_a = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers_a = _normalize_headers(headers_a)

    # Create another org B user to obtain an org B to attach the lesson to
    _other_user, _headers_b, org_b = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Lesson in org B
    course_b = Course(title="B", slug=f"b-{uuid.uuid4().hex[:8]}", organization_id=org_b.id, is_published=True)
    _set_if_has(course_b, created_by=caller.id)
    db_session.add(course_b)
    await db_session.commit(); await db_session.refresh(course_b)

    target_b = Lesson(
        title="Foreign",
        order=1,
        is_published=True,
        course_id=course_b.id,
        organization_id=org_b.id
    )
    _set_if_has(target_b, created_by=caller.id)
    db_session.add(target_b)
    await db_session.commit(); await db_session.refresh(target_b)

    # Caller from org A should get a 404/denied response (as per route behavior)
    r = await async_client.get(f"{BASE}/{target_b.id}/blocked-by", headers=headers_a)
    assert r.status_code == 404, r.text


@pytest.mark.anyio
async def test_blocked_by__200_empty_when_no_prereqs(async_client: AsyncClient, db_session, org_user_with_token):
    """
    200 with [] when lesson has zero unlock conditions.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="NoPrereqs", slug=f"np-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="Target", order=10, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(target, created_by=user.id)
    db_session.add(target)
    await db_session.commit(); await db_session.refresh(target)

    r = await async_client.get(f"{BASE}/{target.id}/blocked-by", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json() == []
    # ETag is attached for 200s (short-TTL cache)
    assert r.headers.get("ETag")
    assert r.headers.get("Cache-Control")


@pytest.mark.anyio
async def test_blocked_by__200_with_edges_and_ordering(async_client: AsyncClient, db_session, org_user_with_token):
    """
    Returns prerequisites as LessonEdge[] with deterministic ordering by
    source lesson: order ASC → created_at → id (NULLS LAST in code, but order is non-null here).
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="Flow", slug=f"flow-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit(); await db_session.refresh(c)

    # Target lesson
    target = Lesson(title="Target", order=100, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(target, created_by=user.id)
    db_session.add(target)
    await db_session.commit(); await db_session.refresh(target)

    # Source lessons with different orders (deterministic)
    a = Lesson(title="A", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    b = Lesson(title="B", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    z = Lesson(title="Z", order=3, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (a, b, z):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(a); await db_session.refresh(b); await db_session.refresh(z)

    # Edges (include a mix of hard/soft)
    db_session.add_all([
        LessonUnlockCondition(source_lesson_id=a.id, target_lesson_id=target.id, course_id=c.id, soft_unlock=False),
        LessonUnlockCondition(source_lesson_id=z.id, target_lesson_id=target.id, course_id=c.id, soft_unlock=True),
        LessonUnlockCondition(source_lesson_id=b.id, target_lesson_id=target.id, course_id=c.id, soft_unlock=False),
    ])
    await db_session.commit()

    r = await async_client.get(f"{BASE}/{target.id}/blocked-by", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()

    # Order should be by source lesson's order: A(1), B(2), Z(3)
    assert [d["from_lesson_id"] for d in data] == [str(a.id), str(b.id), str(z.id)]

    # Shape and soft flag
    for edge in data:
        assert set(edge.keys()) == {"from_lesson_id", "to_lesson_id", "soft_unlock"}
        assert edge["to_lesson_id"] == str(target.id)
    # Check specific soft flags
    by_src = {e["from_lesson_id"]: e for e in data}
    assert by_src[str(a.id)]["soft_unlock"] is False
    assert by_src[str(b.id)]["soft_unlock"] is False
    assert by_src[str(z.id)]["soft_unlock"] is True


@pytest.mark.anyio
async def test_blocked_by__etag_304_and_cache_headers(async_client: AsyncClient, db_session, org_user_with_token):
    """
    First request returns 200 + ETag; second with If-None-Match returns 304 with no body.
    Also verify Cache-Control and ETag headers are present in both cases.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="ETag", slug=f"etag-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="T", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    src = Lesson(title="S", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(target, created_by=user.id); _set_if_has(src, created_by=user.id)
    db_session.add_all([target, src])
    await db_session.commit(); await db_session.refresh(target); await db_session.refresh(src)

    db_session.add(LessonUnlockCondition(source_lesson_id=src.id, target_lesson_id=target.id, course_id=c.id, soft_unlock=False))
    await db_session.commit()

    r1 = await async_client.get(f"{BASE}/{target.id}/blocked-by", headers=headers)
    assert r1.status_code == 200
    etag = r1.headers.get("ETag")
    assert etag
    assert r1.headers.get("Cache-Control")  # private, max-age=60 per implementation

    r2 = await async_client.get(f"{BASE}/{target.id}/blocked-by", headers={**headers, "If-None-Match": etag})
    assert r2.status_code == 304
    assert not r2.text or r2.text == ""
    assert r2.headers.get("ETag") == etag
    assert r2.headers.get("Cache-Control")


@pytest.mark.anyio
async def test_blocked_by__etag_changes_when_graph_changes(async_client: AsyncClient, db_session, org_user_with_token):
    """
    ETag should change when the prerequisites payload changes.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(title="Evol", slug=f"evol-{uuid.uuid4().hex[:8]}", organization_id=org.id, is_published=True)
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit(); await db_session.refresh(c)

    target = Lesson(title="Tgt", order=5, is_published=True, course_id=c.id, organization_id=org.id)
    s1 = Lesson(title="S1", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    s2 = Lesson(title="S2", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (target, s1, s2):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(target); await db_session.refresh(s1); await db_session.refresh(s2)

    # Initially only s1 -> target
    db_session.add(LessonUnlockCondition(
        source_lesson_id=s1.id, target_lesson_id=target.id, course_id=c.id, soft_unlock=False
    ))
    await db_session.commit()

    r1 = await async_client.get(f"{BASE}/{target.id}/blocked-by", headers=headers)
    assert r1.status_code == 200
    etag1 = r1.headers.get("ETag")
    assert etag1

    # Add another prerequisite edge and expect a different ETag
    db_session.add(LessonUnlockCondition(
        source_lesson_id=s2.id, target_lesson_id=target.id, course_id=c.id, soft_unlock=True
    ))
    await db_session.commit()

    # IMPORTANT: bypass Redis to force a fresh read and new ETag
    r2 = await async_client.get(
        f"{BASE}/{target.id}/blocked-by",
        headers={**headers, "Cache-Control": "no-cache"},
    )
    assert r2.status_code == 200
    etag2 = r2.headers.get("ETag")
    assert etag2 and etag2 != etag1

    # If-None-Match with the old ETag must NOT yield 304 now (should return 200 + new ETag)
    r3 = await async_client.get(
        f"{BASE}/{target.id}/blocked-by",
        headers={**headers, "If-None-Match": etag1},
    )
    assert r3.status_code == 200
    assert r3.headers.get("ETag") == etag2
