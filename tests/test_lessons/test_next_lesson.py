import json
import re
import anyio
import pytest
from httpx import AsyncClient
from uuid import UUID, uuid4
from datetime import datetime, timezone
from app.schemas.enums import OrgRole
from sqlalchemy import select

from app.db.models import (
    Course,
    Lesson,
    LessonProgress,
    LessonUnlockCondition,
    UserOrganization,
    CourseEnrollment,
)
from app.schemas.enums import CourseVisibility
from app.core.redis_client import redis_wrapper

BASE = "/api/v1/lessons"


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _slugify(title: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (title or "").lower()).strip("-")
    return s or "course"

def _rand_slug(title: str) -> str:
    return f"{_slugify(title)}-{uuid4().hex[:8]}"

async def _get_user_org(db, *, user_id, org_id) -> UserOrganization | None:
    res = await db.execute(
        select(UserOrganization).where(
            UserOrganization.user_id == user_id,
            UserOrganization.organization_id == org_id,
        )
    )
    return res.scalars().first()


def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


async def _complete_lesson_for_org_user(db, *, lesson_id: UUID, course_id: UUID, user_org_id: UUID):
    now = datetime.now(timezone.utc)
    cols = LessonProgress.__table__.columns.keys()
    payload = dict(
        lesson_id=lesson_id,
        course_id=course_id,
        user_org_id=user_org_id,
    )
    if "is_completed" in cols:
        payload["is_completed"] = True
    if "completed_at" in cols:
        payload["completed_at"] = now

    prog = LessonProgress(**payload)  # type: ignore[arg-type]
    db.add(prog)
    await db.commit()

# replace the old helper that hard-coded user_org_id
async def _complete_lesson(
    db, *, lesson_id: UUID, course_id: UUID, user_id: UUID | None = None, user_org_id: UUID | None = None
):
    # exactly one identity
    assert (user_id is None) ^ (user_org_id is None), "Provide exactly one of user_id or user_org_id"

    now = datetime.now(timezone.utc)

    cols = LessonProgress.__table__.columns.keys()
    payload = {"lesson_id": lesson_id, "course_id": course_id}
    if user_id is not None:
        payload["user_id"] = user_id
    else:
        payload["user_org_id"] = user_org_id

    if "is_completed" in cols:
        payload["is_completed"] = True
    if "completed_at" in cols:
        payload["completed_at"] = now

    db.add(LessonProgress(**payload))  # type: ignore[arg-type]
    await db.commit()


def _hdrs(h):
    # Accept dict / list[tuple] / "Bearer ..." / raw token
    if isinstance(h, dict):
        return h
    if isinstance(h, (list, tuple)):
        try:
            return dict(h)
        except Exception:
            pass
    if isinstance(h, str):
        val = h if h.lower().startswith("bearer ") else f"Bearer {h}"
        return {"Authorization": val}
    # Fallback: stringify
    return {"Authorization": str(h)}

# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_next_lesson__200_picks_next_published_unlocked(
    async_client: AsyncClient, db_session, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    # Published, PUBLIC course
    course = Course(
        title="Flow",
        slug=_rand_slug("Flow"),
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PUBLIC,
    )
    _set_if_has(course, created_by=user.id)
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    # Three published lessons (orders 1,2,3)
    l1 = Lesson(title="L1", order=1, is_published=True, course_id=course.id, organization_id=org.id)
    l2 = Lesson(title="L2", order=2, is_published=True, course_id=course.id, organization_id=org.id)
    l3 = Lesson(title="L3", order=3, is_published=True, course_id=course.id, organization_id=org.id)
    for l in (l1, l2, l3):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(l1)
    await db_session.refresh(l2)
    await db_session.refresh(l3)

    r = await async_client.get(f"{BASE}/{l1.id}/next", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == str(l2.id)


@pytest.mark.anyio
async def test_next_lesson__skips_unpublished_and_locked(
    async_client: AsyncClient, db_session, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    # Published public course
    course = Course(
        title="Skips",
        slug=_rand_slug("Skips"),
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PUBLIC,
    )
    _set_if_has(course, created_by=user.id)
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    # current=order1 (published), next candidate order2 is UNPUBLISHED, order3 is LOCKED (prereq=order2),
    # order4 is published & unlocked → should be returned.
    l1 = Lesson(title="A", order=1, is_published=True, course_id=course.id, organization_id=org.id)
    l2 = Lesson(title="B", order=2, is_published=False, course_id=course.id, organization_id=org.id)
    l3 = Lesson(title="C", order=3, is_published=True, course_id=course.id, organization_id=org.id)
    l4 = Lesson(title="D", order=4, is_published=True, course_id=course.id, organization_id=org.id)
    for l in (l1, l2, l3, l4):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(l1)
    await db_session.refresh(l2)
    await db_session.refresh(l3)
    await db_session.refresh(l4)

    # Lock l3 on l2
    db_session.add(
        LessonUnlockCondition(
            source_lesson_id=l2.id,
            target_lesson_id=l3.id,
            course_id=course.id,
            soft_unlock=False,
        )
    )
    await db_session.commit()

    r = await async_client.get(f"{BASE}/{l1.id}/next", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == str(l4.id)


@pytest.mark.anyio
async def test_next_lesson__404_no_next(async_client: AsyncClient, db_session, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = Course(
        title="Tail",
        slug=_rand_slug("Tail"),
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PUBLIC,
    )
    _set_if_has(course, created_by=user.id)
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    tail = Lesson(title="Only", order=1, is_published=True, course_id=course.id, organization_id=org.id)
    _set_if_has(tail, created_by=user.id)
    db_session.add(tail)
    await db_session.commit()
    await db_session.refresh(tail)

    r = await async_client.get(f"{BASE}/{tail.id}/next", headers=headers)
    assert r.status_code == 404, r.text
    assert "No next lesson" in r.json()["detail"]


@pytest.mark.anyio
async def test_next_lesson__404_current_missing(async_client: AsyncClient, db_session, org_user_with_token):
    user, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    # random UUID will behave as "None" result in service
    import uuid
    r = await async_client.get(f"{BASE}/{uuid.uuid4()}/next", headers=headers)
    assert r.status_code == 404, r.text


@pytest.mark.anyio
async def test_next_lesson__403_forbidden_private_without_enrollment(
    async_client: AsyncClient, db_session, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = Course(
        title="Private",
        slug=_rand_slug("Private"),
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PRIVATE,
    )
    _set_if_has(course, created_by=user.id)
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    l1 = Lesson(title="P1", order=1, is_published=True, course_id=course.id, organization_id=org.id)
    l2 = Lesson(title="P2", order=2, is_published=True, course_id=course.id, organization_id=org.id)
    for l in (l1, l2):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(l1)

    # No enrollment added → should be forbidden
    r = await async_client.get(f"{BASE}/{l1.id}/next", headers=headers)
    assert r.status_code == 403, r.text
    assert "access" in r.json()["detail"].lower()


@pytest.mark.anyio
async def test_next_lesson__caching_honors_short_ttl(
    async_client: AsyncClient, db_session, org_user_with_token
):
    """
    First call caches result for 15s. Change DB to make the next lesson different and
    verify the cached payload is still served immediately afterward.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = Course(
        title="Cache",
        slug=_rand_slug("Cache"),
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PUBLIC,
    )
    _set_if_has(course, created_by=user.id)
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    a = Lesson(title="A", order=1, is_published=True, course_id=course.id, organization_id=org.id)
    b = Lesson(title="B", order=2, is_published=True, course_id=course.id, organization_id=org.id)
    c = Lesson(title="C", order=3, is_published=True, course_id=course.id, organization_id=org.id)
    for l in (a, b, c):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(a)
    await db_session.refresh(b)
    await db_session.refresh(c)

    r1 = await async_client.get(f"{BASE}/{a.id}/next", headers=headers)
    assert r1.status_code == 200, r1.text
    assert r1.json()["id"] == str(b.id)

    # Change DB to try to affect next pick
    b.is_published = False
    await db_session.commit()

    # Should still get cached result (B) immediately
    r2 = await async_client.get(f"{BASE}/{a.id}/next", headers=headers)
    assert r2.status_code == 200
    assert r2.json()["id"] == str(b.id)


@pytest.mark.anyio
async def test_next_lesson__identity_aware_cache(
    async_client: AsyncClient, db_session, org_user_with_token, user_with_token
):
    """
    Cache key includes identity (user vs user_org + id). Make next lesson unlocked for org_user
    but locked for plain user. Ensure cached result for org_user doesn't leak to user.
    """
    # org_user principal (token includes active_org, but the route dependency returns a User)
    org_user, org_headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    # plain user principal (no org context)
    plain_user, user_headers = await user_with_token()

    # PUBLIC published course in org; both identities can view
    course = Course(
        title="Ident",
        slug=_rand_slug("Ident"),
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PUBLIC,
    )
    _set_if_has(course, created_by=org_user.id)
    db_session.add(course)
    await db_session.commit()
    await db_session.refresh(course)

    # Lessons: current=A(1), next candidate=B(2) with prereq=A
    a = Lesson(title="A", order=1, is_published=True, course_id=course.id, organization_id=org.id)
    b = Lesson(title="B", order=2, is_published=True, course_id=course.id, organization_id=org.id)
    db_session.add_all([a, b])
    await db_session.commit()
    await db_session.refresh(a)
    await db_session.refresh(b)

    # Add unlock B <- A (hard)
    unlock = LessonUnlockCondition(
        source_lesson_id=a.id,
        target_lesson_id=b.id,
        course_id=course.id,
        soft_unlock=False,
    )
    db_session.add(unlock)
    await db_session.commit()

    # Compute cache keys EXACTLY like the route does:
    # ident = "user" (the dependency yields a User), actor_id = <user.id>
    cache_key_org  = f"next:v1:lesson:{a.id}:user:{org_user.id}"
    cache_key_user = f"next:v1:lesson:{a.id}:user:{plain_user.id}"

    # Clear any leftover cache
    try:
        await redis_wrapper.client.delete(cache_key_org)
        await redis_wrapper.client.delete(cache_key_user)
    except Exception:
        pass

    # Mark A completed for the ORG user's *user_id* (not user_org_id),
    # because the route checks LessonProgress for the principal it sees (User).
    cols = LessonProgress.__table__.columns.keys()
    payload = {
        "lesson_id": a.id,
        "course_id": course.id,
        "user_id":  org_user.id,
    }
    if "is_completed" in cols:
        payload["is_completed"] = True
    if "completed_at" in cols:
        payload["completed_at"] = datetime.now(timezone.utc)
    db_session.add(LessonProgress(**payload))  # type: ignore[arg-type]
    await db_session.commit()

    # 1) org_user: expect B (and cache populated under cache_key_org)
    r_org1 = await async_client.get(f"{BASE}/{a.id}/next", headers=_hdrs(org_headers))
    print("[DEBUG] org_user GET /next status:", r_org1.status_code)
    print("[DEBUG] org_user GET /next body:", r_org1.text)
    assert r_org1.status_code == 200
    assert r_org1.json()["id"] == str(b.id)

    # Inspect cache after org_user request
    try:
        cached_org_raw  = await redis_wrapper.client.get(cache_key_org)
        cached_user_raw = await redis_wrapper.client.get(cache_key_user)
        cached_org  = cached_org_raw.decode("utf-8")  if isinstance(cached_org_raw,  (bytes, bytearray)) else cached_org_raw
        cached_user = cached_user_raw.decode("utf-8") if isinstance(cached_user_raw, (bytes, bytearray)) else cached_user_raw
        print("[DEBUG] cache_key_org:", cache_key_org)
        print("[DEBUG] cache_key_org value:", cached_org)
        print("[DEBUG] cache_key_user:", cache_key_user)
        print("[DEBUG] cache_key_user value:", cached_user)
    except Exception as e:
        print("[DEBUG] Redis read failed:", repr(e))

    # 2) plain user: still locked → 404; must NOT reuse org_user's cached value
    r_user = await async_client.get(f"{BASE}/{a.id}/next", headers=_hdrs(user_headers))
    print("[DEBUG] plain_user GET /next status:", r_user.status_code)
    print("[DEBUG] plain_user GET /next body:", r_user.text)
    assert r_user.status_code == 404, r_user.text
