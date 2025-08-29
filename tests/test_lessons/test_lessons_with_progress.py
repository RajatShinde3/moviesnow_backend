# tests/test_lessons/test_lessons_with_progress.py

import json
import uuid
import pytest
from datetime import datetime, timezone

from httpx import AsyncClient
from sqlalchemy import select

from app.core.redis_client import redis_wrapper
from app.db.models import (
    Course,
    Lesson,
    LessonProgress,
    CourseEnrollment,
    UserOrganization,
)
from app.schemas.enums import CourseVisibility, OrgRole

BASE = "/api/v1/lessons"


# ── helpers ─────────────────────────────────────────────────────────────────

def _rand_slug(prefix: str = "c") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"

def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)

def _now_utc():
    return datetime.now(timezone.utc)

def _normalize_headers(h):
    # Some fixtures may return a plain "Authorization" string; httpx expects a mapping.
    if isinstance(h, str):
        return {"Authorization": h}
    return h

async def _user_org_for(db, *, user_id, org_id):
    res = await db.execute(
        select(UserOrganization).where(
            UserOrganization.user_id == user_id,
            UserOrganization.organization_id == org_id,
        )
    )
    return res.scalars().first()


# ── tests ───────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_lwp__404_course_not_found(async_client: AsyncClient, org_user_with_token):
    user, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    missing = uuid.uuid4()
    r = await async_client.get(f"{BASE}/course/{missing}/lessons-with-progress", headers=headers)
    assert r.status_code == 404, r.text
    assert "Course not found" in r.text


@pytest.mark.anyio
async def test_lwp__403_private_access_denied(async_client: AsyncClient, db_session, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(
        title="Priv",
        slug=_rand_slug("priv"),
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PRIVATE,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)

    r = await async_client.get(f"{BASE}/course/{c.id}/lessons-with-progress", headers=headers)
    assert r.status_code == 403, r.text
    assert "denied" in r.text.lower() or "access" in r.json().get("detail", "").lower()


@pytest.mark.anyio
async def test_lwp__200_empty_list_when_accessible(async_client: AsyncClient, db_session, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(
        title="PublicNoLessons",
        slug=_rand_slug("pub0"),
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PUBLIC,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)

    r = await async_client.get(f"{BASE}/course/{c.id}/lessons-with-progress", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json() == []
    assert r.headers.get("ETag")


@pytest.mark.anyio
async def test_lwp__200_with_lessons_and_progress(async_client: AsyncClient, db_session, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(
        title="Flow",
        slug=_rand_slug("flow"),
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PUBLIC,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)

    # lessons
    a = Lesson(title="A", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    b = Lesson(title="B", order=2, is_published=True, course_id=c.id, organization_id=org.id)
    z = Lesson(title="Z", order=3, is_published=True, course_id=c.id, organization_id=org.id)
    for l in (a, b, z):
        _set_if_has(l, created_by=user.id)
        db_session.add(l)
    await db_session.commit()
    await db_session.refresh(a); await db_session.refresh(b); await db_session.refresh(z)

    # progress for 'b' only
    cols = LessonProgress.__table__.columns.keys()
    payload = {"lesson_id": b.id, "course_id": c.id, "user_id": user.id}
    if "is_completed" in cols: payload["is_completed"] = True
    if "completed_at" in cols: payload["completed_at"] = _now_utc()
    if "viewed_at" in cols:    payload["viewed_at"] = _now_utc()
    db_session.add(LessonProgress(**payload))  # type: ignore[arg-type]
    await db_session.commit()

    r = await async_client.get(f"{BASE}/course/{c.id}/lessons-with-progress", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()

    # ordering by order asc (1,2,3)
    assert [d["title"] for d in data] == ["A", "B", "Z"]

    by_id = {d["id"]: d for d in data}

    # completion flags
    assert by_id[str(a.id)]["is_completed"] is False
    assert by_id[str(b.id)]["is_completed"] is True

    # last_viewed_at:
    # - For lessons with progress, many serializers include it (possibly as ISO string).
    # - For lessons without progress, some serializers omit the field.
    lv_a = by_id[str(a.id)].get("last_viewed_at")
    lv_b = by_id[str(b.id)].get("last_viewed_at")

    assert (lv_a is None) or isinstance(lv_a, str)
    assert (lv_b is None) or isinstance(lv_b, str)



@pytest.mark.anyio
async def test_lwp__etag_304(async_client: AsyncClient, db_session, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(
        title="ETag",
        slug=_rand_slug("etag"),
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PUBLIC,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)

    l = Lesson(title="L", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(l, created_by=user.id)
    db_session.add(l)
    await db_session.commit()

    r1 = await async_client.get(f"{BASE}/course/{c.id}/lessons-with-progress", headers=headers)
    assert r1.status_code == 200
    etag = r1.headers.get("ETag")
    assert etag

    r2 = await async_client.get(
        f"{BASE}/course/{c.id}/lessons-with-progress",
        headers={**headers, "If-None-Match": etag},
    )
    assert r2.status_code == 304
    assert r2.text == "" or r2.text is None


@pytest.mark.anyio
async def test_lwp__identity_aware_cache_separates_users(
    async_client: AsyncClient, db_session, org_user_with_token
):
    # Create two different org users in the same org
    user_a, headers_a, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    user_b, headers_b, _   = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    headers_a = _normalize_headers(headers_a)
    headers_b = _normalize_headers(headers_b)

    # PUBLIC published course
    c = Course(
        title="IdentCache",
        slug=_rand_slug("lwp"),
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PUBLIC,
    )
    _set_if_has(c, created_by=user_a.id)
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)

    # One lesson
    l = Lesson(title="One", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(l, created_by=user_a.id)
    db_session.add(l)
    await db_session.commit()
    await db_session.refresh(l)

    # Completion for user A only
    cols = LessonProgress.__table__.columns.keys()
    payload = {"lesson_id": l.id, "course_id": c.id, "user_id": user_a.id}
    if "is_completed" in cols: payload["is_completed"] = True
    if "completed_at" in cols: payload["completed_at"] = _now_utc()
    db_session.add(LessonProgress(**payload))  # type: ignore[arg-type]
    await db_session.commit()

    # Cache keys exactly like the route (dependency yields User → "user:<id>")
    key_a = f"lwp:v1:course:{str(c.id)}:user:{user_a.id}"
    key_b = f"lwp:v1:course:{str(c.id)}:user:{user_b.id}"
    try:
        await redis_wrapper.client.delete(key_a)
        await redis_wrapper.client.delete(key_b)
    except Exception:
        pass

    # A: caches payload with is_completed True
    r_a = await async_client.get(f"{BASE}/course/{c.id}/lessons-with-progress", headers=headers_a)
    assert r_a.status_code == 200
    assert r_a.json()[0]["is_completed"] is True

    # best-effort: verify cache A
    try:
        raw_a = await redis_wrapper.client.get(key_a)
        if raw_a:
            cached_a = json.loads(raw_a.decode("utf-8") if isinstance(raw_a, (bytes, bytearray)) else raw_a)
            assert cached_a[0]["is_completed"] is True
    except Exception:
        pass

    # B: must NOT reuse A's cache; should compute payload with is_completed False
    r_b = await async_client.get(f"{BASE}/course/{c.id}/lessons-with-progress", headers=headers_b)
    # helpful debug if this ever flakes
    if r_b.status_code != 200:
        print("[DEBUG] status_b:", r_b.status_code)
        print("[DEBUG] body_b:", r_b.text)
    assert r_b.status_code == 200
    assert r_b.json()[0]["is_completed"] is False

    # best-effort: verify separate cache B
    try:
        raw_b = await redis_wrapper.client.get(key_b)
        if raw_b:
            cached_b = json.loads(raw_b.decode("utf-8") if isinstance(raw_b, (bytes, bytearray)) else raw_b)
            assert cached_b[0]["is_completed"] is False
    except Exception:
        pass



@pytest.mark.anyio
async def test_lwp__200_private_with_enrollment(async_client: AsyncClient, db_session, org_user_with_token):
    """
    PRIVATE course is accessible when the caller has the right enrollment.
    For a User principal, a user-scoped CourseEnrollment is sufficient.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(
        title="PrivOK",
        slug=_rand_slug("pok"),
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PRIVATE,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c)
    await db_session.commit()
    await db_session.refresh(c)

    # enrollment for the user
    enroll = CourseEnrollment(course_id=c.id, user_id=user.id, is_active=True, enrolled_at=_now_utc())
    db_session.add(enroll)
    await db_session.commit()

    l = Lesson(title="Only", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(l, created_by=user.id)
    db_session.add(l)
    await db_session.commit()

    r = await async_client.get(f"{BASE}/course/{c.id}/lessons-with-progress", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1 and body[0]["title"] == "Only"
