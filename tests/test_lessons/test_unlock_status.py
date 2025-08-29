import uuid
import pytest
from httpx import AsyncClient

from app.db.models import Course, Lesson
from app.schemas.enums import OrgRole, CourseVisibility

BASE = "/api/v1/lessons"


def _normalize_headers(h):
    return {"Authorization": h} if isinstance(h, str) else h


def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


@pytest.mark.anyio
async def test_unlock_status__404_not_found(async_client: AsyncClient, org_user_with_token):
    _user, headers, _org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)
    missing = uuid.uuid4()

    r = await async_client.get(f"{BASE}/{missing}/unlock-status", headers=headers)
    assert r.status_code == 404, r.text


@pytest.mark.anyio
async def test_unlock_status__403_forbidden_no_access(async_client: AsyncClient, db_session, org_user_with_token):
    """
    PRIVATE course without enrollment → forbidden.
    NOTE: This assumes your route path is `/{lesson_id}/unlock-status`
    (i.e., router is mounted under /api/v1/lessons).
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(
        title="Priv",
        slug=f"priv-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PRIVATE,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    lesson = Lesson(title="L", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(lesson, created_by=user.id)
    db_session.add(lesson); await db_session.commit(); await db_session.refresh(lesson)

    r = await async_client.get(f"{BASE}/{lesson.id}/unlock-status", headers=headers)
    # If you still get {"detail":"Not Found"}, fix your route to use "/{lesson_id}/unlock-status"
    assert r.status_code == 403, r.text


@pytest.mark.anyio
async def test_unlock_status__200_unlocked_basic(async_client: AsyncClient, db_session, org_user_with_token, monkeypatch):
    """
    PUBLIC course; service returns unlocked=True.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(
        title="Pub",
        slug=f"pub-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PUBLIC,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    lesson = Lesson(title="L", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(lesson, created_by=user.id)
    db_session.add(lesson); await db_session.commit(); await db_session.refresh(lesson)

    async def _fake(db, learner, lesson):
        return True, ["no prerequisites"]

    # Patch the *service* function where it really lives:
    monkeypatch.setattr(
        "app.api.v1.lessons.unlocks.is_lesson_unlocked_for_user",
        _fake,
        raising=True,
    )

    r = await async_client.get(f"{BASE}/{lesson.id}/unlock-status", headers=headers)
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["lesson_id"] == str(lesson.id)
    assert payload["is_unlocked"] is True
    assert payload["reasons"] == ["no prerequisites"]
    assert r.headers.get("ETag")
    assert r.headers.get("Cache-Control")


@pytest.mark.anyio
async def test_unlock_status__200_locked_missing_hard(async_client: AsyncClient, db_session, org_user_with_token, monkeypatch):
    """
    PUBLIC course; service returns unlocked=False.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(
        title="Pub2",
        slug=f"pub2-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PUBLIC,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    lesson = Lesson(title="L2", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(lesson, created_by=user.id)
    db_session.add(lesson); await db_session.commit(); await db_session.refresh(lesson)

    async def _fake(db, learner, lesson):
        return False, ["Missing hard prerequisites"]

    monkeypatch.setattr(
        "app.api.v1.lessons.unlocks.is_lesson_unlocked_for_user",
        _fake,
        raising=True,
    )

    r = await async_client.get(f"{BASE}/{lesson.id}/unlock-status", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["is_unlocked"] is False
    assert data["reasons"] == ["Missing hard prerequisites"]


@pytest.mark.anyio
async def test_unlock_status__etag_304(async_client: AsyncClient, db_session, org_user_with_token, monkeypatch):
    """
    200 + ETag then 304 with If-None-Match.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(
        title="PubEtag",
        slug=f"puE-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PUBLIC,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    lesson = Lesson(title="L3", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(lesson, created_by=user.id)
    db_session.add(lesson); await db_session.commit(); await db_session.refresh(lesson)

    async def _fake(db, learner, lesson):
        return True, ["cached"]

    monkeypatch.setattr(
        "app.api.v1.lessons.unlocks.is_lesson_unlocked_for_user",
        _fake,
        raising=True,
    )

    r1 = await async_client.get(f"{BASE}/{lesson.id}/unlock-status", headers=headers)
    assert r1.status_code == 200
    etag = r1.headers.get("ETag")
    assert etag

    r2 = await async_client.get(
        f"{BASE}/{lesson.id}/unlock-status",
        headers={**headers, "If-None-Match": etag},
    )
    assert r2.status_code == 304
    assert r2.headers.get("ETag") == etag
    assert not r2.text or r2.text == ""


@pytest.mark.anyio
async def test_unlock_status__etag_changes_when_body_changes_bypass_cache(async_client: AsyncClient, db_session, org_user_with_token, monkeypatch):
    """
    Force a fresh compute via Cache-Control: no-cache (don’t touch redis_wrapper.client).
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    headers = _normalize_headers(headers)

    c = Course(
        title="PubEvol",
        slug=f"puEv-{uuid.uuid4().hex[:8]}",
        organization_id=org.id,
        is_published=True,
        visibility=CourseVisibility.PUBLIC,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    lesson = Lesson(title="L4", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(lesson, created_by=user.id)
    db_session.add(lesson); await db_session.commit(); await db_session.refresh(lesson)

    async def _fake1(db, learner, lesson): return True,  ["state1"]
    async def _fake2(db, learner, lesson): return False, ["state2"]

    target = "app.api.v1.lessons.unlocks.is_lesson_unlocked_for_user"
    monkeypatch.setattr(target, _fake1, raising=True)

    r1 = await async_client.get(f"{BASE}/{lesson.id}/unlock-status", headers=headers)
    assert r1.status_code == 200
    etag1 = r1.headers.get("ETag")
    assert etag1

    # Switch implementation and bypass cache to force recompute
    monkeypatch.setattr(target, _fake2, raising=True)
    r2 = await async_client.get(
        f"{BASE}/{lesson.id}/unlock-status",
        headers={**headers, "Cache-Control": "no-cache"},
    )
    assert r2.status_code == 200
    etag2 = r2.headers.get("ETag")
    assert etag2 and etag2 != etag1
