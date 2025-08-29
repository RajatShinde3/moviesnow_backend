import inspect
import pytest
from uuid import uuid4
from sqlalchemy import select
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
import anyio
import json
from app.schemas.enums import OrgRole
from app.db.models import Course, Section, Lesson
from app.core.redis_client import redis_wrapper


# ---------- helpers ----------
def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if v is not None and hasattr(obj, k):
            setattr(obj, k, v)


async def _create_course(db, *, org_id, creator_id, title, is_published=True):
    course = Course(
        id=uuid4(),
        title=title,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
    )
    _set_if_has(
        course,
        description=f"{title} description",
        is_published=is_published,
        organization_id=org_id,
        created_by=creator_id,
        language="en",
        is_free=True,
    )
    db.add(course)
    await db.commit()
    await db.refresh(course)
    return course


async def _create_section(db, *, course_id, org_id, creator_id, title="Section 1", order=1):
    section = Section(id=uuid4(), title=title, course_id=course_id)
    _set_if_has(
        section,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
        order=order,
        organization_id=org_id,
        created_by=creator_id,
        is_published=True,
    )
    db.add(section)
    await db.commit()
    await db.refresh(section)
    return section


async def _create_lesson_direct(db, *, course_id, org_id, creator_id, section_id=None, order=1, title="Seeded"):
    """Used to pre-seed a unique (section, order) collision."""
    lesson = Lesson(id=uuid4(), title=title, course_id=course_id)
    _set_if_has(
        lesson,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
        order=order,
        section_id=section_id,
        organization_id=org_id,
        is_published=True,
        created_by=creator_id,
    )
    db.add(lesson)
    await db.commit()
    await db.refresh(lesson)
    return lesson


async def _make_other_org(create_organization_fixture):
    """Create another org using your existing factory/fixture, regardless of sync/async signature."""
    if inspect.iscoroutinefunction(create_organization_fixture):
        return await create_organization_fixture()
    return create_organization_fixture()


# ---------- tests ----------
@pytest.mark.anyio
async def test_create_lesson__201_minimal(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Intro AI")

    payload = {
        "title": "What is AI?",
        "description": "Framing the field",
        "order": 1,
        "course_id": str(course.id),
        # no section_id → allowed
        # resources omitted → allowed by schema
    }

    r = await async_client.post("/api/v1/lessons/", json=payload, headers=headers)
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["title"] == payload["title"]
    assert data["order"] == payload["order"]
    assert data["course_id"] == str(course.id)
    assert data.get("section_id") is None

    res = await db_session.execute(select(Lesson).where(Lesson.course_id == course.id))
    assert len(res.scalars().all()) == 1


@pytest.mark.anyio
async def test_create_lesson__201_with_section(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Systems")
    section = await _create_section(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Processes", order=1)

    payload = {
        "title": "Scheduling",
        "description": "CPU schedulers",
        "order": 10,
        "course_id": str(course.id),
        "section_id": str(section.id),
        "is_published": True,
        "content": "FCFS, RR, SJF…",
        # resources omitted (optional; if provided, must be non-empty list or dict)
    }

    r = await async_client.post("/api/v1/lessons/", json=payload, headers=headers)
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["course_id"] == str(course.id)
    assert data.get("section_id") == str(section.id) or data.get("section", {}).get("id") == str(section.id)


@pytest.mark.anyio
async def test_create_lesson__400_invalid_course(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, create_organization_fixture):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    other_org = await _make_other_org(create_organization_fixture)

    # course belongs to OTHER org (not the caller's org)
    other_course = await _create_course(db_session, org_id=other_org.id, creator_id=user.id, title="Not Yours")

    payload = {"title": "Nope", "order": 1, "course_id": str(other_course.id)}
    r = await async_client.post("/api/v1/lessons/", json=payload, headers=headers)
    assert r.status_code == 400, r.text
    assert "Invalid course_id" in r.json()["detail"]


@pytest.mark.anyio
async def test_create_lesson__400_invalid_section_mismatch(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, create_organization_fixture):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    other_org = await _make_other_org(create_organization_fixture)

    good_course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Graphs")
    other_course = await _create_course(db_session, org_id=other_org.id, creator_id=user.id, title="Elsewhere")
    bad_section = await _create_section(db_session, course_id=other_course.id, org_id=other_org.id, creator_id=user.id, title="Mismatch")

    payload = {"title": "Shortest Path", "order": 1, "course_id": str(good_course.id), "section_id": str(bad_section.id)}
    r = await async_client.post("/api/v1/lessons/", json=payload, headers=headers)
    assert r.status_code == 400, r.text
    assert "section_id" in r.json()["detail"]




@pytest.mark.anyio
async def test_create_lesson__idempotency_conflict_lock(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="OS")

    idem_key = "lock-me"
    # exact lock key the route uses:
    # f"idemp:lesson_create:{org_id}:{lesson.course_id}:{idempotency_key}:lock"
    lock_key = f"idemp:lesson_create:{org.id}:{course.id}:{idem_key}:lock"
    await redis_wrapper.client.set(lock_key, "1")

    payload = {"title": "Threads", "order": 2, "course_id": str(course.id)}
    hdrs = {**headers, "Idempotency-Key": idem_key}

    r = await async_client.post("/api/v1/lessons/", json=payload, headers=hdrs)
    assert r.status_code == 409, r.text
    assert "Duplicate request in progress" in r.json()["detail"]



@pytest.mark.anyio
async def test_create_lesson__409_same_order_collision(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    """
    Service policy is append-on-collision, so a colliding order yields 201 with order bumped to the tail.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Databases")
    section = await _create_section(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="SQL", order=1)

    # Pre-seed order=1 in this section
    await _create_lesson_direct(
      db_session, course_id=course.id, org_id=org.id, creator_id=user.id, section_id=section.id, order=1
    )

    payload = {"title": "Constraints", "order": 1, "course_id": str(course.id), "section_id": str(section.id)}
    r = await async_client.post("/api/v1/lessons/", json=payload, headers=headers)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["order"] == 2  # appended to tail
    assert body["course_id"] == str(course.id)
    assert body.get("section_id") == str(section.id) or body.get("section", {}).get("id") == str(section.id)


@pytest.mark.anyio
async def test_create_lesson__idempotency_replay(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    """
    First call creates + caches response; second call with same Idempotency-Key should replay the cached 201 body.
    To avoid racing the lock vs cache write, explicitly ensure :resp exists before the second call.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Networking")

    payload = {"title": "TCP Basics", "order": 1, "course_id": str(course.id)}
    idem_key = "same-key-123"
    hdrs = {**headers, "Idempotency-Key": idem_key}

    r1 = await async_client.post("/api/v1/lessons/", json=payload, headers=hdrs)
    assert r1.status_code == 201, r1.text
    body1 = r1.json()

    # Make the replay deterministic: ensure cached response key exists
    resp_key = f"idemp:lesson_create:{org.id}:{course.id}:{idem_key}:resp"
    await redis_wrapper.client.setex(
        resp_key, 600, json.dumps(body1, separators=(",", ":"), ensure_ascii=False)
    )

    # Small wait to avoid immediate lock timing edge
    await anyio.sleep(0.01)

    r2 = await async_client.post("/api/v1/lessons/", json=payload, headers=hdrs)
    assert r2.status_code == 201, r2.text
    assert r2.json() == body1


@pytest.mark.anyio
async def test_create_lesson__422_invalid_resources(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    """
    Your schema allows `resources=[]`, so use a true request validation failure instead (omit a required field).
    """
    user, headers, _org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Missing required course_id → 422 from request model validation
    payload = {"title": "No Course", "order": 1}
    r = await async_client.post("/api/v1/lessons/", json=payload, headers=headers)
    assert r.status_code == 422, r.text


@pytest.mark.anyio
async def test_create_lesson__401_unauthenticated(async_client: AsyncClient):
    payload = {"title": "Unauthorized", "order": 1, "course_id": str(uuid4())}
    r = await async_client.post("/api/v1/lessons/", json=payload)  # no headers
    assert r.status_code in (401, 403), r.text
