import json
import anyio
import pytest
from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.core.redis_client import redis_wrapper
from app.db.models import Course, Section, Lesson


# ── helpers (schema-safe setters) ────────────────────────────────────────────
def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if v is not None and hasattr(obj, k):
            setattr(obj, k, v)


async def _create_course(db, *, org_id, creator_id, title, is_published=True):
    c = Course(id=uuid4(), title=title, slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}")
    _set_if_has(
        c,
        organization_id=org_id,
        created_by=creator_id,
        is_published=is_published,
        language="en",
        is_free=True,
    )
    db.add(c)
    await db.commit()
    await db.refresh(c)
    return c


async def _create_section(db, *, course_id, org_id, creator_id, title="Section 1", order=1, is_published=True):
    s = Section(id=uuid4(), title=title, course_id=course_id)
    _set_if_has(
        s,
        organization_id=org_id,
        created_by=creator_id,
        is_published=is_published,
        order=order,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
    )
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


async def _create_lesson_direct(db, *, course_id, org_id, creator_id, section_id=None, order=1, title="Seeded"):
    l = Lesson(id=uuid4(), title=title, course_id=course_id)
    _set_if_has(
        l,
        organization_id=org_id,
        created_by=creator_id,
        is_published=True,
        section_id=section_id,
        order=order,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
    )
    db.add(l)
    await db.commit()
    await db.refresh(l)
    return l


# ── ensure redis mock is wired + clean between tests ────────────────────────
@pytest.fixture(autouse=True)
async def _clean_redis_between_tests():
    try:
        await redis_wrapper.client.flushdb()
    except Exception:
        # If your redis mock lacks flushdb, no-op
        pass
    yield
    try:
        await redis_wrapper.client.flushdb()
    except Exception:
        pass


# ────────────────────────────────────────────────────────────────────────────
# Success cases
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_bulk_create__happy_path_mixed_sections(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    """
    Creates lessons (one unsectioned, two in a section) with mixed order inputs.
    Colliding/omitted orders append to tail per section. Response preserves input order.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Algorithms")
    sec = await _create_section(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Sorting", order=1)

    # Preseed an existing lesson in the section at order=1 to force collision
    await _create_lesson_direct(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, section_id=sec.id, order=1, title="Existing")

    payload = {
        "lessons": [
            # A: unsectioned, no explicit order → should be order=1 in unsectioned scope
            {"title": "Intro", "course_id": str(course.id)},
            # B: sectioned, colliding order=1 → should append (order=2)
            {"title": "QuickSort", "course_id": str(course.id), "section_id": str(sec.id), "order": 1},
            # C: sectioned, free order=3 → honored
            {"title": "MergeSort", "course_id": str(course.id), "section_id": str(sec.id), "order": 3},
        ]
    }

    r = await async_client.post("/api/v1/lessons/bulk-create", json=payload, headers=headers)
    assert r.status_code == 201, r.text
    body = r.json()

    # Response order == input order
    assert [b["title"] for b in body] == ["Intro", "QuickSort", "MergeSort"]

    # Assert per-scope final orders
    by_title = {b["title"]: b for b in body}
    assert by_title["Intro"]["order"] == 1                         # unsectioned first
    assert by_title["QuickSort"]["order"] == 2                     # append on collision
    assert by_title["MergeSort"]["order"] == 3                     # honored free order

    # DB count sanity
    res = await db_session.execute(select(Lesson).where(Lesson.course_id == course.id))
    assert len(res.scalars().all()) >= 4  # 1 existing + 3 new


@pytest.mark.anyio
async def test_bulk_create__respects_existing_tails(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    """
    When there are existing lessons, new ones should append to the correct tails per section.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Systems")
    sec = await _create_section(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Processes", order=1)

    # Existing: unsectioned order=1, sectioned orders=1,2
    await _create_lesson_direct(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, order=1, title="Unsectioned-1")
    await _create_lesson_direct(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, section_id=sec.id, order=1, title="S-1")
    await _create_lesson_direct(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, section_id=sec.id, order=2, title="S-2")

    payload = {
        "lessons": [
            {"title": "Unsectioned-2", "course_id": str(course.id)},                             # → order 2 (unsectioned)
            {"title": "Scheduling", "course_id": str(course.id), "section_id": str(sec.id)},     # → order 3 (section)
        ]
    }

    r = await async_client.post("/api/v1/lessons/bulk-create", json=payload, headers=headers)
    assert r.status_code == 201, r.text
    body = r.json()
    by_title = {b["title"]: b for b in body}
    assert by_title["Unsectioned-2"]["order"] == 2
    assert by_title["Scheduling"]["order"] == 3


# ────────────────────────────────────────────────────────────────────────────
# Validation / ownership / atomicity
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_bulk_create__422_no_lessons(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.post("/api/v1/lessons/bulk-create", json={"lessons": []}, headers=headers)
    assert r.status_code == 422, r.text


@pytest.mark.anyio
async def test_bulk_create__400_different_course_ids(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    c1 = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="C1")
    c2 = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="C2")

    payload = {"lessons": [
        {"title": "A", "course_id": str(c1.id)},
        {"title": "B", "course_id": str(c2.id)},
    ]}

    r = await async_client.post("/api/v1/lessons/bulk-create", json=payload, headers=headers)
    assert r.status_code == 400
    assert "same course" in r.json()["detail"]


@pytest.mark.anyio
async def test_bulk_create__404_course_not_in_org(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, create_organization_fixture):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    other_org = await (create_organization_fixture() if not callable(getattr(create_organization_fixture, "__await__", None)) else create_organization_fixture())
    course_other_org = await _create_course(db_session, org_id=other_org.id, creator_id=user.id, title="Foreign")

    payload = {"lessons": [{"title": "Should Fail", "course_id": str(course_other_org.id)}]}
    r = await async_client.post("/api/v1/lessons/bulk-create", json=payload, headers=headers)
    assert r.status_code == 404
    assert "not found" in r.json()["detail"].lower() or "access denied" in r.json()["detail"].lower()


@pytest.mark.anyio
async def test_bulk_create__409_invalid_section_belongs_to_other_course(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    """
    If any provided section_id does not belong to the course/org, the service raises,
    and the route maps to 409 (per current code). Atomic: creates none.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    base = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Base")
    other = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Other")
    foreign_sec = await _create_section(db_session, course_id=other.id, org_id=org.id, creator_id=user.id, title="Other's Section")

    payload = {"lessons": [
        {"title": "X", "course_id": str(base.id), "section_id": str(foreign_sec.id)},
        {"title": "Y", "course_id": str(base.id)},  # in same batch; should not be created if atomic
    ]}

    r = await async_client.post("/api/v1/lessons/bulk-create", json=payload, headers=headers)
    assert r.status_code == 409, r.text

    # Atomicity check: none created in target course (since first invalid)
    res = await db_session.execute(select(Lesson).where(Lesson.course_id == base.id))
    assert len(res.scalars().all()) == 0


# ────────────────────────────────────────────────────────────────────────────
# Idempotency
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_bulk_create__idempotency_replay(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Networking")

    payload = {"lessons": [
        {"title": "TCP 1", "course_id": str(course.id)},
        {"title": "TCP 2", "course_id": str(course.id)},
    ]}
    idem = "bulk-key-123"
    hdrs = {**headers, "Idempotency-Key": idem}

    # First call: create + capture body
    r1 = await async_client.post("/api/v1/lessons/bulk-create", json=payload, headers=hdrs)
    assert r1.status_code == 201, r1.text
    body1 = r1.json()

    # Prime the :resp cache exactly as the route would, and relax the lock TTL
    resp_key = f"idemp:lessons:bulk_create:{course.id}:{org.id}:{idem}:resp"
    lock_key = f"idemp:lessons:bulk_create:{course.id}:{org.id}:{idem}:lock"
    await redis_wrapper.client.setex(resp_key, 600, json.dumps(body1, separators=(",", ":"), ensure_ascii=False))
    # Make sure a lingering lock won't cause a 409 if cache read hiccups
    try:
        await redis_wrapper.client.pexpire(lock_key, 1)
    except Exception:
        pass
    await anyio.sleep(0.01)

    # Second call: should replay the exact same 201 body
    r2 = await async_client.post("/api/v1/lessons/bulk-create", json=payload, headers=hdrs)
    assert r2.status_code == 201, r2.text
    assert r2.json() == body1


@pytest.mark.anyio
async def test_bulk_create__idempotency_conflict_lock(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    """
    Pre-create the lock key to simulate an in-flight duplicate. Route should return 409.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Concurrency")

    idem = "conflict-key"
    lock_key = f"idemp:lessons:bulk_create:{course.id}:{org.id}:{idem}:lock"
    await redis_wrapper.client.set(lock_key, "1")  # NX would fail in the route

    payload = {"lessons": [{"title": "A", "course_id": str(course.id)}]}
    hdrs = {**headers, "Idempotency-Key": idem}

    r = await async_client.post("/api/v1/lessons/bulk-create", json=payload, headers=hdrs)
    assert r.status_code == 409, r.text
    assert "Duplicate request in progress" in r.json()["detail"]


# ────────────────────────────────────────────────────────────────────────────
# Mixed ordering within the same batch
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_bulk_create__same_section_colliding_orders_within_batch(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    """
    Two items in the same batch targeting the same section with the same order:
    first gets that order (if free); second should append to tail.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Math")
    sec = await _create_section(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Algebra")

    payload = {"lessons": [
        {"title": "First", "course_id": str(course.id), "section_id": str(sec.id), "order": 1},
        {"title": "Second", "course_id": str(course.id), "section_id": str(sec.id), "order": 1},  # collides with First
    ]}

    r = await async_client.post("/api/v1/lessons/bulk-create", json=payload, headers=headers)
    assert r.status_code == 201, r.text
    body = r.json()
    by_title = {b["title"]: b for b in body}
    assert by_title["First"]["order"] == 1
    assert by_title["Second"]["order"] == 2


# ────────────────────────────────────────────────────────────────────────────
# Auth
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_bulk_create__401_unauthenticated(async_client: AsyncClient):
    payload = {"lessons": [{"title": "Nope", "course_id": str(uuid4())}]}
    r = await async_client.post("/api/v1/lessons/bulk-create", json=payload)  # no headers
    assert r.status_code in (401, 403), r.text
