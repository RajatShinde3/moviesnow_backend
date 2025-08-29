import pytest
from uuid import uuid4
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.models import Course, Section, Lesson
from app.schemas.enums import OrgRole


# -----------------------------
# Helpers (schema-safe setters)
# -----------------------------
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


async def _create_lesson(db, *, course_id, org_id, creator_id, title="Lesson", section_id=None, order=1, is_published=True):
    l = Lesson(id=uuid4(), title=title, course_id=course_id)
    _set_if_has(
        l,
        organization_id=org_id,
        created_by=creator_id,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
        order=order,
        section_id=section_id,
        is_published=is_published,
    )
    db.add(l)
    await db.commit()
    await db.refresh(l)
    return l


# ============================================================
# ✅ Happy path: update basic fields, ETag present
# ============================================================
@pytest.mark.anyio
async def test_update_lesson__200_basic(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Algorithms")
    lesson = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Old", order=1)

    payload = {"title": "New Title", "description": "  Trim me  "}
    r = await async_client.put(f"/api/v1/lessons/{lesson.id}", json=payload, headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["title"] == "New Title"
    # description should be stripped but not empty
    assert data["description"] == "Trim me"
    # ETag set by route
    assert r.headers.get("ETag")

    # ensure record persisted
    row = await db_session.get(Lesson, lesson.id)
    assert row.title == "New Title"


# ============================================================
# ✅ Move lesson to another valid section within same course
# ============================================================
@pytest.mark.anyio
async def test_update_lesson__200_move_to_valid_section(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Systems")
    sec1 = await _create_section(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="S1", order=1)
    sec2 = await _create_section(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="S2", order=2)
    lesson = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Topic", section_id=sec1.id, order=1)

    payload = {"section_id": str(sec2.id)}
    r = await async_client.put(f"/api/v1/lessons/{lesson.id}", json=payload, headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data.get("section_id") == str(sec2.id) or (data.get("section") and data["section"]["id"] == str(sec2.id))


# ============================================================
# 🚫 Invalid section (belongs to other course) → 409
# ============================================================
@pytest.mark.anyio
async def test_update_lesson__409_invalid_section_other_course(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    base = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Base")
    other = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Other")
    foreign_sec = await _create_section(db_session, course_id=other.id, org_id=org.id, creator_id=user.id, title="Other's Section")
    lesson = await _create_lesson(db_session, course_id=base.id, org_id=org.id, creator_id=user.id, title="Topic", order=1)

    payload = {"section_id": str(foreign_sec.id)}
    r = await async_client.put(f"/api/v1/lessons/{lesson.id}", json=payload, headers=headers)
    # Service raises IntegrityError("invalid_section_move") → route maps to generic 409
    assert r.status_code == 409, r.text


# ============================================================
# 🚫 Order collision → 409 (generic mapping)
# ============================================================
@pytest.mark.anyio
async def test_update_lesson__409_order_collision(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="DBs")
    sec = await _create_section(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="SQL", order=1)
    a = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="A", section_id=sec.id, order=1)
    b = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="B", section_id=sec.id, order=2)

    # Try to move B to order=1 (occupied by A) → expect 409 from unique constraint
    payload = {"order": 1}
    r = await async_client.put(f"/api/v1/lessons/{b.id}", json=payload, headers=headers)
    assert r.status_code == 409, r.text


# ============================================================
# 🔐 404 when lesson not found in org (or random UUID)
# ============================================================
@pytest.mark.anyio
async def test_update_lesson__404_not_found(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    random_id = uuid4()
    r = await async_client.put(f"/api/v1/lessons/{random_id}", json={"title": "X"}, headers=headers)
    assert r.status_code == 404, r.text


# ============================================================
# 🔐 404 when lesson belongs to another org
# ============================================================
@pytest.mark.anyio
async def test_update_lesson__404_wrong_org(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, create_organization_fixture):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    # create foreign org and a lesson there
    other_org = await (create_organization_fixture() if not callable(getattr(create_organization_fixture, "__await__", None)) else create_organization_fixture())
    course_other = await _create_course(db_session, org_id=other_org.id, creator_id=user.id, title="Foreign")
    lesson_other = await _create_lesson(db_session, course_id=course_other.id, org_id=other_org.id, creator_id=user.id, title="Not Yours")

    r = await async_client.put(f"/api/v1/lessons/{lesson_other.id}", json={"title": "Nope"}, headers=headers)
    assert r.status_code == 404, r.text


# ============================================================
# 🔒 ETag (If-Match): success when matching, 412 when mismatched
# ============================================================
@pytest.mark.anyio
async def test_update_lesson__etag_if_match_success_and_mismatch(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Networking")
    lesson = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="TCP", order=1)

    # First update to obtain a server-generated ETag
    r1 = await async_client.put(f"/api/v1/lessons/{lesson.id}", json={"description": "Round 1"}, headers=headers)
    assert r1.status_code == 200, r1.text
    etag = r1.headers.get("ETag")
    assert etag, "ETag must be present after update"

    # Second update with If-Match = etag should succeed
    hdrs = {**headers, "If-Match": etag}
    r2 = await async_client.put(f"/api/v1/lessons/{lesson.id}", json={"description": "Round 2"}, headers=hdrs)
    assert r2.status_code == 200, r2.text

    # Third update with mismatching If-Match → 412
    bad_hdrs = {**headers, "If-Match": 'W/"bogus"'}
    r3 = await async_client.put(f"/api/v1/lessons/{lesson.id}", json={"description": "Round 3"}, headers=bad_hdrs)
    assert r3.status_code == 412, r3.text
    assert "Precondition failed" in r3.json()["detail"]


# ============================================================
# 🚫 Ignore forbidden fields (course_id/org drift attempts)
# ============================================================
@pytest.mark.anyio
async def test_update_lesson__ignores_course_and_org_fields(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    c1 = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="C1")
    c2 = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="C2")
    lesson = await _create_lesson(db_session, course_id=c1.id, org_id=org.id, creator_id=user.id, title="Stable", order=1)

    payload = {"course_id": str(c2.id), "organization_id": str(uuid4()), "title": "Stay"}
    r = await async_client.put(f"/api/v1/lessons/{lesson.id}", json=payload, headers=headers)
    assert r.status_code == 200, r.text

    # Verify DB didn't drift course/org
    row = await db_session.get(Lesson, lesson.id)
    assert row.course_id == c1.id
    assert row.organization_id == org.id
    assert row.title == "Stay"
