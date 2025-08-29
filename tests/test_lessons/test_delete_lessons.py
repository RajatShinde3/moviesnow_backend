import pytest
from uuid import uuid4
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.schemas.enums import OrgRole
from app.db.models import (
    Course,
    Section,
    Lesson,
    LessonProgress,
    LessonUnlockCondition,
    UserOrganization,
)


# -----------------------------
# helpers (schema-safe setters)
# -----------------------------
def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if v is not None and hasattr(obj, k):
            setattr(obj, k, v)


async def _get_or_create_user_org(db, *, user_id, org_id):
    uo = await db.scalar(
        select(UserOrganization).where(
            UserOrganization.user_id == user_id,
            UserOrganization.organization_id == org_id,
        )
    )
    if uo is None:
        uo = UserOrganization(user_id=user_id, organization_id=org_id)
        db.add(uo)
        await db.commit()
        await db.refresh(uo)
    return uo


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


async def _create_lesson(db, *, course_id, org_id, creator_id, title="L", section_id=None, order=1, is_published=True):
    l = Lesson(id=uuid4(), title=title, course_id=course_id)
    _set_if_has(
        l,
        organization_id=org_id,
        created_by=creator_id,
        is_published=is_published,
        section_id=section_id,
        order=order,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
    )
    db.add(l)
    await db.commit()
    await db.refresh(l)
    return l


# ============================================================
# ✅ 204 basic delete + compact order (default True)
# ============================================================
@pytest.mark.anyio
async def test_delete_lesson__204_basic_and_compact(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Algorithms")
    sec = await _create_section(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Sorting")

    l1 = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Intro", section_id=sec.id, order=1)
    l2 = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="QS", section_id=sec.id, order=2)

    r = await async_client.delete(f"/api/v1/lessons/lesson/{l1.id}", headers=headers)  # compact_order defaults to True
    assert r.status_code == 204, r.text
    assert r.text == ""

    # l1 gone (hard delete) OR soft-deleted (row present but flagged)
    still = await db_session.get(Lesson, l1.id)
    if still:
        # soft-delete path: must be flagged if model supports it
        has_soft_flag = (hasattr(still, "is_deleted") and still.is_deleted) or (hasattr(still, "deleted_at") and getattr(still, "deleted_at"))
        assert has_soft_flag is True
    # l2 order should be compacted to 1
    l2_db = await db_session.get(Lesson, l2.id)
    assert l2_db.order == 1


# ============================================================
# ✅ 204 delete with compact_order = False (keep gaps)
# ============================================================
@pytest.mark.anyio
async def test_delete_lesson__204_no_compact(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    c = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Systems")
    s = await _create_section(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="Proc")

    l1 = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="A", section_id=s.id, order=1)
    l2 = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="B", section_id=s.id, order=2)
    l3 = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="C", section_id=s.id, order=3)

    r = await async_client.delete(f"/api/v1/lessons/lesson/{l2.id}", headers=headers, params={"compact_order": "false"})
    assert r.status_code == 204, r.text

    # Remaining orders should be 1 and 3 (no compaction)
    a = await db_session.get(Lesson, l1.id)
    c_db = await db_session.get(Lesson, l3.id)
    assert a.order == 1
    assert c_db.order == 3


# ============================================================
# 🔐 404 when lesson not found
# ============================================================
@pytest.mark.anyio
async def test_delete_lesson__404_not_found(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.delete(f"/api/v1/lessons/lesson/{uuid4()}", headers=headers)
    assert r.status_code == 404, r.text


# ============================================================
# 🔐 404 when lesson belongs to another org
# ============================================================
@pytest.mark.anyio
async def test_delete_lesson__404_wrong_org(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, create_organization_fixture):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    other_org = await (create_organization_fixture() if not callable(getattr(create_organization_fixture, "__await__", None)) else create_organization_fixture())

    c_other = await _create_course(db_session, org_id=other_org.id, creator_id=user.id, title="Foreign")
    l_other = await _create_lesson(db_session, course_id=c_other.id, org_id=other_org.id, creator_id=user.id, title="Nope", order=1)

    r = await async_client.delete(f"/api/v1/lessons/lesson/{l_other.id}", headers=headers)
    assert r.status_code == 404, r.text


# ============================================================
# 🔒 412 When If-Match mismatches
# ============================================================
@pytest.mark.anyio
async def test_delete_lesson__412_if_match_mismatch(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Networking")
    lesson = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="TCP", order=1)

    # bogus If-Match should fail
    hdrs = {**headers, "If-Match": 'W/"bogus"'}
    r = await async_client.delete(f"/api/v1/lessons/lesson/{lesson.id}", headers=hdrs)
    assert r.status_code == 412, r.text


# ============================================================
# 🚫 Deps present: either 409 (blocked) OR 204 (soft/cascade) — validate state
# ============================================================
@pytest.mark.anyio
async def test_delete_lesson__blocked_or_cascaded(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    """
    If FKs block deletion (no cascade, hard delete), expect 409.
    If model soft-deletes OR schema cascades, expect 204.
    In either case, validate resulting DB state.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Deps")
    lesson = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="ToDelete", order=1)
    other  = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Other", order=2)

    # Seed dependencies
    user_org = await _get_or_create_user_org(db_session, user_id=user.id, org_id=org.id)
    prog = LessonProgress(
        user_id=user.id,
        user_org_id=user_org.id,
        course_id=course.id,
        lesson_id=lesson.id,
        is_completed=True,
    )
    _set_if_has(prog, organization_id=org.id, created_by=user.id)
    db_session.add(prog)

    # ✅ include course_id (NOT NULL)
    unlock = LessonUnlockCondition(
        source_lesson_id=other.id,
        target_lesson_id=lesson.id,
        course_id=course.id,
        soft_unlock=False,
    )
    _set_if_has(unlock, organization_id=org.id, created_by=user.id)
    db_session.add(unlock)
    await db_session.commit()

    # Attempt delete WITHOUT force
    r = await async_client.delete(f"/api/v1/lessons/lesson/{lesson.id}", headers=headers, params={"force": "false"})

    if r.status_code == 409:
        # Blocked by deps: rows must still exist
        res1 = await db_session.execute(select(LessonProgress).where(LessonProgress.lesson_id == lesson.id))
        assert res1.scalars().all() != []
        res2 = await db_session.execute(
            select(LessonUnlockCondition).where(
                (LessonUnlockCondition.source_lesson_id == lesson.id) |
                (LessonUnlockCondition.target_lesson_id == lesson.id)
            )
        )
        assert res2.scalars().all() != []
    else:
        # Allow 204 for soft delete or cascade
        assert r.status_code == 204, r.text

        # Re-check lesson and dependencies to characterize outcome:
        remaining_lesson = await db_session.get(Lesson, lesson.id)

        if remaining_lesson:
            # Soft-deleted path: lesson row remains and should be flagged
            is_soft = (
                (hasattr(remaining_lesson, "is_deleted") and remaining_lesson.is_deleted) or
                (hasattr(remaining_lesson, "deleted_at") and getattr(remaining_lesson, "deleted_at"))
            )
            assert is_soft is True

            # With soft delete and force=False, dependencies should remain
            res1 = await db_session.execute(select(LessonProgress).where(LessonProgress.lesson_id == lesson.id))
            res2 = await db_session.execute(
                select(LessonUnlockCondition).where(
                    (LessonUnlockCondition.source_lesson_id == lesson.id) |
                    (LessonUnlockCondition.target_lesson_id == lesson.id)
                )
            )
            assert res1.scalars().all() != []
            assert res2.scalars().all() != []
        else:
            # Hard delete happened; if FK is CASCADE, deps should be gone
            res1 = await db_session.execute(select(LessonProgress).where(LessonProgress.lesson_id == lesson.id))
            res2 = await db_session.execute(
                select(LessonUnlockCondition).where(
                    (LessonUnlockCondition.source_lesson_id == lesson.id) |
                    (LessonUnlockCondition.target_lesson_id == lesson.id)
                )
            )
            assert res1.scalars().all() == []
            assert res2.scalars().all() == []


# ============================================================
# ✅ force=true removes deps and succeeds with 204
# ============================================================
@pytest.mark.anyio
async def test_delete_lesson__204_force_removes_dependencies(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    course = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Deps2")
    lesson = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="ToDelete", order=1)
    other = await _create_lesson(db_session, course_id=course.id, org_id=org.id, creator_id=user.id, title="Other", order=2)

    # Seed dependencies again
    user_org = await _get_or_create_user_org(db_session, user_id=user.id, org_id=org.id)
    db_session.add(
        LessonProgress(
            user_id=user.id,
            user_org_id=user_org.id,
            course_id=course.id,
            lesson_id=lesson.id,
            is_completed=True,
        )
    )
    # ✅ include course_id on unlock to satisfy NOT NULL
    db_session.add(
        LessonUnlockCondition(
            source_lesson_id=other.id,
            target_lesson_id=lesson.id,
            course_id=course.id,
            soft_unlock=False,  # optional
            # uncomment if your schema requires these as NOT NULL:
            # organization_id=org.id,
            # created_by=user.id,
        )
    )
    await db_session.commit()

    r = await async_client.delete(f"/api/v1/lessons/lesson/{lesson.id}", headers=headers, params={"force": "true"})
    assert r.status_code == 204, r.text

    # Dependencies gone
    res = await db_session.execute(select(LessonProgress).where(LessonProgress.lesson_id == lesson.id))
    assert res.scalars().all() == []
    res2 = await db_session.execute(
        select(LessonUnlockCondition).where(
            (LessonUnlockCondition.source_lesson_id == lesson.id) | (LessonUnlockCondition.target_lesson_id == lesson.id)
        )
    )
    assert res2.scalars().all() == []

    # Lesson removed or soft-deleted
    remains = await db_session.get(Lesson, lesson.id)
    if remains:
        assert (hasattr(remains, "is_deleted") and remains.is_deleted) or (hasattr(remains, "deleted_at") and getattr(remains, "deleted_at"))
