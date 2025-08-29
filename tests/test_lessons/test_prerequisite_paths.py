import pytest
from uuid import uuid4
from httpx import AsyncClient
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.db.models import (
    Course,
    Lesson,
    LessonUnlockCondition,
    UserOrganization,
)

# ---------------------------------------------------------
# small helpers consistent with your earlier test utilities
# ---------------------------------------------------------
def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if v is not None and hasattr(obj, k):
            setattr(obj, k, v)

async def _create_course(db, *, org_id, creator_id, title, is_published=True):
    c = Course(
        id=uuid4(),
        title=title,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
    )
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


async def _create_lesson(
    db,
    *,
    course_id,
    org_id,
    creator_id,
    title="L",
    order: Optional[int] = None,
    is_published=True,
):
    l = Lesson(
        id=uuid4(),
        title=title,
        course_id=course_id,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
    )
    _set_if_has(
        l,
        organization_id=org_id,
        created_by=creator_id,
        is_published=is_published,
        order=order,
    )
    db.add(l)
    await db.commit()
    await db.refresh(l)
    return l


async def _create_unlock(
    db,
    *,
    course_id,
    source_lesson_id,
    target_lesson_id,
    org_id=None,
    created_by=None,
    soft_unlock=False,
):
    u = LessonUnlockCondition(
        source_lesson_id=source_lesson_id,
        target_lesson_id=target_lesson_id,
        course_id=course_id,     # REQUIRED by schema
        soft_unlock=soft_unlock,
    )
    _set_if_has(u, organization_id=org_id, created_by=created_by)
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


BASE = "/api/v1/lessons"


# ============================================================
# 404: lesson not found
# ============================================================
@pytest.mark.anyio
async def test_prereq_paths__404_not_found(async_client: AsyncClient, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.get(f"{BASE}/{uuid4()}/prerequisite-paths", headers=headers)
    assert r.status_code == 404, r.text


# ============================================================
# 403: lesson belongs to another org
# ============================================================
@pytest.mark.anyio
async def test_prereq_paths__403_wrong_org(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, create_organization_fixture):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # create course+lesson in a DIFFERENT org
    other_org = await (create_organization_fixture() if not callable(getattr(create_organization_fixture, "__await__", None)) else create_organization_fixture())
    course_other = await _create_course(db_session, org_id=other_org.id, creator_id=user.id, title="Foreign")
    lesson_other = await _create_lesson(db_session, course_id=course_other.id, org_id=other_org.id, creator_id=user.id, title="Nope", order=1)

    r = await async_client.get(f"{BASE}/{lesson_other.id}/prerequisite-paths", headers=headers)
    assert r.status_code == 403, r.text


# ============================================================
# 404: target filtered (unpublished + include_unpublished=False)
# ============================================================
@pytest.mark.anyio
async def test_prereq_paths__404_target_filtered(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    c = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Filter")
    tgt = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="T", order=1, is_published=False)

    # target is unpublished; not included unless include_unpublished=True
    r = await async_client.get(f"{BASE}/{tgt.id}/prerequisite-paths", headers=headers)
    assert r.status_code == 404, r.text
    assert "Target lesson not available" in r.json()["detail"]


# ============================================================
# 200: trivial graph → [[target]]
# ============================================================
@pytest.mark.anyio
async def test_prereq_paths__trivial_returns_target_only(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    c = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Trivial")
    tgt = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="Solo", order=1)

    r = await async_client.get(f"{BASE}/{tgt.id}/prerequisite-paths", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["lesson_id"] == str(tgt.id)
    assert data["paths"] == [[str(tgt.id)]]


# ============================================================
# 200: simple chain A->B->C (target=C) → [[A,B,C]]
# ============================================================
@pytest.mark.anyio
async def test_prereq_paths__simple_chain(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    c = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Chain")
    a = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="A", order=1)
    b = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="B", order=2)
    c_t = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="C", order=3)

    await _create_unlock(db_session, course_id=c.id, source_lesson_id=a.id, target_lesson_id=b.id, org_id=org.id, created_by=user.id)
    await _create_unlock(db_session, course_id=c.id, source_lesson_id=b.id, target_lesson_id=c_t.id, org_id=org.id, created_by=user.id)

    r = await async_client.get(f"{BASE}/{c_t.id}/prerequisite-paths", headers=headers)
    assert r.status_code == 200, r.text
    paths = r.json()["paths"]
    assert [str(a.id), str(b.id), str(c_t.id)] in paths


# ============================================================
# 200: only_hard filters out soft edges
# ============================================================
@pytest.mark.anyio
async def test_prereq_paths__only_hard_filters_soft_edges(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    c = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Hardness")
    s = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="SoftSrc", order=1)
    h = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="HardSrc", order=2)
    b = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="B", order=3)
    t = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="T", order=4)

    # s --soft--> b --hard--> t
    await _create_unlock(db_session, course_id=c.id, source_lesson_id=s.id, target_lesson_id=b.id, org_id=org.id, created_by=user.id, soft_unlock=True)
    await _create_unlock(db_session, course_id=c.id, source_lesson_id=h.id, target_lesson_id=b.id, org_id=org.id, created_by=user.id, soft_unlock=False)
    await _create_unlock(db_session, course_id=c.id, source_lesson_id=b.id, target_lesson_id=t.id, org_id=org.id, created_by=user.id, soft_unlock=False)

    # only_hard=True should exclude paths via s
    r = await async_client.get(f"{BASE}/{t.id}/prerequisite-paths", headers=headers, params={"only_hard": "true"})
    assert r.status_code == 200, r.text
    paths = r.json()["paths"]
    str_s = str(s.id)
    # ensure no path includes soft source
    assert all(str_s not in p for p in paths)
    # but a hard path must exist via h
    assert [str(h.id), str(b.id), str(t.id)] in paths


# ============================================================
# 200: include_unpublished toggles whether unpublished sources show up
# ============================================================
@pytest.mark.anyio
async def test_prereq_paths__include_unpublished_toggle(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    c = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Unpub")
    src_unpub = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="U", order=1, is_published=False)
    tgt_pub   = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="P", order=2, is_published=True)

    await _create_unlock(db_session, course_id=c.id, source_lesson_id=src_unpub.id, target_lesson_id=tgt_pub.id, org_id=org.id, created_by=user.id)

    # exclude unpublished (default)
    r1 = await async_client.get(f"{BASE}/{tgt_pub.id}/prerequisite-paths", headers=headers)
    assert r1.status_code == 200, r1.text
    assert [str(src_unpub.id), str(tgt_pub.id)] not in r1.json()["paths"]

    # include unpublished
    r2 = await async_client.get(f"{BASE}/{tgt_pub.id}/prerequisite-paths", headers=headers, params={"include_unpublished": "true"})
    assert r2.status_code == 200, r2.text
    assert [str(src_unpub.id), str(tgt_pub.id)] in r2.json()["paths"]


# ============================================================
# 200: max_depth limits how far roots can be in paths
# ============================================================
@pytest.mark.anyio
async def test_prereq_paths__max_depth(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    """
    Build A->B->C->D (target D). With max_depth=2, we should get [B,C,D] (not A).
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    c = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Depth")
    a = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="A", order=1)
    b = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="B", order=2)
    d = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="D", order=4)
    # put C between B and D
    cc = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="C", order=3)

    await _create_unlock(db_session, course_id=c.id, source_lesson_id=a.id, target_lesson_id=b.id, org_id=org.id, created_by=user.id)
    await _create_unlock(db_session, course_id=c.id, source_lesson_id=b.id, target_lesson_id=cc.id, org_id=org.id, created_by=user.id)
    await _create_unlock(db_session, course_id=c.id, source_lesson_id=cc.id, target_lesson_id=d.id, org_id=org.id, created_by=user.id)

    r = await async_client.get(f"{BASE}/{d.id}/prerequisite-paths", headers=headers, params={"max_depth": "2"})
    assert r.status_code == 200, r.text
    paths = r.json()["paths"]
    assert [str(b.id), str(cc.id), str(d.id)] in paths
    assert all(not p or p[0] != str(a.id) for p in paths)  # no path should start with A


# ============================================================
# 200: max_paths caps the enumeration size
# ============================================================
@pytest.mark.anyio
async def test_prereq_paths__max_paths_cap(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    """
    Build a target C with multiple independent roots A1..A4 -> C.
    With max_paths=2 we must not exceed 2 paths returned.
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    c = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="Cap")
    c_t = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="C", order=10)

    roots = []
    for i in range(1, 5):
        src = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title=f"A{i}", order=i)
        roots.append(src)
        await _create_unlock(db_session, course_id=c.id, source_lesson_id=src.id, target_lesson_id=c_t.id, org_id=org.id, created_by=user.id)

    r = await async_client.get(f"{BASE}/{c_t.id}/prerequisite-paths", headers=headers, params={"max_paths": "2"})
    assert r.status_code == 200, r.text
    paths = r.json()["paths"]
    assert len(paths) == 2
    # both must end with target
    assert all(p and p[-1] == str(c_t.id) for p in paths)


# ============================================================
# 304: ETag cache replay (If-None-Match)
# ============================================================
@pytest.mark.anyio
async def test_prereq_paths__etag_304(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, redis_client):
    """
    First call builds cache, returns ETag.
    Second call with If-None-Match should return 304 (same params).
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    c = await _create_course(db_session, org_id=org.id, creator_id=user.id, title="ETag")
    a = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="A", order=1)
    t = await _create_lesson(db_session, course_id=c.id, org_id=org.id, creator_id=user.id, title="T", order=2)
    await _create_unlock(db_session, course_id=c.id, source_lesson_id=a.id, target_lesson_id=t.id, org_id=org.id, created_by=user.id)

    r1 = await async_client.get(f"{BASE}/{t.id}/prerequisite-paths", headers=headers)
    assert r1.status_code == 200, r1.text
    etag = r1.headers.get("ETag")
    assert etag, "ETag missing on first response"

    r2 = await async_client.get(
        f"{BASE}/{t.id}/prerequisite-paths",
        headers={**headers, "If-None-Match": etag},
    )
    assert r2.status_code == 304, r2.text
    assert r2.headers.get("ETag") == etag
    # Cache-Control should be present as per route
    assert "Cache-Control" in r2.headers
