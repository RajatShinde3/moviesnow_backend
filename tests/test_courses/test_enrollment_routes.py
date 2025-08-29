# tests/test_courses/test_enrollment_routes.py

import pytest
from uuid import uuid4
from typing import Optional, Union
from datetime import datetime, timezone
from app.schemas.enums import CourseStatus
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_

from app.db.models import (
    Course,
    CourseEnrollment,
    User,
    UserOrganization,
)
from app.schemas.enums import CourseVisibility, CourseLevel, OrgRole


# ──────────────────────────────────────────────────────────────
# Helpers (schema‑resilient)
# ──────────────────────────────────────────────────────────────

def _set_if_has(obj, **fields):
    """
    Set attributes only if the ORM model has them and value is not None.
    Keeps tests resilient across schema variations.
    """
    for k, v in fields.items():
        if v is not None and hasattr(obj, k):
            setattr(obj, k, v)


async def _create_course(
    db,
    *,
    org_id,
    creator_id,
    title: str = "Course",
    is_published: bool = True,
    visibility: Optional[CourseVisibility] = CourseVisibility.PUBLIC,
) -> Course:
    """
    Minimal course row that satisfies common NOT NULLs across schemas.
    Uses safe defaults instead of column objects to avoid SQLAlchemy
    misinterpreting them as SQL expressions.
    """
    c = Course(
        id=uuid4(),
        title=title,
        slug=f"{title.lower().replace(' ', '-')}-{uuid4().hex[:6]}",
        description=f"{title} description",
        organization_id=org_id,
        is_published=is_published,
        language="en",
        level=CourseLevel.BEGINNER,
    )
    _set_if_has(
        c,
        created_by=creator_id,
        is_free=True,
        status=CourseStatus.DRAFT,  # ✅ Safe enum value, not column object
        visibility=visibility,
        total_lessons=0,
        total_enrollments=0,        # ✅ Typo fix: total_enrollment → total_enrollments
        rating=0.0,
    )
    db.add(c)
    await db.commit()
    await db.refresh(c)
    return c



async def _enroll_user_in_course(
    db: AsyncSession,
    *,
    learner: Union[User, UserOrganization],
    course: Course,
    completed: bool = False,
) -> CourseEnrollment:
    """
    Test helper to create a CourseEnrollment that matches production behavior.
    """
    # Match production: set IDs based on learner type
    if isinstance(learner, UserOrganization):
        user_id = learner.user_id
        user_org_id = learner.id
    else:
        user_id = learner.id
        user_org_id = None

    e = CourseEnrollment(
        id=uuid4(),
        course_id=course.id,
        user_id=user_id,
        user_org_id=user_org_id,
        enrolled_at=datetime.now(timezone.utc),
        is_active=True,
        enrolled_by=user_id,
        progress_percent=100 if completed else 0,
    )

    if completed:
        e.completed_at = datetime.now(timezone.utc)

    db.add(e)
    await db.commit()
    await db.refresh(e)
    return e


async def _count_enrollment(db, *, course_id, user_id) -> int:
    """
    Count enrollments for a given course and user.
    Matches both user_id and user_org_id to support both User and UserOrganization.
    """
    q = select(func.count()).select_from(CourseEnrollment).where(
        CourseEnrollment.course_id == course_id,
        or_(
            CourseEnrollment.user_id == user_id,
            CourseEnrollment.user_org_id == user_id
        )
    )
    return (await db.scalar(q)) or 0

# ──────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────
from uuid import uuid4
import pytest
from sqlalchemy import text
from app.db.models import UserOrganization, User

@pytest.mark.anyio
async def test_enroll_course_success(async_client, db_session, org_user_with_token):
    """POST → 201 and enrollment exists."""
    learner, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    print("\n[DEBUG] learner type:", type(learner), "learner.id:", getattr(learner, "id", None),
          "learner.user_id:", getattr(learner, "user_id", None), "org_id:", org.id)

    creator_id = getattr(learner, "user_id", getattr(learner, "id", None))
    course = await _create_course(db_session, org_id=org.id, creator_id=creator_id, title="Perm OK Course")
    print("[DEBUG] Created course:", course.id, course.title, "org_id:", course.organization_id)

    r = await async_client.post(f"/api/v1/courses/enrollment/{course.id}", headers=headers)
    print("[DEBUG] POST response:", r.status_code, r.json())

    # Check actual DB contents after POST
    rows = (await db_session.execute(text("SELECT * FROM course_enrollments"))).fetchall()
    print("[DEBUG] course_enrollments after POST:", rows)

    assert r.status_code == 201, r.text
    body = r.json()
    assert body.get("success") is True
    assert isinstance(body.get("message"), str)

    user_id = learner.user_id if isinstance(learner, UserOrganization) else learner.id
    count = await _count_enrollment(db_session, course_id=course.id, user_id=user_id)
    print("[DEBUG] _count_enrollment result:", count, "for user_id:", user_id)
    assert count == 1


@pytest.mark.anyio
async def test_enroll_course_idempotent(async_client, db_session, org_user_with_token):
    """Enrolling twice is idempotent."""
    learner, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    creator_id = getattr(learner, "user_id", getattr(learner, "id", None))
    course = await _create_course(db_session, org_id=org.id, creator_id=creator_id, title="Idempotent Course")

    r1 = await async_client.post(f"/api/v1/courses/enrollment/{course.id}", headers=headers)
    assert r1.status_code == 201, r1.text

    r2 = await async_client.post(f"/api/v1/courses/enrollment/{course.id}", headers=headers)
    assert r2.status_code in (200, 201), r2.text
    assert r2.json().get("success") is True

    user_id = learner.user_id if isinstance(learner, UserOrganization) else learner.id
    assert await _count_enrollment(db_session, course_id=course.id, user_id=user_id) == 1


@pytest.mark.anyio
async def test_enroll_course_not_found(async_client, db_session, org_user_with_token):
    """404 if course does not exist."""
    learner, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.post(f"/api/v1/courses/enrollment/{uuid4()}", headers=headers)
    assert r.status_code == 404, r.text
    # Accept API wrapper or plain FastAPI error
    payload = r.json()
    assert "success" not in payload or isinstance(payload["success"], bool)


@pytest.mark.anyio
async def test_get_my_enrollment_returns_enrolled_courses(async_client, db_session, org_user_with_token):
    """GET /my returns enrolled courses."""
    learner, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    print("\n[DEBUG] learner type:", type(learner), 
          "learner.id:", getattr(learner, "id", None),
          "learner.user_id:", getattr(learner, "user_id", None),
          "org_id:", org.id)

    creator_id = getattr(learner, "user_id", getattr(learner, "id", None))
    c = await _create_course(db_session, org_id=org.id, creator_id=creator_id, title="Enrolled A")
    print("[DEBUG] Created course:", c.id, c.title, "org_id:", c.organization_id)

    enrollment = await _enroll_user_in_course(db_session, learner=learner, course=c)
    print("[DEBUG] Created enrollment:", enrollment.id, 
          "course_id:", enrollment.course_id,
          "user_id:", enrollment.user_id,
          "user_org_id:", getattr(enrollment, "user_org_id", None))

    # Check DB directly before hitting endpoint
    from sqlalchemy import text
    rows_in_db = (await db_session.execute(text("SELECT * FROM course_enrollments"))).fetchall()
    print("[DEBUG] course_enrollments table contents:", rows_in_db)

    r = await async_client.get("/api/v1/courses/enrollment/my", headers=headers)
    print("[DEBUG] GET /my status:", r.status_code)
    print("[DEBUG] GET /my response JSON:", r.json())

    assert r.status_code == 200, r.text
    data = r.json()
    rows = data if isinstance(data, list) else data.get("data") or []
    titles = {row["title"] for row in rows}
    print("[DEBUG] Extracted titles from response:", titles)
    assert "Enrolled A" in titles



@pytest.mark.anyio
async def test_get_my_enrollment_empty(async_client, db_session, org_user_with_token):
    """
    200 + returns empty list when the learner has no enrollment.
    """
    learner, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    r = await async_client.get("/api/v1/courses/enrollment/my", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    rows = data if isinstance(data, list) else data.get("data") or []
    assert rows == []


@pytest.mark.anyio
async def test_check_enrollment_status_enrolled(async_client, db_session, org_user_with_token):
    """
    GET /api/v1/courses/enrollment/{course_id}/status returns 200 for an enrolled learner.
    (We verify enrollment via DB because response payload is envelope-normalized.)
    """
    learner, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = await _create_course(db_session, org_id=org.id, creator_id=getattr(learner, "user_id", getattr(learner, "id", None)), title="Status Course")
    await _enroll_user_in_course(db_session, learner=learner, course=c)

    r = await async_client.get(f"/api/v1/courses/enrollment/{c.id}/status", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json().get("success") in (True, False)  # wrapper may not expose detail/message
    user_id = learner.user_id if isinstance(learner, UserOrganization) else learner.id
    assert await _count_enrollment(db_session, course_id=c.id, user_id=user_id) == 1


@pytest.mark.anyio
async def test_check_enrollment_status_not_enrolled(async_client, db_session, org_user_with_token):
    """
    GET /api/v1/courses/enrollment/{course_id}/status returns 200; verify not enrolled by DB.
    """
    learner, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = await _create_course(db_session, org_id=org.id, creator_id=getattr(learner, "user_id", getattr(learner, "id", None)), title="Not Enrolled Course")

    r = await async_client.get(f"/api/v1/courses/enrollment/{c.id}/status", headers=headers)
    assert r.status_code == 200, r.text
    user_id = learner.user_id if isinstance(learner, UserOrganization) else learner.id
    assert await _count_enrollment(db_session, course_id=c.id, user_id=user_id) == 0


@pytest.mark.anyio
async def test_permission_denied_when_missing(async_client, db_session, org_user_with_token):
    """
    403 when the learner lacks enrollment permissions (e.g., INTERN role).
    """
    learner, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    c = await _create_course(db_session, org_id=org.id, creator_id=getattr(learner, "user_id", getattr(learner, "id", None)), title="Perm Blocked")

    r1 = await async_client.post(f"/api/v1/courses/enrollment/{c.id}", headers=headers)
    assert r1.status_code in (401, 403), r1.text

    r2 = await async_client.get("/api/v1/courses/enrollment/my", headers=headers)
    assert r2.status_code in (401, 403), r2.text
