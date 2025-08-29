# tests/test_progress/test_upload_certificate.py

import json
import uuid
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Course, CourseEnrollment, Lesson
from app.schemas.enums import OrgRole
from app.core.redis_client import redis_wrapper

BASE = "/api/v1/progress"

# -- tiny helper: only set attributes that exist on the model -----------
def _set_if_has(obj, **fields):
    for k, v in fields.items():
        if hasattr(obj, k):
            setattr(obj, k, v)

# -----------------------------------------------------------------------
# 404 if course missing or belongs to another org
# -----------------------------------------------------------------------
@pytest.mark.anyio
async def test_upload_cert__404_when_course_missing_or_other_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # 1) Missing course
    missing = uuid.uuid4()
    r = await async_client.post(
        f"{BASE}/course/{missing}/certificate",
        headers=headers,
        json={"certificate_url": "https://example.com/c1.pdf"},
    )
    assert r.status_code == 404, r.text

    # 2) Course in another org
    from app.db.models import Organization
    other = Organization(name=f"Other-{uuid.uuid4().hex[:6]}")
    # ensure slug exists in envs where it's NOT NULL
    _set_if_has(other, slug=f"other-{uuid.uuid4().hex[:6]}")
    _set_if_has(other, created_by=user.id)
    db_session.add(other); await db_session.commit(); await db_session.refresh(other)

    foreign = Course(
        title="Foreign",
        slug=f"for-{uuid.uuid4().hex[:6]}",
        organization_id=other.id,
        is_published=True,
    )
    _set_if_has(foreign, created_by=user.id)
    db_session.add(foreign); await db_session.commit(); await db_session.refresh(foreign)

    r2 = await async_client.post(
        f"{BASE}/course/{foreign.id}/certificate",
        headers=headers,
        json={"certificate_url": "https://example.com/c2.pdf"},
    )
    assert r2.status_code == 404, r2.text


# -----------------------------------------------------------------------
# 404 if enrollment doesn't exist
# -----------------------------------------------------------------------
@pytest.mark.anyio
async def test_upload_cert__404_when_enrollment_missing(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="NoEnroll",
        slug=f"ne-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    r = await async_client.post(
        f"{BASE}/course/{c.id}/certificate",
        headers=headers,
        json={"certificate_url": "https://example.com/cert.pdf"},
    )
    assert r.status_code == 404, r.text
    assert "Enrollment not found" in r.text


# -----------------------------------------------------------------------
# 400 if enrollment exists but not completed
# -----------------------------------------------------------------------
@pytest.mark.anyio
async def test_upload_cert__400_when_not_completed(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Half",
        slug=f"half-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    # create enrollment but not completed (no completed_at)
    ce = CourseEnrollment(user_id=user.id, course_id=c.id)
    db_session.add(ce); await db_session.commit()

    r = await async_client.post(
        f"{BASE}/course/{c.id}/certificate",
        headers=headers,
        json={"certificate_url": "https://example.com/x.pdf"},
    )
    assert r.status_code == 400, r.text
    assert "Course not yet completed" in r.text


# -----------------------------------------------------------------------
# 400 if URL is not HTTPS (service uses _validate_https_url)
# -----------------------------------------------------------------------
@pytest.mark.anyio
async def test_upload_cert__400_rejects_non_https_url(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Proto",
        slug=f"proto-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    # valid completed enrollment
    ce = CourseEnrollment(
        user_id=user.id, course_id=c.id, completed_at=datetime.now(timezone.utc)
    )
    db_session.add(ce); await db_session.commit()

    # http should be rejected by service-level validation
    r = await async_client.post(
        f"{BASE}/course/{c.id}/certificate",
        headers=headers,
        json={"certificate_url": "http://insecure.example.com/c.pdf"},
    )
    assert r.status_code == 400, r.text


# -----------------------------------------------------------------------
# 200 on success: sets URL, returns body, sets headers, deletes cache key
# -----------------------------------------------------------------------
@pytest.mark.anyio
async def test_upload_cert__200_success_sets_and_invalidates_cache_and_headers(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Done",
        slug=f"done-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    # some envs require a lesson for visibility (safe to add one)
    l = Lesson(title="L", order=1, is_published=True, course_id=c.id, organization_id=org.id)
    _set_if_has(l, created_by=user.id)
    db_session.add(l); await db_session.commit(); await db_session.refresh(l)

    # completed enrollment
    ce = CourseEnrollment(
        user_id=user.id, course_id=c.id, completed_at=datetime.now(timezone.utc)
    )
    db_session.add(ce); await db_session.commit()

    # seed completion-status cache to verify invalidation
    cache_key = f"cstatus:v1:course:{c.id}:user:{user.id}:org:{org.id}"
    await redis_wrapper.client.setex(
        cache_key, 60,
        json.dumps(
            dict(is_completed=True, completed_at=None, certificate_url=None, progress_percent=100.0),
            separators=(",", ":"), ensure_ascii=False
        ),
    )

    url = "https://example.com/cert-final.pdf"
    r = await async_client.post(
        f"{BASE}/course/{c.id}/certificate",
        headers=headers,
        json={"certificate_url": url},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["message"].lower().startswith("certificate url set")
    assert body["certificate_url"] == url

    # Headers: ETag + Cache-Control set
    assert r.headers.get("ETag")
    assert "Cache-Control" in r.headers

    # cache invalidated
    leftover = await redis_wrapper.client.get(cache_key)
    assert leftover is None


# -----------------------------------------------------------------------
# Audit is best-effort: called with expected kwargs; errors do not break request
# -----------------------------------------------------------------------
@pytest.mark.anyio
async def test_upload_cert__audit_called_best_effort(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    c = Course(
        title="Audit",
        slug=f"aud-{uuid.uuid4().hex[:6]}",
        organization_id=org.id,
        is_published=True,
    )
    _set_if_has(c, created_by=user.id)
    db_session.add(c); await db_session.commit(); await db_session.refresh(c)

    # completed enrollment
    ce = CourseEnrollment(
        user_id=user.id, course_id=c.id, completed_at=datetime.now(timezone.utc)
    )
    db_session.add(ce); await db_session.commit()

    called = {}

    async def _audit(*a, **k):
        # record kwargs and simulate success
        called.update(k)

    monkeypatch.setattr("app.api.v1.progress.progress.log_org_event", _audit, raising=True)

    url = "https://example.com/audit.pdf"
    r = await async_client.post(
        f"{BASE}/course/{c.id}/certificate",
        headers=headers,
        json={"certificate_url": url},
    )
    assert r.status_code == 200, r.text
    # verify kwargs shape (tolerant to names)
    assert called.get("organization_id") == org.id
    assert called.get("actor_id") == user.id
    meta = called.get("meta_data") or called.get("metadata") or {}
    assert isinstance(meta, dict) and meta.get("course_id") == str(c.id)

    # Now force audit to raise; route should still succeed
    async def _boom(*a, **k):
        raise RuntimeError("audit broke")

    monkeypatch.setattr("app.api.v1.progress.progress.log_org_event", _boom, raising=True)

    r2 = await async_client.post(
        f"{BASE}/course/{c.id}/certificate",
        headers=headers,
        json={"certificate_url": url},
    )
    assert r2.status_code == 200, r2.text
