import uuid
import pytest
from fastapi import status

# Reuse the same helpers your issue tests use
from app.db.models import User

import uuid
from typing import Dict
import pytest
from fastapi import status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    User,
    Organization,
    Course,
    CertificateTemplate,
    IssuedCertificate,
)
from app.schemas.enums import CourseVisibility, CourseLevel

# ─────────────────────────────────────────────────────────────
# 🏗️ Helpers: minimal course/template factories
# ─────────────────────────────────────────────────────────────
async def _mk_course(db: AsyncSession, *, org: Organization, creator: User) -> Course:
    c = Course(
        title="Certifiable Course",
        description="desc",
        visibility=CourseVisibility.PUBLIC,
        is_published=True,
        organization_id=org.id,
        created_by=creator.id,
        slug=f"cert-course-{creator.id.hex[:6]}",
        language="en",
        level=CourseLevel.BEGINNER,
        version=1,
        is_latest=True,
    )
    db.add(c)
    await db.commit()
    await db.refresh(c)
    return c


async def _mk_template(db: AsyncSession, *, org: Organization) -> CertificateTemplate:
    """
    Build using only attributes your model actually has.
    Always set NOT NULL columns like name & slug when present.
    """
    kwargs = {"template_svg": "<html><body><h1>{{ course_title }}</h1></body></html>"}

    # Required fields on your model (per IntegrityError): name (NOT NULL), slug (likely NOT NULL)
    if hasattr(CertificateTemplate, "name"):
        kwargs["name"] = f"Test Template {uuid.uuid4().hex[:6]}"
    if hasattr(CertificateTemplate, "slug"):
        kwargs["slug"] = f"tmpl-{uuid.uuid4().hex[:8]}"

    # Optional / nice-to-have columns
    if hasattr(CertificateTemplate, "organization_id"):
        kwargs["organization_id"] = getattr(org, "id", None)
    if hasattr(CertificateTemplate, "template_version"):
        kwargs["template_version"] = 1
    if hasattr(CertificateTemplate, "watermark_url"):
        kwargs["watermark_url"] = None
    if hasattr(CertificateTemplate, "show_qr_code"):
        kwargs["show_qr_code"] = True  # if NOT NULL in your schema

    t = CertificateTemplate(**kwargs)
    db.add(t)
    await db.commit()
    await db.refresh(t)

    # Post-create flags (set only if column exists)
    if hasattr(t, "is_active"):
        t.is_active = True
        db.add(t)
        await db.commit()
        await db.refresh(t)

    return t


@pytest.mark.anyio
async def test_view_certificate_html_200_and_304(
    async_client,
    db_session,
    org_user_with_token,
    create_test_user,
):
    # Arrange: org/admin, learner, course, template
    actor, headers, org = await org_user_with_token()
    learner: User = await create_test_user()
    course = await _mk_course(db_session, org=org, creator=actor)
    template = await _mk_template(db_session, org=org)

    # Issue a certificate (201)
    payload = {
        "user_id": str(learner.id),
        "course_id": str(course.id),
        "organization_id": str(org.id),
        "template_id": str(template.id),
        "language_code": "en",
    }
    r_issue = await async_client.post("/api/v1/courses/issue", headers=headers, json=payload)
    assert r_issue.status_code == status.HTTP_201_CREATED, r_issue.text
    body = r_issue.json()
    license_id = body["license_id"]

    # Act: fetch the HTML viewer
    r_view = await async_client.get(f"/api/v1/courses/c/{license_id}")
    assert r_view.status_code == status.HTTP_200_OK
    # Basic security + caching headers
    assert "Content-Security-Policy" in r_view.headers
    assert r_view.headers.get("X-Frame-Options") == "DENY"
    assert r_view.headers.get("X-Content-Type-Options") == "nosniff"
    assert r_view.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert r_view.headers.get("Cache-Control") == "public, max-age=300"
    assert "ETag" in r_view.headers
    etag = r_view.headers["ETag"]
    assert isinstance(etag, str) and etag.startswith('W/"')

    # Conditional GET → 304
    r_304 = await async_client.get(f"/api/v1/courses/c/{license_id}", headers={"If-None-Match": etag})
    assert r_304.status_code == status.HTTP_304_NOT_MODIFIED
    assert r_304.text == ""  # empty body for 304

    # Negative: unknown license → 404
    r_not_found = await async_client.get("/api/v1/courses/c/DOES-NOT-EXIST-123")
    assert r_not_found.status_code == status.HTTP_404_NOT_FOUND
    assert r_not_found.json()["detail"] == "Certificate not found"


@pytest.mark.anyio
async def test_verify_certificate_json_200_and_304(
    async_client,
    db_session,
    org_user_with_token,
    create_test_user,
):
    # Arrange: org/admin, learner, course, template
    actor, headers, org = await org_user_with_token()
    learner: User = await create_test_user()
    course = await _mk_course(db_session, org=org, creator=actor)
    template = await _mk_template(db_session, org=org)

    # Issue a certificate (201)
    payload = {
        "user_id": str(learner.id),
        "course_id": str(course.id),
        "organization_id": str(org.id),
        "template_id": str(template.id),
        "language_code": "en",
    }
    r_issue = await async_client.post("/api/v1/courses/issue", headers=headers, json=payload)
    assert r_issue.status_code == status.HTTP_201_CREATED, r_issue.text
    b = r_issue.json()
    license_id = b["license_id"]

    # Act: verify JSON
    r_json = await async_client.get(f"/api/v1/courses/c/{license_id}.json")
    assert r_json.status_code == status.HTTP_200_OK, r_json.text
    data = r_json.json()

    # Payload sanity
    assert data["license_id"] == license_id
    assert data["course_id"] == str(course.id)
    assert data["organization_id"] == str(org.id)
    assert data["status"] == "active"
    assert data["is_revoked"] is False
    assert "verification_url" in data

    # Caching headers + ETag
    assert r_json.headers.get("Cache-Control") == "public, max-age=120"
    assert "ETag" in r_json.headers
    etag = r_json.headers["ETag"]

    # Conditional GET → 304
    r_304 = await async_client.get(f"/api/v1/courses/c/{license_id}.json", headers={"If-None-Match": etag})
    assert r_304.status_code == status.HTTP_304_NOT_MODIFIED
    # Starlette JSONResponse returns empty body for 304
    assert r_304.text == "null"

    # Negative: unknown license → 404
    r_nf = await async_client.get("/api/v1/courses/c/DOES-NOT-EXIST-123.json")
    assert r_nf.status_code == status.HTTP_404_NOT_FOUND
    assert r_nf.json()["detail"] == "Certificate not found"
