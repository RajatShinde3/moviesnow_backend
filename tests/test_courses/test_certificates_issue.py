# tests/test_courses/test_certificates_issue.py
from __future__ import annotations

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
# 🔧 Patch external deps (Redis idempotency, QR, PDF, S3 HEAD)
# ─────────────────────────────────────────────────────────────
@pytest.fixture
def patch_external_dependencies(monkeypatch):
    # In-memory idempotency snapshot store
    idem_store: Dict[str, dict] = {}

    # ── Redis idempotency (fake) ───────────────────────────────────────────
    from app.core.redis_client import redis_wrapper

    async def fake_idem_get(key: str):
        return idem_store.get(key)

    async def fake_idem_set(key: str, payload: dict, ttl_seconds: int = 86400):
        idem_store[key] = payload

    monkeypatch.setattr(redis_wrapper, "idempotency_get", fake_idem_get, raising=True)
    monkeypatch.setattr(redis_wrapper, "idempotency_set", fake_idem_set, raising=True)

    # ── Patch service-level deps ───────────────────────────────────────────
    from app.services.courses import certificate_service as svc
    from uuid import uuid4

    # must be **sync** (service calls it like a normal function)
    def fake_generate_certificate_pdf(
        *, template_svg, context, output_prefix, qr_image_url=None, watermark_url=None, css_path=None
    ):
        # Make URLs UNIQUE per call (avoid DB unique collisions)
        lid = context.get("license_id") or uuid4().hex
        return ("https://cdn.test/cert.pdf", "https://cdn.test/thumb.png")

    def fake_generate_qr_code_image_url(*args, **kwargs):
        # Unique as well, in case the column is constrained
        return "https://cdn.test/qr.png"

    class FakeS3:
        def head(self, key: str):
            # Provide deterministic pdf hash metadata
            return {"Metadata": {"x-pdf-sha256": "deadbeef" * 8}}

    monkeypatch.setattr(svc, "generate_certificate_pdf", fake_generate_certificate_pdf, raising=True)
    monkeypatch.setattr(svc, "generate_qr_code_image_url", fake_generate_qr_code_image_url, raising=True)
    monkeypatch.setattr(svc, "S3Client", FakeS3, raising=True)

    # ⛔️ Do NOT mutate pydantic Settings (no setter). Use env var instead.
    monkeypatch.setenv("JWS_ENABLED", "false")

    return {"idem_store": idem_store}

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


# ╔════════════════════════════════════════════════════════════╗
# ║  201 — happy path                                          ║
# ╚════════════════════════════════════════════════════════════╝
@pytest.mark.anyio
async def test_issue_certificate_201_happy_path(
    async_client,
    db_session: AsyncSession,
    org_user_with_token,
    create_test_user,
    patch_external_dependencies,
):
    actor, headers, org = await org_user_with_token()
    learner: User = await create_test_user()
    course = await _mk_course(db_session, org=org, creator=actor)
    template = await _mk_template(db_session, org=org)

    payload = {
        "user_id": str(learner.id),
        "course_id": str(course.id),
        "organization_id": str(org.id),
        "template_id": str(template.id),
        "language_code": "en",
    }

    r = await async_client.post("/api/v1/courses/issue", headers=headers, json=payload)
    assert r.status_code == status.HTTP_201_CREATED, r.text
    body = r.json()

    assert body["course_id"] == str(course.id)
    assert body["organization_id"] == str(org.id)
    assert "license_id" in body
    assert body["certificate_pdf_url"] == "https://cdn.test/cert.pdf"
    assert body["preview_thumbnail_url"] == "https://cdn.test/thumb.png"
    assert body["qr_code_url"] == "https://cdn.test/qr.png"

    lic = body["license_id"]
    row = (
        await db_session.execute(select(IssuedCertificate).where(IssuedCertificate.license_id == lic))
    ).scalars().first()
    assert row is not None
    assert row.verification_url.endswith(f"/c/{lic}")


# ╔════════════════════════════════════════════════════════════╗
# ║  403 — org scope mismatch                                  ║
# ╚════════════════════════════════════════════════════════════╝
@pytest.mark.anyio
async def test_issue_certificate_403_wrong_org(
    async_client,
    db_session: AsyncSession,
    org_user_with_token,
    create_test_user,
    create_organization_fixture,
    patch_external_dependencies,
):
    actor, headers, orgA = await org_user_with_token()
    orgB = await create_organization_fixture()
    learner: User = await create_test_user()
    course = await _mk_course(db_session, org=orgA, creator=actor)
    template = await _mk_template(db_session, org=orgA)

    payload = {
        "user_id": str(learner.id),
        "course_id": str(course.id),
        "organization_id": str(orgB.id),  # mismatch triggers 403
        "template_id": str(template.id),
        "language_code": "en",
    }

    r = await async_client.post("/api/v1/courses/issue", headers=headers, json=payload)
    assert r.status_code == status.HTTP_403_FORBIDDEN
    assert "outside your organization" in r.text


# ╔════════════════════════════════════════════════════════════╗
# ║  409 — duplicate issuance                                  ║
# ╚════════════════════════════════════════════════════════════╝
@pytest.mark.anyio
async def test_issue_certificate_409_duplicate(
    async_client,
    db_session: AsyncSession,
    org_user_with_token,
    create_test_user,
    patch_external_dependencies,
):
    actor, headers, org = await org_user_with_token()
    learner: User = await create_test_user()
    course = await _mk_course(db_session, org=org, creator=actor)
    template = await _mk_template(db_session, org=org)

    payload = {
        "user_id": str(learner.id),
        "course_id": str(course.id),
        "organization_id": str(org.id),
        "template_id": str(template.id),
        "language_code": "en",
    }

    r1 = await async_client.post("/api/v1/courses/issue", headers=headers, json=payload)
    assert r1.status_code == status.HTTP_201_CREATED, r1.text

    r2 = await async_client.post("/api/v1/courses/issue", headers=headers, json=payload)
    assert r2.status_code == status.HTTP_409_CONFLICT
    assert "already issued" in r2.text or "conflicting" in r2.text


# ╔════════════════════════════════════════════════════════════╗
# ║  Idempotency replay → 201 with original body               ║
# ╚════════════════════════════════════════════════════════════╝
@pytest.mark.anyio
async def test_issue_certificate_idempotency_replay_201(
    async_client,
    db_session: AsyncSession,
    org_user_with_token,
    create_test_user,
    patch_external_dependencies,
):
    actor, headers, org = await org_user_with_token()
    learner: User = await create_test_user()
    course = await _mk_course(db_session, org=org, creator=actor)
    template = await _mk_template(db_session, org=org)

    idem_key = uuid.uuid4().hex
    headers_with_idem = {**headers, "Idempotency-Key": idem_key}

    payload = {
        "user_id": str(learner.id),
        "course_id": str(course.id),
        "organization_id": str(org.id),
        "template_id": str(template.id),
        "language_code": "en",
    }

    r1 = await async_client.post("/api/v1/courses/issue", headers=headers_with_idem, json=payload)
    assert r1.status_code == status.HTTP_201_CREATED, r1.text
    body1 = r1.json()

    r2 = await async_client.post("/api/v1/courses/issue", headers=headers_with_idem, json=payload)
    assert r2.status_code == status.HTTP_201_CREATED, r2.text
    body2 = r2.json()

    assert body1 == body2
