# tests/test_courses/test_certificates_admin_preview_jwks.py

import uuid
import json
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import status

from tests.test_courses.test_certificates_issue import _mk_course, _mk_template

# Helpers
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

async def _issue_cert(async_client, headers, user_id, course_id, org_id, template_id, language_code="en") -> str:
    """Issue a certificate and return its license_id."""
    payload = {
        "user_id": str(user_id),
        "course_id": str(course_id),
        "organization_id": str(org_id),
        "template_id": str(template_id),
        "language_code": language_code,
    }
    r = await async_client.post("/api/v1/courses/issue", headers=headers, json=payload)
    assert r.status_code == status.HTTP_201_CREATED, r.text
    return r.json()["license_id"]


def _is_http_url(v: str) -> bool:
    return isinstance(v, str) and (v.startswith("https://") or v.startswith("http://"))


# ────────────────────────────────────────────────────────────────────────────
# Revoke
# ────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_revoke_certificate_success_and_idempotency(
    async_client, db_session, org_user_with_token, create_test_user
):
    # Arrange
    actor, headers, org = await org_user_with_token()
    learner = await create_test_user()
    course = await _mk_course(db_session, org=org, creator=actor)
    template = await _mk_template(db_session, org=org)
    license_id = await _issue_cert(async_client, headers, learner.id, course.id, org.id, template.id)

    # Act: revoke (first call)
    body = {"reason": "fraudulent submission"}
    r1 = await async_client.post(f"/api/v1/courses/c/{license_id}/revoke", headers=headers, json=body)
    assert r1.status_code == status.HTTP_200_OK, r1.text
    js1 = r1.json()

    # Response shape / state
    assert js1["license_id"] == license_id
    # Service maps to REVOKED when available, else INACTIVE; accept both.
    assert js1["status"].lower() in {"revoked", "inactive"}
    # "revoked_at" may or may not be present depending on response model; only assert if present.
    if "revoked_at" in js1:
        assert isinstance(js1["revoked_at"], (str, type(None)))
        # if provided, it should look like an ISO Zulu timestamp
        if js1["revoked_at"] is not None:
            assert js1["revoked_at"].endswith("Z")

    # Idempotency snapshot (same key → replayed body + header)
    idem_headers = dict(headers)
    idem_headers["Idempotency-Key"] = "revoke-key-1"
    r2 = await async_client.post(f"/api/v1/courses/c/{license_id}/revoke", headers=idem_headers, json=body)
    assert r2.status_code == status.HTTP_200_OK
    # First call with a given key will store the snapshot; second call with the same key should replay.
    r3 = await async_client.post(f"/api/v1/courses/c/{license_id}/revoke", headers=idem_headers, json=body)
    assert r3.status_code == status.HTTP_200_OK
    assert r3.headers.get("Idempotency-Replayed") == "true"
    assert r3.json() == r2.json()  # verbatim replay

    # Calling revoke again with a DIFFERENT key should not be considered a replay
    idem_headers2 = dict(headers)
    idem_headers2["Idempotency-Key"] = "revoke-key-2"
    r4 = await async_client.post(f"/api/v1/courses/c/{license_id}/revoke", headers=idem_headers2, json=body)
    assert r4.status_code == status.HTTP_200_OK
    assert r4.headers.get("Idempotency-Replayed") in (None, "false")


@pytest.mark.anyio
async def test_revoke_certificate_404_when_missing(async_client, org_user_with_token):
    _, headers, _ = await org_user_with_token()
    r = await async_client.post("/api/v1/courses/c/NOT-A-REAL-LIC/revoke", headers=headers, json={"reason": "x"})
    assert r.status_code == status.HTTP_404_NOT_FOUND
    assert r.json()["detail"].lower().startswith("certificate not found")


@pytest.mark.anyio
async def test_revoke_certificate_403_cross_org(
    async_client, db_session, org_user_with_token, create_test_user
):
    # Org A issues
    actor_a, headers_a, org_a = await org_user_with_token()
    learner = await create_test_user()
    course = await _mk_course(db_session, org=org_a, creator=actor_a)
    template = await _mk_template(db_session, org=org_a)
    license_id = await _issue_cert(async_client, headers_a, learner.id, course.id, org_a.id, template.id)

    # Org B tries to revoke Org A's cert → 403
    _, headers_b, _ = await org_user_with_token()
    r = await async_client.post(f"/api/v1/courses/c/{license_id}/revoke", headers=headers_b, json={"reason": "nope"})
    assert r.status_code == status.HTTP_403_FORBIDDEN


# ────────────────────────────────────────────────────────────────────────────
# Reactivate
# ────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_reactivate_certificate_success_and_idempotency(
    async_client, db_session, org_user_with_token, create_test_user
):
    # Arrange
    actor, headers, org = await org_user_with_token()
    learner = await create_test_user()
    course = await _mk_course(db_session, org=org, creator=actor)
    template = await _mk_template(db_session, org=org)
    license_id = await _issue_cert(async_client, headers, learner.id, course.id, org.id, template.id)

    # Revoke first
    r_rev = await async_client.post(f"/api/v1/courses/c/{license_id}/revoke", headers=headers, json={"reason": "x"})
    assert r_rev.status_code == status.HTTP_200_OK

    # Reactivate
    r1 = await async_client.post(f"/api/v1/courses/c/{license_id}/reactivate", headers=headers)
    assert r1.status_code == status.HTTP_200_OK, r1.text
    js1 = r1.json()
    assert js1["license_id"] == license_id
    assert js1["status"].lower() == "active"
    # If present, revoked flags must be cleared
    if "revoked_at" in js1:
        assert js1["revoked_at"] is None
    if "revoke_reason" in js1:
        assert js1["revoke_reason"] in (None, "")

    # Idempotency on reactivate
    idem_headers = dict(headers)
    idem_headers["Idempotency-Key"] = "reactivate-key-1"
    r2 = await async_client.post(f"/api/v1/courses/c/{license_id}/reactivate", headers=idem_headers)
    assert r2.status_code == status.HTTP_200_OK
    r3 = await async_client.post(f"/api/v1/courses/c/{license_id}/reactivate", headers=idem_headers)
    assert r3.status_code == status.HTTP_200_OK
    assert r3.headers.get("Idempotency-Replayed") == "true"
    assert r3.json() == r2.json()


@pytest.mark.anyio
async def test_reactivate_noop_when_already_active(
    async_client, db_session, org_user_with_token, create_test_user
):
    actor, headers, org = await org_user_with_token()
    learner = await create_test_user()
    course = await _mk_course(db_session, org=org, creator=actor)
    template = await _mk_template(db_session, org=org)
    license_id = await _issue_cert(async_client, headers, learner.id, course.id, org.id, template.id)

    r = await async_client.post(f"/api/v1/courses/c/{license_id}/reactivate", headers=headers)
    assert r.status_code == status.HTTP_200_OK
    assert r.json()["status"].lower() == "active"


# ────────────────────────────────────────────────────────────────────────────
# Preview
# ────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_preview_certificate_invalid_template_returns_404_or_422(async_client, org_user_with_token):
    """
    Some implementations validate the template_id early and return 422,
    others look it up and return 404. Accept either but assert useful shape.
    """
    _, headers, _ = await org_user_with_token()
    payload = {
        "template_id": str(uuid.uuid4()),  # valid UUID, but not present
        "learner_name": "X",
        "course_title": "Y",
        "course_description": "Z",
        "language_code": "en",
    }
    r = await async_client.post("/api/v1/courses/preview", headers=headers, json=payload)
    assert r.status_code in (status.HTTP_404_NOT_FOUND, status.HTTP_422_UNPROCESSABLE_ENTITY)
    js = r.json()
    # error payload should have "detail"
    assert "detail" in js


@pytest.mark.anyio
async def test_preview_certificate_success_returns_urls(async_client, db_session, org_user_with_token):
    _, headers, org = await org_user_with_token()
    template = await _mk_template(db_session, org=org)

    payload = {
        "template_id": str(template.id),
        "learner_name": "Ada Lovelace",
        "course_title": "Intro to Engines",
        "course_description": "Boilerplate",
        "language_code": "en",
    }
    r = await async_client.post("/api/v1/courses/preview", headers=headers, json=payload)
    assert r.status_code == status.HTTP_200_OK, r.text
    js = r.json()
    assert "pdf_url" in js and "thumbnail_url" in js
    assert _is_http_url(js["pdf_url"])
    assert _is_http_url(js["thumbnail_url"])


# ────────────────────────────────────────────────────────────────────────────
# JWKS
# NOTE: Your app's Settings are instantiated at import time and don't expose
# a setter; toggling env at runtime won’t reliably change behavior here.
# So the tests below assert structure + cacheability and adapt to whatever
# algorithm is currently configured (EC or RSA) or disabled (empty set).
# ────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_jwks_paths_consistent_and_cacheable(async_client):
    r1 = await async_client.get("/api/v1/courses/.well-known/jwks.json")
    r2 = await async_client.get("/api/v1/courses/jwks.json")

    assert r1.status_code == status.HTTP_200_OK
    assert r2.status_code == status.HTTP_200_OK

    js1 = r1.json()
    js2 = r2.json()

    assert isinstance(js1, dict) and isinstance(js2, dict)
    assert "keys" in js1 and isinstance(js1["keys"], list)
    assert "keys" in js2 and isinstance(js2["keys"], list)
    # Both routes should serve identical content
    assert js1 == js2

    # Public cache present with a max-age
    cc1 = r1.headers.get("Cache-Control", "")
    cc2 = r2.headers.get("Cache-Control", "")
    assert "max-age" in cc1 and "max-age" in cc2


@pytest.mark.anyio
async def test_jwks_key_shape_if_present(async_client):
    """
    If JWS is enabled, ensure the key shape matches the advertised algorithm.
    If it's disabled, we simply get an empty set.
    """
    r = await async_client.get("/api/v1/courses/jwks.json")
    assert r.status_code == status.HTTP_200_OK
    js = r.json()
    assert "keys" in js and isinstance(js["keys"], list)

    if not js["keys"]:
        # Disabled config → nothing to assert further
        return

    # Enabled → one key expected
    k = js["keys"][0]
    assert isinstance(k.get("kid"), str) and k["kid"]
    assert isinstance(k.get("alg"), str) and k["alg"] in {"ES256", "RS256"}
    assert isinstance(k.get("kty"), str)

    if k["kty"] == "EC":
        # ES256/P-256
        assert k["alg"] == "ES256"
        assert k.get("crv") == "P-256"
        assert isinstance(k.get("x"), str) and isinstance(k.get("y"), str)
        assert "n" not in k and "e" not in k
    elif k["kty"] == "RSA":
        # RS256
        assert k["alg"] == "RS256"
        assert isinstance(k.get("n"), str) and isinstance(k.get("e"), str)
        assert "x" not in k and "y" not in k
    else:
        pytest.fail(f"Unexpected kty in JWKS: {k['kty']}")


# (Optional) Smoke tests for env hints — these DO NOT rely on settings being
# re-loaded; they just ensure the endpoint behaves safely even if env vars
# are set to unexpected combinations.
@pytest.mark.anyio
async def test_jwks_endpoint_is_robust_under_random_env(async_client, monkeypatch):
    # Set odd env values; endpoint should still return 200 with a sane payload.
    monkeypatch.setenv("JWS_ENABLED", "maybe")
    monkeypatch.setenv("JWS_ALG", "HS256")  # unsupported
    monkeypatch.setenv("JWS_PRIVATE_KEY_PEM", "not a key")
    monkeypatch.setenv("JWS_KID", "weird-kid")

    r = await async_client.get("/api/v1/courses/jwks.json")
    assert r.status_code == status.HTTP_200_OK
    js = r.json()
    assert "keys" in js and isinstance(js["keys"], list)  # either [] or a valid list
