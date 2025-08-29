# tests/test_live/test_validate_user_session_token.py

import pytest
from httpx import AsyncClient
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone

from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy import select
from app.core.config import settings
from app.schemas.enums import OrgRole
from app.db.models.live_sessions import LiveSession
from app.db.models.user_organization import UserOrganization
from app.db.models.user import User
from app.db.models.revoked_token import RevokedToken

BASE = "/api/v1/course/live/security"  # adjust if your router is mounted elsewhere
ALGO = getattr(settings, "JWT_ALGORITHM", "HS256")
ISSUER = getattr(settings, "JWT_ISSUER", "careerOS")
SECRET = settings.LIVE_SESSION_SECRET.get_secret_value()

# ------------------------ Helpers ------------------------

def _mk_session(org_id, starts_in_minutes=-5, ends_in_minutes=60):
    now = datetime.now(timezone.utc)
    data = dict(
        title="Validate Token Session",
        organization_id=org_id,
        start_time=now + timedelta(minutes=starts_in_minutes),
        end_time=now + timedelta(minutes=ends_in_minutes),
    )
    if hasattr(LiveSession, "is_deleted"):
        data["is_deleted"] = False
    return LiveSession(**data)

async def _mk_user(db: AsyncSession, email: str, full_name: str = None):
    from app.db.models.user import User
    # reuse if already exists (prevents UNIQUE(email) violation)
    existing = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if existing:
        return existing

    u = User(
        email=email,
        hashed_password="x",
        is_active=True,
        is_verified=True,
        full_name=full_name,
        created_at=datetime.now(timezone.utc),
        **({"updated_at": datetime.now(timezone.utc)} if hasattr(User, "updated_at") else {}),
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


async def _add_membership(db: AsyncSession, user_id, org_id, role=OrgRole.INTERN, is_active=True):
    m = UserOrganization(
        user_id=user_id,
        organization_id=org_id,
        role=role,
        is_active=is_active,
    )
    db.add(m)
    await db.commit()
    await db.refresh(m)
    return m

def _token(
    *,
    sub: str,
    session_id: str,
    org_id: str,
    exp_secs: int = 24 * 60 * 60,  # generous to avoid clock quirks
    scope: str = "live_session_access",
    jti: str | None = None,
    extra: dict | None = None,
):
    now = int(datetime.now(timezone.utc).timestamp())
    claims = {
        "sub": sub,
        "session_id": session_id,  # route also accepts 'sid'
        "org_id": org_id,          # route also accepts 'org'
        "scope": scope,
        "iss": ISSUER,
        # NB: omit 'aud' to avoid decoder rejecting it
        "iat": now,
        "nbf": now - 10,
        "exp": now + exp_secs,
        "jti": jti or str(uuid4()),
        "issuer_id": sub,
        "source": "api",
        "ver": 1,
    }
    if extra:
        claims.update(extra)
    return jwt.encode(claims, SECRET, algorithm=ALGO), claims

# ------------------------ Tests --------------------------

@pytest.mark.anyio
async def test_validate_ok__200(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    org_id = str(org.id)

    subject = await _mk_user(db_session, "subject@example.com")
    await _add_membership(db_session, subject.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    token, _ = _token(sub=str(subject.id), session_id=sid, org_id=org_id)

    r = await async_client.post(f"{BASE}/{sid}/validate-user", headers=headers, json={"access_token": token})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["message"] == "Token is valid"
    assert body["user_id"] == str(subject.id)
    assert body["session_id"] == sid
    assert body["expires_at"].endswith("Z")


@pytest.mark.anyio
async def test_validate__401_invalid_signature(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    org_id = str(org.id)
    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    bogus = jwt.encode(
        {
            "sub": str(admin.id),
            "session_id": sid,
            "org_id": org_id,
            "scope": "live_session_access",
            "jti": str(uuid4()),
            "exp": int(datetime.now(timezone.utc).timestamp()) + 86400,
        },
        "WRONG_SECRET",
        algorithm=ALGO,
    )

    r = await async_client.post(f"{BASE}/{sid}/validate-user", headers=headers, json={"access_token": bogus})
    assert r.status_code == 401
    assert "invalid token" in r.text.lower()


@pytest.mark.anyio
async def test_validate__401_expired(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    org_id = str(org.id)
    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    token, _ = _token(sub=str(admin.id), session_id=sid, org_id=org_id, exp_secs=-60)

    r = await async_client.post(f"{BASE}/{sid}/validate-user", headers=headers, json={"access_token": token})
    assert r.status_code == 401
    assert "expired" in r.text.lower()


@pytest.mark.anyio
async def test_validate__400_missing_claims(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    now = int(datetime.now(timezone.utc).timestamp())
    # Missing org_id on purpose
    claims = {
        "sub": str(admin.id),
        "session_id": sid,
        "scope": "live_session_access",
        "jti": str(uuid4()),
        "exp": now + 86400,
    }
    token = jwt.encode(claims, SECRET, algorithm=ALGO)

    r = await async_client.post(f"{BASE}/{sid}/validate-user", headers=headers, json={"access_token": token})
    assert r.status_code == 400
    assert "incomplete" in r.text.lower()


@pytest.mark.anyio
async def test_validate__403_wrong_scope(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    org_id = str(org.id)
    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    token, _ = _token(sub=str(admin.id), session_id=sid, org_id=org_id, scope="different_scope")

    r = await async_client.post(f"{BASE}/{sid}/validate-user", headers=headers, json={"access_token": token})
    assert r.status_code == 403
    assert "scope" in r.text.lower()


@pytest.mark.anyio
async def test_validate__400_session_mismatch(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    org_id = str(org.id)
    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)

    wrong_sid = str(uuid4())
    token, _ = _token(sub=str(admin.id), session_id=wrong_sid, org_id=org_id)

    r = await async_client.post(f"{BASE}/{str(session.id)}/validate-user", headers=headers, json={"access_token": token})
    assert r.status_code == 400
    assert "does not match session" in r.text.lower()


@pytest.mark.anyio
async def test_validate__403_org_mismatch(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    # Use a random UUID as the token org_id so it mismatches user_org.organization_id
    bad_org_id = str(uuid4())
    token, _ = _token(sub=str(admin.id), session_id=sid, org_id=bad_org_id)

    r = await async_client.post(f"{BASE}/{sid}/validate-user", headers=headers, json={"access_token": token})
    assert r.status_code == 403
    assert "does not match organization" in r.text.lower()


@pytest.mark.anyio
async def test_validate__400_bad_subject_uuid(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)

    token, _ = _token(sub="not-a-uuid", session_id=str(session.id), org_id=str(org.id))

    r = await async_client.post(f"{BASE}/{str(session.id)}/validate-user", headers=headers, json={"access_token": token})
    assert r.status_code == 400
    assert "invalid subject" in r.text.lower()


@pytest.mark.anyio
async def test_validate__401_revoked(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    org_id = str(org.id)

    subject = await _mk_user(db_session, "revoked@example.com")
    await _add_membership(db_session, subject.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    token, claims = _token(sub=str(subject.id), session_id=sid, org_id=org_id)

    # Insert a realistic revoked row to satisfy NOT NULL constraints (id/org/user/by/time/jti/reason)
    revoked = RevokedToken(
        id=uuid4(),
        jti=claims["jti"],
        token_type="access",  # matches your schema
        user_id=subject.id,
        revoked_by=admin.id,
        org_id=org.id,
        issued_at=datetime.utcfromtimestamp(int(claims["iat"])) if "iat" in claims else datetime.now(timezone.utc),
        expires_at=datetime.utcfromtimestamp(int(claims["exp"])) if "exp" in claims else None,
        revoked_at=datetime.now(timezone.utc),
        reason="test",
        # source_ip / user_agent are nullable in your dump; omit or set to None
    )
    db_session.add(revoked)
    await db_session.commit()

    r = await async_client.post(f"{BASE}/{sid}/validate-user", headers=headers, json={"access_token": token})
    assert r.status_code == 401
    assert "revoked" in r.text.lower()


@pytest.mark.anyio
async def test_validate__403_no_active_membership(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    subject = await _mk_user(db_session, "inactive@example.com")
    await _add_membership(db_session, subject.id, org.id, role=OrgRole.INTERN, is_active=False)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    token, _ = _token(sub=str(subject.id), session_id=sid, org_id=str(org.id))

    r = await async_client.post(f"{BASE}/{sid}/validate-user", headers=headers, json={"access_token": token})
    assert r.status_code == 403
    assert "not an active member" in r.text.lower()


@pytest.mark.anyio
async def test_validate__404_session_not_found(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    session = _mk_session(org.id)
    if hasattr(session, "is_deleted"):
        setattr(session, "is_deleted", True)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    token, _ = _token(sub=str(admin.id), session_id=sid, org_id=str(org.id))

    r = await async_client.post(f"{BASE}/{sid}/validate-user", headers=headers, json={"access_token": token})
    assert r.status_code == 404
    assert "not found" in r.text.lower()


@pytest.mark.anyio
async def test_validate__403_not_started_yet(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    subject = await _mk_user(db_session, "early@example.com")
    await _add_membership(db_session, subject.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id, starts_in_minutes=10, ends_in_minutes=70)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    token, _ = _token(sub=str(subject.id), session_id=sid, org_id=str(org.id))

    r = await async_client.post(f"{BASE}/{sid}/validate-user", headers=headers, json={"access_token": token})
    assert r.status_code == 403
    assert "not started" in r.text.lower()


@pytest.mark.anyio
async def test_validate__403_session_ended(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    subject = await _mk_user(db_session, "ended@example.com")
    await _add_membership(db_session, subject.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id, starts_in_minutes=-120, ends_in_minutes=-60)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    token, _ = _token(sub=str(subject.id), session_id=sid, org_id=str(org.id))

    r = await async_client.post(f"{BASE}/{sid}/validate-user", headers=headers, json={"access_token": token})
    assert r.status_code == 403
    assert "ended" in r.text.lower()


@pytest.mark.anyio
async def test_validate__accepts_alt_claim_names_sid_org(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    subject = await _mk_user(db_session, "alt@example.com")
    await _add_membership(db_session, subject.id, org.id, role=OrgRole.INTERN, is_active=True)

    session = _mk_session(org.id)
    db_session.add(session); await db_session.commit(); await db_session.refresh(session)
    sid = str(session.id)

    now = int(datetime.now(timezone.utc).timestamp())
    claims = {
        "sub": str(subject.id),
        "sid": sid,           # alt claim
        "org": str(org.id),   # alt claim
        "scope": "live_session_access",
        "jti": str(uuid4()),
        "exp": now + 86400,
    }
    token = jwt.encode(claims, SECRET, algorithm=ALGO)

    r = await async_client.post(f"{BASE}/{sid}/validate-user", headers=headers, json={"access_token": token})
    assert r.status_code == 200, r.text
