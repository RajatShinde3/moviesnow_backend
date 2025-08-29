# tests/test_live/test_soft_delete_feedback.py

import pytest
from httpx import AsyncClient
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime, parsedate_to_datetime
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy import select
from sqlalchemy.orm import noload

from app.schemas.enums import OrgRole
from app.db.models.live_sessions import LiveSession
from app.db.models.live_session_feedback import LiveSessionFeedback

BASE = "/api/v1/course/live/feedback"

# ---------- helpers -----------------------------------------------------------

def _set_if_has(obj, **vals):
    for k, v in vals.items():
        if hasattr(obj, k):
            setattr(obj, k, v)

def _mk_session(org_id):
    now = datetime.now(timezone.utc)
    return LiveSession(
        title="Delete Test Session",
        organization_id=org_id,
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(hours=1),
    )

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

# ---------- tests -------------------------------------------------------------

@pytest.mark.anyio
async def test_soft_delete_feedback__404_when_not_found_and_not_idempotent(async_client: AsyncClient, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    missing = uuid4()
    r = await async_client.delete(f"{BASE}/feedback/{missing}", headers=headers)
    assert r.status_code == 404
    assert "not found" in r.text.lower()

@pytest.mark.anyio
async def test_soft_delete_feedback__204_when_not_found_and_idempotent(async_client: AsyncClient, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    missing = uuid4()
    r = await async_client.delete(f"{BASE}/feedback/{missing}?idempotent=true", headers=headers)
    assert r.status_code == 204
    assert r.text == ""

@pytest.mark.anyio
async def test_soft_delete_feedback__org_scoping_prevents_cross_tenant_delete(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, create_organization_fixture
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    other_org = await create_organization_fixture()
    sess_other = _mk_session(other_org.id)
    db_session.add(sess_other); await db_session.commit(); await db_session.refresh(sess_other)

    author = await _mk_user(db_session, "author@example.com", "Author")
    fb_other = LiveSessionFeedback(
        session_id=sess_other.id, user_id=author.id, rating=4, comments="other org", created_at=datetime.now(timezone.utc)
    )
    db_session.add(fb_other); await db_session.commit(); await db_session.refresh(fb_other)

    r1 = await async_client.delete(f"{BASE}/feedback/{fb_other.id}", headers=headers)
    assert r1.status_code == 404

    r2 = await async_client.delete(f"{BASE}/feedback/{fb_other.id}?idempotent=true", headers=headers)
    assert r2.status_code == 204

@pytest.mark.anyio
async def test_soft_delete_feedback__403_when_not_author_nor_admin(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    member, member_headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    sess = _mk_session(org.id)
    _set_if_has(sess, created_by=member.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    other_user = await _mk_user(db_session, "other@example.com", "Other Author")
    fb = LiveSessionFeedback(
        session_id=sess.id, user_id=other_user.id, rating=3, comments="nope", created_at=datetime.now(timezone.utc)
    )
    db_session.add(fb); await db_session.commit(); await db_session.refresh(fb)

    r = await async_client.delete(f"{BASE}/feedback/{fb.id}", headers=member_headers)
    assert r.status_code == 403

    refreshed = await db_session.get(LiveSessionFeedback, fb.id)
    assert getattr(refreshed, "is_deleted", False) is False

@pytest.mark.anyio
async def test_soft_delete_feedback__204_author_can_delete_self(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    author, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    sess = _mk_session(org.id)
    _set_if_has(sess, created_by=author.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    fb = LiveSessionFeedback(session_id=sess.id, user_id=author.id, rating=5, comments="mine", created_at=datetime.now(timezone.utc))
    db_session.add(fb); await db_session.commit(); await db_session.refresh(fb)

    r = await async_client.delete(f"{BASE}/feedback/{fb.id}", headers=headers)
    assert r.status_code == 204

    refreshed = await db_session.get(LiveSessionFeedback, fb.id)
    assert getattr(refreshed, "is_deleted", False) is True
    assert getattr(refreshed, "deleted_at", None) is not None
    if hasattr(LiveSessionFeedback, "deleted_by"):
        assert getattr(refreshed, "deleted_by") == author.id

@pytest.mark.anyio
async def test_soft_delete_feedback__204_admin_can_delete_others_and_reason_stored(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    sess = _mk_session(org.id)
    _set_if_has(sess, created_by=admin.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    author = await _mk_user(db_session, "author2@example.com", "A2")
    fb = LiveSessionFeedback(session_id=sess.id, user_id=author.id, rating=2, comments="please delete", created_at=datetime.now(timezone.utc))
    db_session.add(fb); await db_session.commit(); await db_session.refresh(fb)

    reason = "spam content"
    r = await async_client.delete(f"{BASE}/feedback/{fb.id}?reason={reason}", headers=headers)
    assert r.status_code == 204

    refreshed = await db_session.get(LiveSessionFeedback, fb.id)
    assert getattr(refreshed, "is_deleted", False) is True
    if hasattr(LiveSessionFeedback, "deleted_by"):
        assert getattr(refreshed, "deleted_by") == admin.id
    if hasattr(LiveSessionFeedback, "deleted_reason"):
        assert getattr(refreshed, "deleted_reason") == reason

@pytest.mark.anyio
async def test_soft_delete_feedback__already_deleted_404_then_idempotent_204(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    sess = _mk_session(org.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    author = await _mk_user(db_session, "author3@example.com", "A3")
    fb = LiveSessionFeedback(session_id=sess.id, user_id=author.id, rating=3, comments="first", created_at=datetime.now(timezone.utc))
    db_session.add(fb); await db_session.commit(); await db_session.refresh(fb)

    r1 = await async_client.delete(f"{BASE}/feedback/{fb.id}", headers=headers)
    assert r1.status_code == 204

    r2 = await async_client.delete(f"{BASE}/feedback/{fb.id}", headers=headers)
    assert r2.status_code == 404

    r3 = await async_client.delete(f"{BASE}/feedback/{fb.id}?idempotent=true", headers=headers)
    assert r3.status_code == 204


@pytest.mark.anyio
async def test_soft_delete_feedback__412_if_unmodified_since_precondition_fails(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    sess = _mk_session(org.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    author = await _mk_user(db_session, "author4@example.com", "A4")

    # Row timestamps we expect the server to compare against
    last_updated = datetime.now(timezone.utc).replace(microsecond=0)
    fb = LiveSessionFeedback(
        session_id=sess.id, user_id=author.id, rating=4, comments="precond", created_at=last_updated
    )
    _set_if_has(fb, updated_at=last_updated)
    db_session.add(fb); await db_session.commit(); await db_session.refresh(fb)

    # Build If-Unmodified-Since header (older than last_updated → should FAIL precondition)
    client_dt = last_updated - timedelta(seconds=5)
    header_val = format_datetime(client_dt.replace(tzinfo=timezone.utc))

    # --- DEBUG: show what we're sending vs what's stored ---
    print("\nDEBUG test_soft_delete_feedback__412")
    print(f"DEBUG last_updated (naive/local): {last_updated.isoformat()}")
    print(f"DEBUG client_dt (naive/local):    {client_dt.isoformat()}")
    print(f"DEBUG header 'If-Unmodified-Since': {header_val}")
    try:
        parsed_hdr = parsedate_to_datetime(header_val)
        print(f"DEBUG parsed header (aware):      {parsed_hdr}  tzinfo={parsed_hdr.tzinfo}")
    except Exception as e:
        print(f"DEBUG header parse error: {e!r}")

    # Hit the route
    r = await async_client.delete(
        f"{BASE}/feedback/{fb.id}",
        headers={**headers, "If-Unmodified-Since": header_val},
    )

    # --- DEBUG: show server response details ---
    print(f"DEBUG response.status={r.status_code}")
    print(f"DEBUG response.headers={dict(r.headers)}")
    # 204 has no body; print if present (e.g., on error)
    if r.text:
        print(f"DEBUG response.body={r.text}")

    assert r.status_code == 412

@pytest.mark.anyio
async def test_soft_delete_feedback__400_if_unmodified_since_malformed(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    sess = _mk_session(org.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    author = await _mk_user(db_session, "author5@example.com", "A5")
    fb = LiveSessionFeedback(session_id=sess.id, user_id=author.id, rating=5, comments="bad header", created_at=datetime.now(timezone.utc))
    db_session.add(fb); await db_session.commit(); await db_session.refresh(fb)

    r = await async_client.delete(f"{BASE}/feedback/{fb.id}", headers={**headers, "If-Unmodified-Since": "not-a-date"})
    assert r.status_code == 400
    assert "Invalid If-Unmodified-Since" in r.text

@pytest.mark.anyio
async def test_soft_delete_feedback__precondition_ok_then_deleted(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    sess = _mk_session(org.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    author = await _mk_user(db_session, "author6@example.com", "A6")

    last_updated = datetime.now(timezone.utc).replace(microsecond=0)
    fb = LiveSessionFeedback(session_id=sess.id, user_id=author.id, rating=1, comments="ok header", created_at=last_updated)
    _set_if_has(fb, updated_at=last_updated)
    db_session.add(fb); await db_session.commit(); await db_session.refresh(fb)

    client_dt = last_updated + timedelta(seconds=5)
    header_val = format_datetime(client_dt.replace(tzinfo=timezone.utc))
    r = await async_client.delete(f"{BASE}/feedback/{fb.id}", headers={**headers, "If-Unmodified-Since": header_val})
    assert r.status_code == 204

    refreshed = await db_session.get(LiveSessionFeedback, fb.id)
    assert getattr(refreshed, "is_deleted", False) is True
    assert getattr(refreshed, "deleted_at", None) is not None

@pytest.mark.anyio
async def test_soft_delete_feedback__409_when_row_locked_elsewhere(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Endpoint uses WITH FOR UPDATE SKIP LOCKED, then a non-locking check.
    We lock the row from a *separate* AsyncSession and keep the tx open,
    so the API should return 409 while the lock is held.
    """
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    sess = _mk_session(org.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    author = await _mk_user(db_session, "author7@example.com", "A7")
    fb = LiveSessionFeedback(session_id=sess.id, user_id=author.id, rating=2, comments="lock me", created_at=datetime.now(timezone.utc))
    db_session.add(fb); await db_session.commit(); await db_session.refresh(fb)

    # Hold a row lock in another session
    SessionLocal = async_sessionmaker(bind=db_session.bind, expire_on_commit=False)
    locker = SessionLocal()
    await locker.begin()  # keep tx open
    try:
        await locker.execute(
            select(LiveSessionFeedback)
            .options(noload(LiveSessionFeedback.session), noload(LiveSessionFeedback.user))
            .where(LiveSessionFeedback.id == fb.id)
            .with_for_update(of=LiveSessionFeedback, nowait=False)
        )

        r_locked = await async_client.delete(f"{BASE}/feedback/{fb.id}", headers=headers)
        assert r_locked.status_code == 409, r_locked.text
    finally:
        await locker.rollback()
        await locker.close()

    # After releasing the lock, delete should succeed
    r_after = await async_client.delete(f"{BASE}/feedback/{fb.id}", headers=headers)
    assert r_after.status_code == 204
