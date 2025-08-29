# tests/test_live/test_update_admin_note_on_feedback.py

import pytest
from httpx import AsyncClient
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from sqlalchemy import select, update
from sqlalchemy.orm import noload
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.schemas.enums import OrgRole
from app.db.models.live_sessions import LiveSession
from app.db.models.live_session_feedback import LiveSessionFeedback

# API base and helper to build the endpoint path
BASE = "/api/v1/course/live/feedback"
def ADMIN_NOTE(fid):  # -> /api/v1/course/live/feedback/feedback/{id}/admin-note
    return f"{BASE}/feedback/{fid}/admin-note"


# ---------- helpers -----------------------------------------------------------

def _set_if_has(obj, **vals):
    for k, v in vals.items():
        if hasattr(obj, k):
            setattr(obj, k, v)

def _mk_session(org_id):
    now = datetime.now(timezone.utc)
    return LiveSession(
        title="Admin Note Test Session",
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
async def test_admin_note__404_when_not_found(async_client: AsyncClient, org_user_with_token):
    admin, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    missing = uuid4()
    r = await async_client.put(ADMIN_NOTE(missing), headers=headers, json={"note": "x"})
    assert r.status_code == 404


@pytest.mark.anyio
async def test_admin_note__403_when_not_admin(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    member, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)

    sess = _mk_session(org.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    author = await _mk_user(db_session, "nadmin@example.com", "NAdmin")
    fb = LiveSessionFeedback(
        session_id=sess.id, user_id=author.id, rating=4, comments="c", created_at=datetime.now(timezone.utc)
    )
    db_session.add(fb); await db_session.commit(); await db_session.refresh(fb)

    r = await async_client.put(ADMIN_NOTE(fb.id), headers=headers, json={"note": "nope"})
    assert r.status_code == 403


@pytest.mark.anyio
async def test_admin_note__404_when_soft_deleted(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    sess = _mk_session(org.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    author = await _mk_user(db_session, "sd@example.com", "SD")
    fb = LiveSessionFeedback(
        session_id=sess.id, user_id=author.id, rating=3, comments="z", created_at=datetime.now(timezone.utc)
    )
    db_session.add(fb); await db_session.commit(); await db_session.refresh(fb)

    # soft delete directly
    await db_session.execute(
        update(LiveSessionFeedback)
        .where(LiveSessionFeedback.id == fb.id)
        .values(is_deleted=True, deleted_at=datetime.now(timezone.utc))
    )
    await db_session.commit()

    r = await async_client.put(ADMIN_NOTE(fb.id), headers=headers, json={"note": "should 404"})
    assert r.status_code == 404


@pytest.mark.anyio
async def test_admin_note__400_if_unmodified_since_malformed(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    sess = _mk_session(org.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    author = await _mk_user(db_session, "badhdr@example.com", "B1")
    fb = LiveSessionFeedback(
        session_id=sess.id, user_id=author.id, rating=5, comments="hdr", created_at=datetime.now(timezone.utc)
    )
    db_session.add(fb); await db_session.commit(); await db_session.refresh(fb)

    r = await async_client.put(
        ADMIN_NOTE(fb.id),
        headers={**headers, "If-Unmodified-Since": "not-a-date"},
        json={"note": "x"},
    )
    assert r.status_code == 400
    assert "Invalid If-Unmodified-Since" in r.text


from pprint import pformat
from email.utils import parsedate_to_datetime, format_datetime

@pytest.mark.anyio
async def test_admin_note__412_precondition_failed(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    print("\n=== setup ===")
    sess = _mk_session(org.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    author = await _mk_user(db_session, "pre@example.com", "P1")
    last_updated = datetime.now(timezone.utc).replace(microsecond=0)
    print(f"server last_updated (naive utc): {last_updated!r}")

    fb = LiveSessionFeedback(
        session_id=sess.id, user_id=author.id, rating=2, comments="p", created_at=last_updated
    )
    _set_if_has(fb, updated_at=last_updated)
    db_session.add(fb); await db_session.commit(); await db_session.refresh(fb)

    # Print what actually got persisted on the model after refresh
    db_created = getattr(fb, "created_at", None)
    db_updated = getattr(fb, "updated_at", None)
    print(f"db created_at: {db_created!r}")
    print(f"db updated_at: {db_updated!r}")

    client_dt = last_updated - timedelta(seconds=5)  # older than server -> must 412
    hdr = format_datetime(client_dt.replace(tzinfo=timezone.utc))
    print(f"client_dt (utc): {client_dt!r}")
    print(f"If-Unmodified-Since (hdr): {hdr}")

    print("\n=== request ===")
    url = ADMIN_NOTE(fb.id)
    print(f"PUT {url}")
    r = await async_client.put(
        url,
        headers={**headers, "If-Unmodified-Since": hdr},
        json={"note": "won't update"},
    )

    print(f"status: {r.status_code}")
    # Show response headers (Last-Modified, ETag, etc.)
    print("response.headers:\n" + pformat(dict(r.headers)))
    # Show body (error JSON or text)
    try:
        print("response.json:", r.json())
    except Exception:
        print("response.text:", r.text)

    # Parse Last-Modified if present to verify server’s notion of last-modified
    lm_hdr = r.headers.get("Last-Modified")
    if lm_hdr:
        try:
            lm_dt = parsedate_to_datetime(lm_hdr)
            if lm_dt.tzinfo is None:
                lm_dt = lm_dt.replace(tzinfo=timezone.utc)
            else:
                lm_dt = lm_dt.astimezone(timezone.utc)
            lm_dt = lm_dt.replace(microsecond=0)
            print(f"parsed Last-Modified (UTC, s): {lm_dt!r}")
        except Exception as e:
            print(f"could not parse Last-Modified header: {e}")

    assert r.status_code == 412, "Expected 412 Precondition Failed when client IMS is older than server last-mod"



@pytest.mark.anyio
async def test_admin_note__200_updates_note_and_sets_headers(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    sess = _mk_session(org.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    author = await _mk_user(db_session, "ok@example.com", "OK")
    last = datetime.now(timezone.utc).replace(microsecond=0)
    fb = LiveSessionFeedback(
        session_id=sess.id, user_id=author.id, rating=5, comments="ok", created_at=last
    )
    _set_if_has(fb, updated_at=last)
    db_session.add(fb); await db_session.commit(); await db_session.refresh(fb)

    # client thinks it's newer -> precondition passes
    client_dt = last + timedelta(seconds=5)
    hdr = format_datetime(client_dt.replace(tzinfo=timezone.utc))
    note = " This should be trimmed & stored.  "

    r = await async_client.put(
        ADMIN_NOTE(fb.id),
        headers={**headers, "If-Unmodified-Since": hdr},
        json={"note": note},
    )
    assert r.status_code == 200

    # headers present (best-effort)
    assert "Last-Modified" in r.headers
    assert "ETag" in r.headers

    # verify persisted value
    saved = await db_session.get(LiveSessionFeedback, fb.id)
    assert (saved.admin_note or "").startswith("This should be trimmed")
    assert len(saved.admin_note) > 0


@pytest.mark.anyio
async def test_admin_note__422_when_empty_after_trim(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    sess = _mk_session(org.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    author = await _mk_user(db_session, "empty@example.com", "E1")
    fb = LiveSessionFeedback(
        session_id=sess.id, user_id=author.id, rating=3, comments="e", created_at=datetime.now(timezone.utc)
    )
    db_session.add(fb); await db_session.commit(); await db_session.refresh(fb)

    r = await async_client.put(ADMIN_NOTE(fb.id), headers=headers, json={"note": "   "})
    assert r.status_code == 422


@pytest.mark.anyio
async def test_admin_note__409_when_row_locked_elsewhere(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    """
    Route uses FOR UPDATE NOWAIT; if another tx holds a lock, expect 409.
    We lock the row using a separate AsyncSession + open transaction.
    After releasing the lock, the update should succeed (200).
    """
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Create session + feedback within this org
    sess = _mk_session(org.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    author = await _mk_user(db_session, "lock@example.com", "L1")
    fb = LiveSessionFeedback(
        session_id=sess.id, user_id=author.id, rating=4, comments="lock", created_at=datetime.now(timezone.utc)
    )
    db_session.add(fb); await db_session.commit(); await db_session.refresh(fb)

    # IMPORTANT: cache IDs BEFORE doing anything that could expire the instance
    fid_uuid = fb.id          # UUID for DB filters
    fid = str(fid_uuid)       # string for URL

    # Use a separate session (same engine) to hold a row lock
    SessionLocal = async_sessionmaker(bind=db_session.bind, expire_on_commit=False)
    locker = SessionLocal()
    await locker.begin()  # keep tx open to hold the lock
    try:
        # Lock only the base table row (no eager outer joins)
        await locker.execute(
            select(LiveSessionFeedback)
            .options(noload(LiveSessionFeedback.session), noload(LiveSessionFeedback.user))
            .where(LiveSessionFeedback.id == fid_uuid)
            .with_for_update(of=LiveSessionFeedback, nowait=False)
        )

        # While locked, the API should fail to lock (NOWAIT) -> 409
        r_locked = await async_client.put(ADMIN_NOTE(fid), headers=headers, json={"note": "will conflict"})
        assert r_locked.status_code == 409, r_locked.text
    finally:
        # Release the lock
        await locker.rollback()
        await locker.close()

    # After releasing the lock, update should succeed
    r_after = await async_client.put(ADMIN_NOTE(fid), headers=headers, json={"note": "ok after unlock"})
    assert r_after.status_code == 200, r_after.text
    body = r_after.json()

    # accept both spellings
    note_key = "admin_note" if "admin_note" in body else "admin_notes"
    assert body[note_key] == "ok after unlock"
