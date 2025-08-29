# tests/test_live/test_export_feedback_csv.py

import pytest
import csv
from io import StringIO
from uuid import uuid4
from datetime import datetime, timedelta, timezone

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.schemas.enums import OrgRole
from app.db.models.live_sessions import LiveSession
from app.db.models.live_session_feedback import LiveSessionFeedback, FeedbackType
from app.db.models.user import User

BASE = "/api/v1/course/live/feedback"


def _set_if_has(obj, **vals):
    for k, v in vals.items():
        if hasattr(obj, k):
            setattr(obj, k, v)


def _mk_session(org_id):
    now = datetime.now(timezone.utc)
    return LiveSession(
        title='Title: "Math/Lesson*1?"',  # exercise filename sanitization in header
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

def _parse_csv_bytes(b: bytes):
    text = b.decode("utf-8")
    reader = csv.reader(StringIO(text))
    rows = list(reader)
    return rows


@pytest.mark.anyio
async def test_export_feedback_csv__404_when_session_missing(async_client: AsyncClient, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    missing = uuid4()
    r = await async_client.get(f"{BASE}/{missing}/feedback/export", headers=headers)
    assert r.status_code == 404, r.text


@pytest.mark.anyio
async def test_export_feedback_csv__404_when_session_in_other_org(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, create_organization_fixture
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Create a session under a *different* org
    other_org = await create_organization_fixture()
    sess_other = _mk_session(other_org.id)
    _set_if_has(sess_other, created_by=user.id)
    db_session.add(sess_other)
    await db_session.commit()
    await db_session.refresh(sess_other)

    r = await async_client.get(f"{BASE}/{sess_other.id}/feedback/export", headers=headers)
    assert r.status_code == 404, r.text


@pytest.mark.anyio
async def test_export_feedback_csv__200_headers_rows_and_injection_safety(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Session in the same org
    sess = _mk_session(org.id)
    _set_if_has(sess, created_by=user.id)
    db_session.add(sess)
    await db_session.commit()
    await db_session.refresh(sess)

    # Two authors
    author1 = await _mk_user(db_session, "a1@example.com", full_name="@evil")  # triggers leading '@'
    author2 = await _mk_user(db_session, "a2@example.com", full_name="Normal Name")

    # Two feedback rows (different ratings & contents)
    t1 = datetime.now(timezone.utc) - timedelta(hours=3)
    t2 = datetime.now(timezone.utc) - timedelta(hours=1)

    fb1 = LiveSessionFeedback(
        session_id=sess.id,
        user_id=author1.id,
        rating=5,
        comments="=SUM(1,1)",  # triggers formula-injection guard
        tags=["engaging", "clear"],
        feedback_type=FeedbackType.TECHNICAL,
        source="web",
        admin_note="check later",
        created_at=t1,
    )
    fb2 = LiveSessionFeedback(
        session_id=sess.id,
        user_id=author2.id,
        rating=3,
        comments="Nice pace",
        tags=["slow"],
        feedback_type=FeedbackType.GENERAL,
        source="mobile",
        admin_note=None,
        created_at=t2,
    )
    db_session.add_all([fb1, fb2])
    await db_session.commit()

    r = await async_client.get(f"{BASE}/{sess.id}/feedback/export", headers=headers)
    assert r.status_code == 200, r.text
    assert r.headers.get("content-type", "").startswith("text/csv")
    disp = r.headers.get("Content-Disposition", "")
    # Header should be an attachment with .csv and RFC5987 filename*
    assert "attachment;" in disp and ".csv" in disp and "filename*=" in disp

    rows = _parse_csv_bytes(r.content)
    # header + 2 data rows
    assert len(rows) == 3
    header = rows[0]
    assert header == [
        "User ID",
        "User Name",
        "Session ID",
        "Rating",
        "Comments",
        "Submitted At (UTC)",
        "Source",
        "Admin Note",
        "Feedback Type",
        "Tags",
    ]

    data1, data2 = rows[1], rows[2]

    # Row for author1 (older first; ordered ascending by timestamp then id)
    assert data1[0] == str(author1.id)
    # user name and comments should be single-quoted due to injection protection
    assert data1[1].startswith("'@evil")
    assert data1[4].startswith("'=SUM(1,1)")
    # ISO8601 UTC timestamp
    assert data1[5] == t1.astimezone(timezone.utc).isoformat()
    assert data1[6] == "web"
    assert data1[7] == "check later"
    assert data1[8] in ("technical", "FeedbackType.TECHNICAL", "TECHNICAL")  # tolerate enum reprs
    assert data1[9] in ("engaging;clear", "clear;engaging")  # semicolon-joined, order may vary

    # Row for author2
    assert data2[0] == str(author2.id)
    assert data2[1] == "Normal Name"
    assert data2[4] == "Nice pace"
    assert data2[5] == t2.astimezone(timezone.utc).isoformat()
    assert data2[6] == "mobile"
    # admin note may be empty string
    # tags single element
    assert data2[9] == "slow"


@pytest.mark.anyio
async def test_export_feedback_csv__column_toggles(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = _mk_session(org.id)
    db_session.add(sess)
    await db_session.commit()
    await db_session.refresh(sess)

    # One simple row is enough to verify header shape
    u = await _mk_user(db_session, "x@example.com", full_name="X")
    db_session.add(
        LiveSessionFeedback(
            session_id=sess.id, user_id=u.id, rating=4, comments="ok", source="web", created_at=datetime.now(timezone.utc)
        )
    )
    await db_session.commit()

    # All toggles OFF -> only base 7 columns
    r = await async_client.get(
        f"{BASE}/{sess.id}/feedback/export?include_admin_notes=false&include_tags=false&include_type=false",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    rows = _parse_csv_bytes(r.content)
    assert rows and len(rows[0]) == 7
    assert rows[0] == [
        "User ID",
        "User Name",
        "Session ID",
        "Rating",
        "Comments",
        "Submitted At (UTC)",
        "Source",
    ]


@pytest.mark.anyio
async def test_export_feedback_csv__rating_filter(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = _mk_session(org.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    u1 = await _mk_user(db_session, "r1@example.com", full_name="R1")
    u2 = await _mk_user(db_session, "r2@example.com", full_name="R2")

    db_session.add_all(
        [
            LiveSessionFeedback(session_id=sess.id, user_id=u1.id, rating=5, comments="great", created_at=datetime.now(timezone.utc)),
            LiveSessionFeedback(session_id=sess.id, user_id=u2.id, rating=3, comments="meh", created_at=datetime.now(timezone.utc)),
        ]
    )
    await db_session.commit()

    r = await async_client.get(f"{BASE}/{sess.id}/feedback/export?rating=5", headers=headers)
    assert r.status_code == 200, r.text
    rows = _parse_csv_bytes(r.content)
    # header + exactly one 5-star row
    assert len(rows) == 2
    assert rows[1][0] == str(u1.id)

    # Out of range -> 422
    r_bad = await async_client.get(f"{BASE}/{sess.id}/feedback/export?rating=6", headers=headers)
    assert r_bad.status_code == 422


@pytest.mark.anyio
async def test_export_feedback_csv__timezone_window_filter_ist(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    _, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = _mk_session(org.id)
    db_session.add(sess); await db_session.commit(); await db_session.refresh(sess)

    u1 = await _mk_user(db_session, "t1@example.com", full_name="T1")
    u2 = await _mk_user(db_session, "t2@example.com", full_name="T2")

    # Choose fixed UTC times to make window deterministic
    early = datetime(2025, 1, 1, 6, 0, 0, tzinfo=timezone.utc)   # 11:30 IST
    late  = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)  # 15:30 IST

    db_session.add_all(
        [
            LiveSessionFeedback(session_id=sess.id, user_id=u1.id, rating=4, comments="early", created_at=early),
            LiveSessionFeedback(session_id=sess.id, user_id=u2.id, rating=5, comments="late", created_at=late),
        ]
    )
    await db_session.commit()

    # Start at 15:00 IST (09:30 UTC) => should include only "late" (10:00 UTC)
    start_local = "2025-01-01T15:00:00"
    r = await async_client.get(
        f"{BASE}/{sess.id}/feedback/export?start_date={start_local}&tz=Asia/Kolkata",
        headers=headers,
    )
    assert r.status_code == 200, r.text
    rows = _parse_csv_bytes(r.content)
    assert len(rows) == 2  # header + 1
    assert rows[1][4] == "late"
    # Submitted At should be UTC ISO
    assert rows[1][5] == late.astimezone(timezone.utc).isoformat()
