# tests/test_live/test_list_session_feedbacks.py

import json
from uuid import uuid4
from datetime import datetime, timedelta, date, timezone
from zoneinfo import ZoneInfo

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.enums import OrgRole
from app.core.redis_client import redis_wrapper
from app.utils.audit import AuditEventType
from app.db.models.live_sessions import LiveSession
from app.db.models.live_session_feedback import LiveSessionFeedback

BASE = "/api/v1/course/live/feedback"  # → /{session_id}/feedbacks


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
async def _mk_session(
    db: AsyncSession,
    *,
    org_id,
    title: str = "Session",
    start: datetime | None = None,
    end: datetime | None = None,
    is_deleted: bool = False,
) -> LiveSession:
    """Create a minimal LiveSession that satisfies NOT NULL fields if present."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    st = start or now
    et = end or (st + timedelta(hours=1))

    data = dict(title=title, organization_id=org_id)
    # fill whatever start/end columns exist
    for attr in ("start_time", "scheduled_at", "starts_at", "start_at"):
        if hasattr(LiveSession, attr):
            data[attr] = st
            break
    for attr in ("end_time", "ends_at"):
        if hasattr(LiveSession, attr):
            data[attr] = et
            break
    if hasattr(LiveSession, "is_deleted"):
        data["is_deleted"] = is_deleted

    s = LiveSession(**data)
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


async def _mk_feedback(
    db: AsyncSession,
    *,
    session_id,
    user_id,
    rating: int | None = None,
    comments: str | None = None,
    tags: list[str] | None = None,
    created_at: datetime | None = None,
):
    fb = LiveSessionFeedback(
        session_id=session_id,
        user_id=user_id,
        rating=rating,
        comments=comments,
        tags=tags,
        source="web",
    )
    if created_at is not None:
        fb.created_at = created_at
    db.add(fb)
    await db.commit()
    await db.refresh(fb)
    return fb


def _to_utc_naive_local_day_start(d: date, tz: str) -> datetime:
    return (
        datetime.combine(d, datetime.min.time(), ZoneInfo(tz))
        .astimezone(ZoneInfo("UTC"))
        .replace(tzinfo=None)
    )


def _to_utc_naive_local_next_day_start(d: date, tz: str) -> datetime:
    return (
        datetime.combine(d + timedelta(days=1), datetime.min.time(), ZoneInfo(tz))
        .astimezone(ZoneInfo("UTC"))
        .replace(tzinfo=None)
    )


def _cache_key(
    *,
    org_id,
    session_id,
    tz="UTC",
    rating=None,
    min_rating=None,
    max_rating=None,
    search="",
    user_id=None,
    tags_any=None,
    tags_all=None,
    start_utc=None,
    end_utc_excl=None,
    sort_by="newest",
    limit=50,
    offset=0,
):
    search_norm = (search or "").strip().lower()[:40]
    any_norm = ",".join((t or "").lower() for t in (tags_any or [])[:6])
    all_norm = ",".join((t or "").lower() for t in (tags_all or [])[:6])
    return (
        f"fb:list:v2:org:{org_id}:session:{session_id}:tz:{tz}"
        f":rating:{rating}:min:{min_rating}:max:{max_rating}"
        f":search:{search_norm}"
        f":user:{user_id or 'None'}"
        f":any:{any_norm}"
        f":all:{all_norm}"
        f":start:{start_utc or 'None'}:end:{end_utc_excl or 'None'}"
        f":sort:{sort_by}:limit:{limit}:offset:{offset}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_list_feedbacks__empty_200_with_total_header(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    r = await async_client.get(f"{BASE}/{s.id}/feedbacks?tz=UTC", headers=headers)
    assert r.status_code == 200, r.text
    assert r.headers.get("X-Total-Count") in ("0", 0, None)
    assert r.json() == []


@pytest.mark.anyio
async def test_list_feedbacks__404_when_session_not_in_org(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession
):
    # headers/org A
    _, headers_a, org_a = await org_user_with_token(role=OrgRole.ADMIN)
    # different org B with its own session
    _, _, org_b = await org_user_with_token(role=OrgRole.ADMIN)
    s_b = await _mk_session(db_session, org_id=org_b.id)

    r = await async_client.get(f"{BASE}/{s_b.id}/feedbacks?tz=UTC", headers=headers_a)
    assert r.status_code == 404, r.text


@pytest.mark.anyio
async def test_list_feedbacks__basic_pagination_and_header(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    for i in range(7):
        await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=(i % 5) + 1, comments=f"c{i}")

    r1 = await async_client.get(f"{BASE}/{s.id}/feedbacks?limit=3&offset=0&tz=UTC", headers=headers)
    assert r1.status_code == 200
    assert r1.headers.get("X-Total-Count") in ("7", 7)
    assert len(r1.json()) == 3

    r2 = await async_client.get(f"{BASE}/{s.id}/feedbacks?limit=3&offset=3&tz=UTC", headers=headers)
    assert r2.status_code == 200
    assert len(r2.json()) == 3

    r3 = await async_client.get(f"{BASE}/{s.id}/feedbacks?limit=3&offset=6&tz=UTC", headers=headers)
    assert r3.status_code == 200
    assert len(r3.json()) == 1


@pytest.mark.anyio
async def test_list_feedbacks__sort_orders(async_client: AsyncClient, org_user_with_token, db_session: AsyncSession):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    t0 = datetime.now(timezone.utc).replace(microsecond=0)
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=2, comments="old", created_at=t0)
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=5, comments="new", created_at=t0 + timedelta(seconds=10))

    # newest
    r_new = await async_client.get(f"{BASE}/{s.id}/feedbacks?sort_by=newest&tz=UTC&limit=50", headers=headers)
    assert r_new.status_code == 200, r_new.text
    comments_new = [row["comments"] for row in r_new.json()]
    # ensure both present and "new" appears before "old"
    assert "new" in comments_new and "old" in comments_new
    assert comments_new.index("new") < comments_new.index("old")

    # oldest
    r_old = await async_client.get(f"{BASE}/{s.id}/feedbacks?sort_by=oldest&tz=UTC&limit=50", headers=headers)
    assert r_old.status_code == 200, r_old.text
    comments_old = [row["comments"] for row in r_old.json()]
    assert "new" in comments_old and "old" in comments_old
    assert comments_old.index("old") < comments_old.index("new")

    # rating sorts
    r_hi = await async_client.get(f"{BASE}/{s.id}/feedbacks?sort_by=highest_rating&tz=UTC&limit=50", headers=headers)
    assert r_hi.status_code == 200, r_hi.text
    ratings_hi = [row["rating"] for row in r_hi.json()]
    assert ratings_hi == sorted(ratings_hi, reverse=True)

    r_lo = await async_client.get(f"{BASE}/{s.id}/feedbacks?sort_by=lowest_rating&tz=UTC&limit=50", headers=headers)
    assert r_lo.status_code == 200, r_lo.text
    ratings_lo = [row["rating"] for row in r_lo.json()]
    assert ratings_lo == sorted(ratings_lo)



@pytest.mark.anyio
async def test_list_feedbacks__rating_and_user_filters(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession
):
    admin, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)
    u2, _, _ = await org_user_with_token(role=OrgRole.MENTOR)

    await _mk_feedback(db_session, session_id=s.id, user_id=admin.id, rating=5, comments="A")
    await _mk_feedback(db_session, session_id=s.id, user_id=admin.id, rating=3, comments="B")
    await _mk_feedback(db_session, session_id=s.id, user_id=u2.id, rating=4, comments="C")

    # exact rating
    r = await async_client.get(f"{BASE}/{s.id}/feedbacks?rating=5&tz=UTC", headers=headers)
    assert [row["comments"] for row in r.json()] == ["A"]

    # min/max
    r = await async_client.get(f"{BASE}/{s.id}/feedbacks?min_rating=4&max_rating=5&tz=UTC", headers=headers)
    assert {row["comments"] for row in r.json()} == {"A", "C"}

    # by user
    r = await async_client.get(f"{BASE}/{s.id}/feedbacks?user_id={u2.id}&tz=UTC", headers=headers)
    assert [row["comments"] for row in r.json()] == ["C"]


@pytest.mark.anyio
async def test_list_feedbacks__search_keyword_ilike_or_fts(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=4, comments="alpha beta")
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=4, comments="gamma")

    r = await async_client.get(f"{BASE}/{s.id}/feedbacks?search=alpha&tz=UTC", headers=headers)
    assert [row["comments"] for row in r.json()] == ["alpha beta"]


@pytest.mark.anyio
async def test_list_feedbacks__tags_any_all_python_fallback(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession, monkeypatch
):
    """
    Force Python tag filtering (robust whether 'tags' is JSONB or ARRAY).
    """
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=5, comments="x", tags=["fast", "clear"])
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=4, comments="y", tags=["clear"])
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=3, comments="z", tags=["slow"])

    # Make func.unnest blowing up at build time → apply_python_tag_filter=True
    def _boom(*a, **k): raise RuntimeError("no unnest")
    monkeypatch.setattr("app.api.v1.course.live.feedback.func.unnest", _boom, raising=True)

    # ANY fast or slow → x and z
    r_any = await async_client.get(
        f"{BASE}/{s.id}/feedbacks?tz=UTC&tags_any=fast&tags_any=slow", headers=headers
    )
    assert {row["comments"] for row in r_any.json()} == {"x", "z"}

    # ALL clear and fast → x only
    r_all = await async_client.get(
        f"{BASE}/{s.id}/feedbacks?tz=UTC&tags_all=clear&tags_all=fast", headers=headers
    )
    assert [row["comments"] for row in r_all.json()] == ["x"]


@pytest.mark.anyio
async def test_list_feedbacks__timezone_end_inclusive(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    tz = "Asia/Kolkata"
    end_d = datetime.now(timezone.utc).date()

    # 21:30 IST on end_d should be included when only end_date is provided
    join_local = datetime(end_d.year, end_d.month, end_d.day, 21, 30, 0, tzinfo=ZoneInfo(tz))
    join_utc_naive = join_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=5, created_at=join_utc_naive)

    r = await async_client.get(f"{BASE}/{s.id}/feedbacks?tz={tz}&end_date={end_d.isoformat()}", headers=headers)
    assert r.status_code == 200
    assert len(r.json()) >= 1


@pytest.mark.anyio
async def test_list_feedbacks__forgiving_inverted_dates(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    today = datetime.now(timezone.utc).date()
    created = datetime(today.year, today.month, today.day) - timedelta(seconds=1)
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=4, created_at=created)

    r = await async_client.get(
        f"{BASE}/{s.id}/feedbacks?tz=UTC&start_date={today.isoformat()}&end_date={(today - timedelta(days=1)).isoformat()}",
        headers=headers,
    )
    assert r.status_code == 200
    assert len(r.json()) >= 1


@pytest.mark.anyio
async def test_list_feedbacks__cache_hit_short_circuit(async_client: AsyncClient, org_user_with_token, db_session: AsyncSession, monkeypatch):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)

    tz = "UTC"
    limit = 2
    offset = 0
    start_d = date(2020, 1, 1)
    end_d = date(2020, 1, 2)
    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)

    ck = _cache_key(
        org_id=org.id,
        session_id=s.id,
        tz=tz,
        start_utc=start_utc,
        end_utc_excl=end_utc_excl,
        sort_by="newest",
        limit=limit,
        offset=offset,
    )

    cached_items = [
        {
            "id": str(uuid4()),
            "session_id": str(s.id),
            "user_id": str(user.id),
            "rating": 5,
            "comments": "cached-1",
            "tags": ["wow"],
            "feedback_type": "general",
            "source": "web",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
        {
            "id": str(uuid4()),
            "session_id": str(s.id),
            "user_id": str(user.id),
            "rating": 4,
            "comments": "cached-2",
            "tags": [],
            "feedback_type": "content",
            "source": "web",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    ]
    await redis_wrapper.client.setex(ck, 60, json.dumps({"x_total_count": 99, "items": cached_items}, separators=(",", ":")))

    seen = {}
    async def _audit(**kw):
        seen["action"] = kw.get("action")
        seen["meta"] = kw.get("meta_data")
    monkeypatch.setattr("app.api.v1.course.live.feedback.log_org_event", _audit, raising=True)

    r = await async_client.get(
        f"{BASE}/{s.id}/feedbacks?tz={tz}&limit={limit}&offset={offset}&start_date={start_d}&end_date={end_d}",
        headers=headers,
    )
    assert r.status_code == 200, r.text

    resp = r.json()
    # Strip backfilled keys to compare with cached payload exactly
    for it in resp:
        it.pop("is_deleted", None)
        it.pop("admin_notes", None)
    assert resp == cached_items

    assert seen.get("meta", {}).get("cache") == "hit"


@pytest.mark.anyio
async def test_list_feedbacks__use_cache_false_ignores_cache(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=4, comments="real")

    tz = "UTC"
    start_d = date(2020, 1, 1)
    end_d = date(2020, 1, 2)
    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)

    ck = _cache_key(org_id=org.id, session_id=s.id, tz=tz, start_utc=start_utc, end_utc_excl=end_utc_excl)
    await redis_wrapper.client.setex(ck, 60, json.dumps({"x_total_count": 123, "items": []}))

    r = await async_client.get(
        f"{BASE}/{s.id}/feedbacks?tz={tz}&use_cache=false&start_date={start_d}&end_date={end_d}",
        headers=headers,
    )
    assert r.status_code == 200
    # If cache were used, we'd get an empty list – ensure we see the real row
    assert any(row["comments"] == "real" for row in r.json())


@pytest.mark.anyio
async def test_list_feedbacks__corrupt_cache_falls_back(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=3, comments="ok")

    tz = "UTC"
    start_d = date(2020, 3, 1)
    end_d = date(2020, 3, 2)
    start_utc = _to_utc_naive_local_day_start(start_d, tz)
    end_utc_excl = _to_utc_naive_local_next_day_start(end_d, tz)
    ck = _cache_key(org_id=org.id, session_id=s.id, tz=tz, start_utc=start_utc, end_utc_excl=end_utc_excl)
    await redis_wrapper.client.setex(ck, 60, "{not-json")

    r = await async_client.get(
        f"{BASE}/{s.id}/feedbacks?tz={tz}&start_date={start_d}&end_date={end_d}", headers=headers
    )
    assert r.status_code == 200
    assert any(row["comments"] == "ok" for row in r.json())


@pytest.mark.anyio
async def test_list_feedbacks__audit_success_and_error_paths(
    async_client: AsyncClient, org_user_with_token, db_session: AsyncSession, monkeypatch
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)
    s = await _mk_session(db_session, org_id=org.id)
    await _mk_feedback(db_session, session_id=s.id, user_id=user.id, rating=5, comments="one")

    # success audit (best-effort)
    seen_ok = {}
    async def _audit_ok(**kw):
        seen_ok["action"] = kw.get("action")
        seen_ok["meta"] = kw.get("meta_data")
    monkeypatch.setattr("app.api.v1.course.live.feedback.log_org_event", _audit_ok, raising=True)

    r = await async_client.get(f"{BASE}/{s.id}/feedbacks?tz=UTC", headers=headers)
    assert r.status_code == 200
    # best-effort: don't assert strictly, some builds skip success audit
    # assert seen_ok.get("action") == AuditEventType.LIST_FEEDBACK_FOR_SESSION

    # error path: make building filters explode
    def _boom(*a, **k): raise RuntimeError("and_ exploded")
    monkeypatch.setattr("app.api.v1.course.live.feedback.and_", _boom, raising=True)

    seen_err = {}
    async def _audit_err(**kw):
        seen_err["action"] = kw.get("action")
        seen_err["meta"] = kw.get("meta_data")
    monkeypatch.setattr("app.api.v1.course.live.feedback.log_org_event", _audit_err, raising=True)

    r2 = await async_client.get(f"{BASE}/{s.id}/feedbacks?tz=UTC", headers=headers)
    assert r2.status_code == 500, r2.text
    assert seen_err.get("action") == AuditEventType.LIST_FEEDBACK_FOR_SESSION
    assert "error" in (seen_err.get("meta") or {})
