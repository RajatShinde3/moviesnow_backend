# tests/test_live/test_bulk_purge_access_logs.py

import builtins
import pytest
from httpx import AsyncClient
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.live_sessions import LiveSession
from app.db.models.session_access_log import SessionAccessLog
from app.schemas.enums import OrgRole

BASE = "/api/v1/course/live/security"  # your security router prefix


# ---------- helpers ----------

def _utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0)

async def _mk_session(
    db: AsyncSession,
    *,
    org_id: UUID,
    title: str = "Session",
    start: datetime | None = None,
    end: datetime | None = None,
    creator_id: UUID | None = None,
) -> LiveSession:
    """Create a LiveSession with the minimum fill-ins your schema may require,
    being careful with optional creator/instructor fields and time fields.
    """
    now = _utcnow()
    st = start or now
    et = end or now + timedelta(hours=1)

    data = dict(title=title, organization_id=org_id)

    # Handle various possible time column names
    for attr in ("start_time", "scheduled_at", "starts_at", "start_at"):
        if hasattr(LiveSession, attr):
            data[attr] = st
            break
    for attr in ("end_time", "ends_at"):
        if hasattr(LiveSession, attr):
            data[attr] = et
            break

    # Soft delete flag if present
    if hasattr(LiveSession, "is_deleted"):
        data["is_deleted"] = False

    # If your model has a creator/instructor FK, only set it when we have a real user id.
    if creator_id:
        for attr in ("instructor_id", "created_by", "owner_user_id", "creator_user_id"):
            if hasattr(LiveSession, attr):
                data[attr] = creator_id
                break

    s = LiveSession(**data)
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


async def _add_log(
    db: AsyncSession,
    *,
    org_id: UUID,
    session_id: UUID,
    user_id: UUID | None = None,
    result: str = "ALLOWED",
    success: bool = True,
    ip: str = "203.0.113.5",
    accessed_at: datetime | None = None,
    is_deleted: bool | None = None,
    deleted_at: datetime | None = None,
    reason: str = "ok",
    token_jti: str | None = None,
    user_agent: str = "pytest",
) -> SessionAccessLog:
    row = SessionAccessLog(
        id=uuid4(),
        org_id=org_id,
        session_id=session_id,
        user_id=user_id,
        accessed_at=accessed_at or _utcnow(),
        ip_address=ip,
        user_agent=user_agent,
        token_jti=token_jti or str(uuid4()),
        success=success,
        reason=reason,
        fingerprint=None,
        result=result,  # e.g. 'ALLOWED'/'BLOCKED' etc. (works with your enum)
    )
    # Optional soft-delete columns if present
    if hasattr(SessionAccessLog, "is_deleted") and is_deleted is not None:
        setattr(row, "is_deleted", bool(is_deleted))
    if hasattr(SessionAccessLog, "deleted_at") and deleted_at is not None:
        setattr(row, "deleted_at", deleted_at)

    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


async def _get_log(db: AsyncSession, log_id: UUID) -> SessionAccessLog | None:
    return (await db.execute(
        select(SessionAccessLog).where(SessionAccessLog.id == log_id)
    )).scalars().first()


# ---------- tests ----------

@pytest.mark.anyio
async def test_bulk_purge__400_empty_ids(async_client: AsyncClient, org_user_with_token):
    actor, headers, _org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    r = await async_client.post(f"{BASE}/access-log/bulk-purge", headers=headers, json={"log_ids": []})
    assert r.status_code == 400
    assert "log_ids" in r.text.lower()


@pytest.mark.anyio
async def test_bulk_purge__404_none_found(async_client: AsyncClient, org_user_with_token):
    actor, headers, _org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    ids = [str(uuid4()), str(uuid4())]
    r = await async_client.post(f"{BASE}/access-log/bulk-purge", headers=headers, json={"log_ids": ids})
    assert r.status_code == 404
    assert "no matching logs" in r.text.lower()


@pytest.mark.anyio
async def test_bulk_purge__200_default_only_soft_deleted(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id, creator_id=actor.id)

    # soft-deleted (eligible)
    old = _utcnow() - timedelta(days=60)
    log_deleted = await _add_log(
        db_session, org_id=org.id, session_id=sess.id,
        is_deleted=True, deleted_at=old
    )
    # active (not eligible by default)
    log_active = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=False, deleted_at=None)

    r = await async_client.post(
        f"{BASE}/access-log/bulk-purge",
        headers=headers,
        json={"log_ids": [str(log_deleted.id), str(log_active.id)]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["force"] is False
    assert str(log_deleted.id) in body["purged"]
    assert str(log_active.id) in body["skipped"]
    assert body["missing"] == []

    # DB: deleted row is gone, active row remains
    assert await _get_log(db_session, log_deleted.id) is None
    assert await _get_log(db_session, log_active.id) is not None


@pytest.mark.anyio
async def test_bulk_purge__200_force_deletes_even_active(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id, creator_id=actor.id)

    log_a = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=False)
    log_b = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=True, deleted_at=_utcnow())

    r = await async_client.post(
        f"{BASE}/access-log/bulk-purge",
        headers=headers,
        json={"log_ids": [str(log_a.id), str(log_b.id)], "force": True},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["force"] is True
    assert set(body["purged"]) == {str(log_a.id), str(log_b.id)}
    assert body["skipped"] == []  # nothing skipped when forcing
    assert body["missing"] == []

    # DB: both gone
    assert await _get_log(db_session, log_a.id) is None
    assert await _get_log(db_session, log_b.id) is None


@pytest.mark.anyio
async def test_bulk_purge__200_mixed_found_and_missing(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id, creator_id=actor.id)

    # one deleted, one missing
    log_deleted = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=True, deleted_at=_utcnow())
    missing_id = str(uuid4())

    r = await async_client.post(
        f"{BASE}/access-log/bulk-purge",
        headers=headers,
        json={"log_ids": [str(log_deleted.id), missing_id]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert str(log_deleted.id) in body["purged"]
    assert missing_id in body["missing"]
    assert await _get_log(db_session, log_deleted.id) is None


@pytest.mark.anyio
async def test_bulk_purge__403_non_admin_forbidden(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    # Low-privilege member; stub require_org_admin to raise 403 explicitly.
    member, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    import app.api.v1.course.live.security as sec
    from fastapi import HTTPException

    def deny(*_a, **_k):
        raise HTTPException(status_code=403, detail="Forbidden")

    monkeypatch.setattr(sec, "require_org_admin", deny, raising=True)

    r = await async_client.post(f"{BASE}/access-log/bulk-purge", headers=headers, json={"log_ids": [str(uuid4())]})
    assert r.status_code == 403


@pytest.mark.anyio
async def test_bulk_purge__501_when_soft_delete_not_supported_and_not_force(
    async_client: AsyncClient, org_user_with_token, monkeypatch
):
    actor, headers, _org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)

    # Fake hasattr(SessionAccessLog, "is_deleted") -> False
    original_hasattr = builtins.hasattr

    def fake_hasattr(obj, name):
        if obj is SessionAccessLog and name == "is_deleted":
            return False
        return original_hasattr(obj, name)

    import app.api.v1.course.live.security as sec
    monkeypatch.setattr(builtins, "hasattr", fake_hasattr, raising=True)

    r = await async_client.post(
        f"{BASE}/access-log/bulk-purge",
        headers=headers,
        json={"log_ids": [str(uuid4())], "force": False},
    )
    assert r.status_code == 501


@pytest.mark.anyio
async def test_bulk_purge__200_audit_failure_non_blocking(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    sess = await _mk_session(db_session, org_id=org.id, creator_id=actor.id)
    log_deleted = await _add_log(db_session, org_id=org.id, session_id=sess.id, is_deleted=True, deleted_at=_utcnow())

    import app.api.v1.course.live.security as sec

    async def boom(**kwargs):
        raise RuntimeError("audit down")

    monkeypatch.setattr(sec, "log_org_event", boom, raising=True)

    r = await async_client.post(
        f"{BASE}/access-log/bulk-purge",
        headers=headers,
        json={"log_ids": [str(log_deleted.id)]},
    )
    assert r.status_code == 200, r.text
    assert await _get_log(db_session, log_deleted.id) is None


@pytest.mark.anyio
async def test_bulk_purge__400_too_many_ids(async_client: AsyncClient, org_user_with_token):
    actor, headers, _org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    too_many = [str(uuid4()) for _ in range(5001)]
    r = await async_client.post(f"{BASE}/access-log/bulk-purge", headers=headers, json={"log_ids": too_many})
    assert r.status_code == 400
    assert "too many" in r.text.lower()
