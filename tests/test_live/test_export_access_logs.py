# tests/test_live/test_export_access_logs.py

import io
import zipfile
import pytest
from httpx import AsyncClient
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.live_sessions import LiveSession
from app.schemas.enums import OrgRole

BASE = "/api/v1/course/live/security"


# ---------- helpers ----------

def _utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)

async def _mk_session(
    db: AsyncSession,
    *,
    org_id: UUID,
    title: str = "Exportable Session",
    start: datetime | None = None,
    end: datetime | None = None,
) -> LiveSession:
    """Create a minimal LiveSession for the org, filling whatever fields your model exposes."""
    now = _utc_now()
    st = start or now
    et = end or (st + timedelta(hours=1))

    data = dict(title=title, organization_id=org_id)
    # normalize common column names across schemas
    for attr in ("start_time", "scheduled_at", "starts_at", "start_at"):
        if hasattr(LiveSession, attr):
            data[attr] = st
            break
    for attr in ("end_time", "ends_at"):
        if hasattr(LiveSession, attr):
            data[attr] = et
            break
    if hasattr(LiveSession, "is_deleted"):
        data["is_deleted"] = False

    s = LiveSession(**data)
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


# ---------- tests ----------

@pytest.mark.anyio
async def test_export_logs__200_stream_csv(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id)

    # Make the export functions deterministic
    import app.api.v1.course.live.security as sec

    expected_csv = b"id,ip,result\n1,203.0.113.5,ALLOWED\n"
    async def fake_get_access_logs_for_export(**kwargs):
        # Any non-empty payload; content is controlled by _csv_rows below
        return [{"dummy": 1}]
    def fake_csv_rows(_rows):
        yield expected_csv

    monkeypatch.setattr(sec, "get_access_logs_for_export", fake_get_access_logs_for_export, raising=True)
    monkeypatch.setattr(sec, "_csv_rows", fake_csv_rows, raising=True)

    r = await async_client.get(f"{BASE}/sessions/{session.id}/access-log/export", headers=headers)
    assert r.status_code == 200, r.text
    assert r.headers.get("content-type", "").startswith("text/csv")
    cd = r.headers.get("content-disposition", "")
    assert ".csv" in cd
    assert r.content == expected_csv


@pytest.mark.anyio
async def test_export_logs__200_zip_csv(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id)

    import app.api.v1.course.live.security as sec

    expected_csv = b"a,b\nx,y\n"
    async def fake_get_access_logs_for_export(**kwargs):
        return [{"dummy": 1}, {"dummy": 2}]
    def fake_csv_rows(_rows):
        yield expected_csv

    monkeypatch.setattr(sec, "get_access_logs_for_export", fake_get_access_logs_for_export, raising=True)
    monkeypatch.setattr(sec, "_csv_rows", fake_csv_rows, raising=True)

    r = await async_client.get(
        f"{BASE}/sessions/{session.id}/access-log/export",
        headers=headers,
        params={"zip": True},
    )
    assert r.status_code == 200, r.text
    assert r.headers.get("content-type") == "application/zip"
    cd = r.headers.get("content-disposition", "")
    assert ".zip" in cd

    # Inspect the zip payload
    buf = io.BytesIO(r.content)
    with zipfile.ZipFile(buf, "r") as zf:
        names = zf.namelist()
        assert len(names) == 1 and names[0].endswith(".csv")
        inner = zf.read(names[0])
        assert inner == expected_csv


@pytest.mark.anyio
async def test_export_logs__email_schedules_background_and_returns_message(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id)

    import app.api.v1.course.live.security as sec
    async def fake_get_access_logs_for_export(**kwargs):
        return [{"any": "thing"}]

    # Spy on add_task to assert the correct function & args are scheduled
    calls = {}
    from starlette.background import BackgroundTasks
    orig_add_task = BackgroundTasks.add_task
    def spy_add_task(self, fn, *a, **k):
        calls["fn"] = fn
        calls["args"] = a
        calls["kwargs"] = k
        # don't actually run the task
        return None

    monkeypatch.setattr(sec, "get_access_logs_for_export", fake_get_access_logs_for_export, raising=True)
    monkeypatch.setattr(BackgroundTasks, "add_task", spy_add_task, raising=True)

    r = await async_client.get(
        f"{BASE}/sessions/{session.id}/access-log/export",
        headers=headers,
        params={"email": True, "zip": True, "preview": True},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "sent to your email" in body.get("detail", "").lower()
    # ensure send_export_email is scheduled with the proper flags
    assert calls.get("fn") is sec.send_export_email
    # args: (current_user, session_id, logs, zip, preview)
    assert isinstance(calls["args"][1], UUID)
    assert calls["args"][1] == session.id
    assert isinstance(calls["args"][2], list) and calls["args"][2]  # logs non-empty
    assert calls["args"][3] is True   # zip
    assert calls["args"][4] is True   # preview

    # restore add_task to avoid bleedover (pytest monkeypatch auto-restores too)
    BackgroundTasks.add_task = orig_add_task


@pytest.mark.anyio
async def test_export_logs__204_no_content_when_no_logs(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id)

    import app.api.v1.course.live.security as sec
    async def fake_get_access_logs_for_export(**kwargs):
        return []
    monkeypatch.setattr(sec, "get_access_logs_for_export", fake_get_access_logs_for_export, raising=True)

    r = await async_client.get(f"{BASE}/sessions/{session.id}/access-log/export", headers=headers)
    assert r.status_code == 204


@pytest.mark.anyio
async def test_export_logs__400_invalid_date_range(async_client: AsyncClient, db_session: AsyncSession, org_user_with_token):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id)

    start = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    end = datetime.now(timezone.utc).isoformat()
    r = await async_client.get(
        f"{BASE}/sessions/{session.id}/access-log/export",
        headers=headers,
        params={"start_date": start, "end_date": end},
    )
    assert r.status_code == 400
    assert "start_date" in r.text.lower()


@pytest.mark.anyio
async def test_export_logs__404_session_not_found(async_client: AsyncClient, org_user_with_token):
    _, headers, _ = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    missing = uuid4()
    r = await async_client.get(f"{BASE}/sessions/{missing}/access-log/export", headers=headers)
    assert r.status_code == 404
    assert "not found" in r.text.lower()


@pytest.mark.anyio
async def test_export_logs__403_requires_admin_or_creator(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    # caller has low privilege
    member, headers, org = await org_user_with_token(role=OrgRole.INTERN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id)

    # force 403 via helper
    import app.api.v1.course.live.security as sec
    from fastapi import HTTPException
    def deny(*_a, **_k):
        raise HTTPException(status_code=403, detail="Forbidden")
    monkeypatch.setattr(sec, "require_admin_or_creator_from_session", deny, raising=True)

    r = await async_client.get(f"{BASE}/sessions/{session.id}/access-log/export", headers=headers)
    assert r.status_code == 403


@pytest.mark.anyio
async def test_export_logs__preview_sets_limit_100_for_fetch(
    async_client: AsyncClient, db_session: AsyncSession, org_user_with_token, monkeypatch
):
    actor, headers, org = await org_user_with_token(role=OrgRole.ADMIN, set_active_org=True)
    session = await _mk_session(db_session, org_id=org.id)

    import app.api.v1.course.live.security as sec

    seen = {}
    async def fake_get_access_logs_for_export(**kwargs):
        seen.update(kwargs)
        # must return something so route streams
        return [{"rows": "preview"}]

    def fake_csv_rows(_rows):
        yield b"ok\n"

    monkeypatch.setattr(sec, "get_access_logs_for_export", fake_get_access_logs_for_export, raising=True)
    monkeypatch.setattr(sec, "_csv_rows", fake_csv_rows, raising=True)

    r = await async_client.get(
        f"{BASE}/sessions/{session.id}/access-log/export",
        headers=headers,
        params={"preview": True, "result": "blocked"},  # lowercase enum value
    )
    assert r.status_code == 200, r.text

    # ensure preview enforced limit=100 and result parsed/forwarded
    assert seen.get("limit") == 100
    res = seen.get("result")
    # AccessResult enum instance → compare by value ("blocked")
    assert getattr(res, "value", res) == "blocked"
