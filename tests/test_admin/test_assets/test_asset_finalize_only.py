# tests/test_admin/test_assets/test_asset_finalize_only.py
import hashlib
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.media_asset import MediaAsset

BASE = "/api/v1/admin"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _mk_asset(
    db,
    *,
    storage_key: str | None = "media/a.mp4",
    bytes_size: int | None = None,
    mime_type: str | None = None,
    checksum_sha256: str | None = None,
) -> MediaAsset:
    m = MediaAsset(
        id=str(uuid4()),
        title_id=None,
        storage_key=storage_key,
        bytes_size=bytes_size,
        mime_type=mime_type,
        checksum_sha256=checksum_sha256,
    )
    db.add(m)
    await db.commit()
    await db.refresh(m)
    return m

# -----------------------------
# Shared stubs
# -----------------------------
async def _noop(*args, **kwargs):
    return None

@pytest.fixture(autouse=True)
def _patch_admin_auth(monkeypatch):
    """
    Make `ensure_admin` and `ensure_mfa` no-ops so we don't need real auth/MFA in tests.
    (The route imports them at call time from app.dependencies.admin.)
    """
    import app.dependencies.admin as admin_mod

    monkeypatch.setattr(admin_mod, "ensure_admin", _noop, raising=True)
    monkeypatch.setattr(admin_mod, "ensure_mfa", _noop, raising=True)


@pytest.fixture(autouse=True)
async def _override_current_user(app):
    """Provide a valid UUID-bearing admin user for dependency-based auth."""
    import uuid as _uuid
    from app.core.security import get_current_user

    async def _test_user_dep():
        class _U:
            id = _uuid.uuid4()
            is_superuser = True
        return _U()

    app.dependency_overrides[get_current_user] = _test_user_dep
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_current_user, None)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_finalize_updates_size_and_content_type(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session, bytes_size=None, mime_type=None)
    asset_id = str(m.id)

    # Avoid audit FK noise during tests
    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod, "log_audit_event", lambda *a, **k: None, raising=True)

    payload = {"size_bytes": 2048, "content_type": "video/mp4"}
    r = await async_client.post(f"{BASE}/assets/{asset_id}/finalize", json=payload)
    assert r.status_code == 200, r.text
    assert r.json() == {"id": asset_id, "bytes_size": 2048, "mime_type": "video/mp4"}

    fresh = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one()
    assert fresh.bytes_size == 2048
    assert fresh.mime_type == "video/mp4"


@pytest.mark.anyio
async def test_finalize_negative_size_rejected(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session)
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod, "log_audit_event", lambda *a, **k: None, raising=True)

    # Depending on stack, Pydantic's ValidationError may bubble out of the route,
    # or FastAPI may turn it into a 422 response. Accept either.
    try:
        r = await async_client.post(f"{BASE}/assets/{asset_id}/finalize", json={"size_bytes": -1})
    except Exception as e:  # pydantic_core ValidationError in some setups
        msg = str(e)
        assert "greater_than_equal" in msg or "greater than or equal to 0" in msg
        assert "size_bytes" in msg
        return

    assert r.status_code == 422, r.text
    detail = r.json().get("detail")
    assert isinstance(detail, list) and detail, r.text
    err = detail[0]
    # Pydantic v2 error shape
    assert err.get("type") == "greater_than_equal"
    assert err.get("loc") and err["loc"][-1] == "size_bytes"



@pytest.mark.anyio
async def test_finalize_sets_checksum_if_absent(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session, checksum_sha256=None)
    asset_id = str(m.id)

    # Uppercase to ensure route lowercases it
    data = b"abc"
    sha_up = hashlib.sha256(data).hexdigest().upper()

    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod, "log_audit_event", lambda *a, **k: None, raising=True)

    r = await async_client.post(
        f"{BASE}/assets/{asset_id}/finalize",
        json={"sha256": sha_up},
    )
    assert r.status_code == 200, r.text
    # Route returns the mutated field names it stores
    assert r.json() == {"id": asset_id, "checksum_sha256": hashlib.sha256(data).hexdigest()}

    fresh = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one()
    assert fresh.checksum_sha256 == hashlib.sha256(data).hexdigest()


@pytest.mark.anyio
async def test_finalize_does_not_overwrite_checksum_without_force(async_client: AsyncClient, db_session, monkeypatch):
    existing = "a" * 64
    m = await _mk_asset(db_session, checksum_sha256=existing)
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod, "log_audit_event", lambda *a, **k: None, raising=True)

    r = await async_client.post(
        f"{BASE}/assets/{asset_id}/finalize",
        json={"sha256": "b" * 64},  # valid but should be ignored
    )
    assert r.status_code == 200
    # No fields updated → only id is returned
    assert r.json() == {"id": asset_id}

    fresh = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one()
    assert fresh.checksum_sha256 == existing


@pytest.mark.anyio
async def test_finalize_overwrites_checksum_with_force(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session, checksum_sha256="c" * 64)
    asset_id = str(m.id)

    new_sha = "d" * 64

    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod, "log_audit_event", lambda *a, **k: None, raising=True)

    r = await async_client.post(
        f"{BASE}/assets/{asset_id}/finalize",
        json={"sha256": new_sha, "force": True},
    )
    assert r.status_code == 200
    assert r.json() == {"id": asset_id, "checksum_sha256": new_sha}

    fresh = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one()
    assert fresh.checksum_sha256 == new_sha


@pytest.mark.anyio
async def test_finalize_no_updates_returns_id_only(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session, bytes_size=10, mime_type="video/old")
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod, "log_audit_event", lambda *a, **k: None, raising=True)

    r = await async_client.post(f"{BASE}/assets/{asset_id}/finalize", json={})
    assert r.status_code == 200
    assert r.json() == {"id": asset_id}

    fresh = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one()
    assert fresh.bytes_size == 10
    assert fresh.mime_type == "video/old"


@pytest.mark.anyio
async def test_finalize_invalid_sha_rejected(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session)
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod, "log_audit_event", lambda *a, **k: None, raising=True)

    r = await async_client.post(f"{BASE}/assets/{asset_id}/finalize", json={"sha256": "not-a-hash"})
    assert r.status_code == 400
    assert r.json()["detail"] == "Invalid sha256 hex"


@pytest.mark.anyio
async def test_finalize_updates_only_selected_fields(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session, bytes_size=1, mime_type="video/old")
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod, "log_audit_event", lambda *a, **k: None, raising=True)

    r = await async_client.post(f"{BASE}/assets/{asset_id}/finalize", json={"content_type": "video/new"})
    assert r.status_code == 200
    assert r.json() == {"id": asset_id, "mime_type": "video/new"}

    fresh = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one()
    assert fresh.bytes_size == 1
    assert fresh.mime_type == "video/new"


@pytest.mark.anyio
async def test_finalize_audit_log_failure_is_ignored(async_client: AsyncClient, db_session, monkeypatch):
    m = await _mk_asset(db_session, bytes_size=None, mime_type=None)
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod

    async def _boom(*a, **k):
        raise RuntimeError("audit down")
    monkeypatch.setattr(mod, "log_audit_event", _boom, raising=True)

    r = await async_client.post(f"{BASE}/assets/{asset_id}/finalize", json={"size_bytes": 42})
    assert r.status_code == 200
    assert r.json() == {"id": asset_id, "bytes_size": 42}


@pytest.mark.anyio
async def test_finalize_db_commit_failure_bubbles(async_client: AsyncClient, db_session, monkeypatch):
    # Create first, then patch commit so the route's commit fails (not the setup)
    m = await _mk_asset(db_session, bytes_size=None, mime_type=None)
    asset_id = str(m.id)

    from app.api.v1.routers.admin.assets import meta as mod
    monkeypatch.setattr(mod, "log_audit_event", lambda *a, **k: None, raising=True)

    async def _boom_commit(self):
        raise RuntimeError("commit failed")

    from sqlalchemy.ext.asyncio import AsyncSession
    monkeypatch.setattr(AsyncSession, "commit", _boom_commit, raising=True)

    # In some stacks Starlette returns a 500; in others the exception bubbles out.
    try:
        r = await async_client.post(f"{BASE}/assets/{asset_id}/finalize", json={"size_bytes": 7})
    except RuntimeError as e:
        assert "commit failed" in str(e)
        return

    # If your stack converts to HTTP, we accept 500 here.
    assert r.status_code == 500