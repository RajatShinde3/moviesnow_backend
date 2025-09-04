# tests/test_admin/test_assets/test_delete_artwork.py

import uuid
import pytest
from sqlalchemy import select

from app.schemas.enums import ArtworkKind, TitleType
from app.db.models.title import Title
from app.db.models.artwork import Artwork

BASE_ART = "/api/v1/admin/artwork"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers (mirrors your other admin/artwork tests)
# ─────────────────────────────────────────────────────────────────────────────

async def _mk_title(db_session) -> Title:
    t = Title(
        id=uuid.uuid4(),
        type=TitleType.MOVIE,
        name=f"Title {uuid.uuid4().hex[:6]}",
        slug=f"t-{uuid.uuid4().hex[:6]}",
        is_published=True,
        release_year=2024,
    )
    db_session.add(t)
    await db_session.flush()
    await db_session.commit()
    return t


async def _mk_art(
    db_session,
    *,
    title_id,
    kind=ArtworkKind.POSTER,
    language="en",
    storage_key=True,
    is_primary=False,
    sort_order=0,
) -> Artwork:
    key = None
    if storage_key:
        key = f"art/{title_id}/{kind.name.lower()}/{language}/{uuid.uuid4()}.jpg"
    art = Artwork(
        id=uuid.uuid4(),
        title_id=title_id,
        kind=kind,
        language=language,
        content_type="image/jpeg",
        storage_key=key,
        is_primary=is_primary,
        sort_order=sort_order,
    )
    db_session.add(art)
    await db_session.flush()
    await db_session.commit()
    return art


# ─────────────────────────────────────────────────────────────────────────────
# Auth/MFA gates → no-ops; current_user override
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _mock_admin_mfa(monkeypatch):
    import app.dependencies.admin as admin_deps
    async def _noop(*args, **kwargs): return None
    monkeypatch.setattr(admin_deps, "ensure_admin", _noop)
    monkeypatch.setattr(admin_deps, "ensure_mfa", _noop)


@pytest.fixture(autouse=True)
async def _override_current_user(app):
    # Keep a stable UUID to avoid any FKs if something sneaks past the audit noop
    from app.core.security import get_current_user
    async def _test_user_dep():
        class _U:
            id = uuid.UUID("00000000-0000-0000-0000-000000000001")
            is_superuser = True
        return _U()
    app.dependency_overrides[get_current_user] = _test_user_dep
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_current_user, None)


# Mute audit log writes (avoid FK to users + extra I/O)
@pytest.fixture(autouse=True)
def _mute_audit_logging(monkeypatch):
    import app.services.audit_log_service as audit_svc
    async def _noop(*args, **kwargs): return None
    monkeypatch.setattr(audit_svc, "log_audit_event", _noop)


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_delete_success_removes_row_and_calls_s3(async_client, db_session, monkeypatch):
    t = await _mk_title(db_session)
    a = await _mk_art(db_session, title_id=t.id, storage_key=True)

    deleted_keys = []

    class _FakeS3:
        def delete(self, key):
            deleted_keys.append(key)

    # Patch the router's _ensure_s3 factory to return our fake client
    import app.api.v1.routers.admin.assets.artwork as artwork_router
    monkeypatch.setattr(artwork_router, "_ensure_s3", lambda: _FakeS3())

    r = await async_client.delete(f"{BASE_ART}/{a.id}")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["message"] == "Artwork deleted"
    # Cache hardening headers present
    assert "Cache-Control" in r.headers and "no-store" in r.headers["Cache-Control"].lower()

    # DB row is gone
    remaining = (
        await db_session.execute(select(Artwork).where(Artwork.id == a.id))
    ).scalar_one_or_none()
    assert remaining is None

    # S3 delete attempted with correct key
    assert deleted_keys == [a.storage_key]


@pytest.mark.anyio
async def test_delete_returns_404_if_missing(async_client):
    missing_id = uuid.uuid4()
    r = await async_client.delete(f"{BASE_ART}/{missing_id}")
    assert r.status_code == 404, r.text
    assert "Artwork not found" in r.text


@pytest.mark.anyio
async def test_delete_best_effort_s3_failure_is_swallowed(async_client, db_session, monkeypatch):
    t = await _mk_title(db_session)
    a = await _mk_art(db_session, title_id=t.id, storage_key=True)

    class _BoomS3:
        def delete(self, key):
            raise RuntimeError("network / permission error")

    import app.api.v1.routers.admin.assets.artwork as artwork_router
    monkeypatch.setattr(artwork_router, "_ensure_s3", lambda: _BoomS3())

    r = await async_client.delete(f"{BASE_ART}/{a.id}")
    assert r.status_code == 200, r.text
    # DB row still deleted even if storage purge failed
    remaining = (
        await db_session.execute(select(Artwork).where(Artwork.id == a.id))
    ).scalar_one_or_none()
    assert remaining is None


@pytest.mark.anyio
async def test_delete_twice_first_200_then_404(async_client, db_session, monkeypatch):
    t = await _mk_title(db_session)
    a = await _mk_art(db_session, title_id=t.id, storage_key=True)

    class _FakeS3:
        def delete(self, key): pass

    import app.api.v1.routers.admin.assets.artwork as artwork_router
    monkeypatch.setattr(artwork_router, "_ensure_s3", lambda: _FakeS3())

    r1 = await async_client.delete(f"{BASE_ART}/{a.id}")
    assert r1.status_code == 200, r1.text

    r2 = await async_client.delete(f"{BASE_ART}/{a.id}")
    assert r2.status_code == 404, r2.text
    assert "Artwork not found" in r2.text
