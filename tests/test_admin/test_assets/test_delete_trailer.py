# tests/test_admin/test_assets/test_delete_trailer.py

import uuid
import pytest
from sqlalchemy import select

from app.schemas.enums import TitleType, MediaAssetKind
from app.db.models.title import Title
from app.db.models.media_asset import MediaAsset

BASE_ADMIN = "/api/v1/admin"


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

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


async def _mk_trailer(
    db_session,
    *,
    title_id,
    language=None,
    is_primary=False,
    storage_key="",
) -> MediaAsset:
    m = MediaAsset(
        id=uuid.uuid4(),
        title_id=title_id,
        kind=MediaAssetKind.TRAILER,
        language=language,
        mime_type="video/mp4",
        is_primary=is_primary,
        metadata_json=None,
        storage_key=storage_key or None,
    )
    db_session.add(m)
    await db_session.flush()
    await db_session.commit()
    return m


# ────────────────────────────────────────────────────────────────────────────
# Test scaffolding (auth / MFA / audit / S3)
# ────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _mock_admin_mfa(monkeypatch):
    import app.dependencies.admin as admin_deps
    async def _noop(*args, **kwargs): return None
    monkeypatch.setattr(admin_deps, "ensure_admin", _noop)
    monkeypatch.setattr(admin_deps, "ensure_mfa", _noop)


@pytest.fixture(autouse=True)
async def _override_current_user(app):
    from app.core.security import get_current_user
    import uuid as _uuid
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


@pytest.fixture(autouse=True)
def _suppress_audit_logs(monkeypatch):
    import app.services.audit_log_service as audit_mod
    async def _noop(*args, **kwargs): return None
    monkeypatch.setattr(audit_mod, "log_audit_event", _noop)


def _import_assets_module():
    """Import the module where the admin asset routes live so we can patch _ensure_s3."""
    try:
        # Adjust these two lines if your routes live under a different module.
        import app.api.v1.routers.admin.assets.trailers as mod  # type: ignore
        return mod
    except Exception:
        import app.api.v1.routers.admin.assets.trailers as mod  # type: ignore
        return mod


@pytest.fixture
def s3_delete_spy(monkeypatch):
    """Patch _ensure_s3() to capture delete() calls."""
    mod = _import_assets_module()

    class _S3Spy:
        def __init__(self):
            self.deleted = []
            self.raise_on_delete = False
        def delete(self, key: str):
            if self.raise_on_delete:
                raise RuntimeError("boom")
            self.deleted.append(key)

    spy = _S3Spy()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: spy)
    return spy


# ────────────────────────────────────────────────────────────────────────────
# Tests
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_delete_trailer_success_deletes_row_and_calls_s3(async_client, db_session, s3_delete_spy):
    t = await _mk_title(db_session)
    trailer = await _mk_trailer(
        db_session,
        title_id=t.id,
        language="en",
        is_primary=True,
        storage_key=f"video/title/{t.id}/trailers/en/{uuid.uuid4()}.mp4",
    )

    r = await async_client.delete(f"{BASE_ADMIN}/trailers/{trailer.id}")
    assert r.status_code == 200, r.text
    assert r.json()["message"].lower() == "trailer deleted"

    # Row removed
    gone = (await db_session.execute(
        select(MediaAsset).where(MediaAsset.id == trailer.id)
    )).scalar_one_or_none()
    assert gone is None

    # S3 delete called once with the key
    assert s3_delete_spy.deleted == [trailer.storage_key]


@pytest.mark.anyio
async def test_delete_trailer_second_time_is_404(async_client, db_session):
    t = await _mk_title(db_session)
    trailer = await _mk_trailer(
        db_session,
        title_id=t.id,
        language="en",
        storage_key=f"video/title/{t.id}/trailers/en/{uuid.uuid4()}.mp4",
    )

    r1 = await async_client.delete(f"{BASE_ADMIN}/trailers/{trailer.id}")
    assert r1.status_code == 200, r1.text

    r2 = await async_client.delete(f"{BASE_ADMIN}/trailers/{trailer.id}")
    assert r2.status_code == 404
    assert "not found" in r2.text.lower()


@pytest.mark.anyio
async def test_delete_trailer_404_when_missing(async_client):
    r = await async_client.delete(f"{BASE_ADMIN}/trailers/{uuid.uuid4()}")
    assert r.status_code == 404
    assert "not found" in r.text.lower()


@pytest.mark.anyio
async def test_delete_trailer_s3_failure_is_swallowed(async_client, db_session, s3_delete_spy):
    t = await _mk_title(db_session)
    trailer = await _mk_trailer(
        db_session,
        title_id=t.id,
        language=None,
        storage_key=f"video/title/{t.id}/trailers/und/{uuid.uuid4()}.mp4",
    )

    # Simulate S3 delete failure
    s3_delete_spy.raise_on_delete = True

    r = await async_client.delete(f"{BASE_ADMIN}/trailers/{trailer.id}")
    assert r.status_code == 200, r.text  # DB deletion succeeded; storage failure swallowed

    # Row is gone regardless of S3 failure
    gone = (await db_session.execute(
        select(MediaAsset).where(MediaAsset.id == trailer.id)
    )).scalar_one_or_none()
    assert gone is None


@pytest.mark.anyio
async def test_delete_trailer_with_null_storage_key_skips_s3(async_client, db_session, s3_delete_spy):
    t = await _mk_title(db_session)
    trailer = await _mk_trailer(
        db_session,
        title_id=t.id,
        language="fr",
        storage_key="",  # None/empty → endpoint should not call S3.delete
    )

    r = await async_client.delete(f"{BASE_ADMIN}/trailers/{trailer.id}")
    assert r.status_code == 200, r.text

    # No S3 deletions recorded
    assert s3_delete_spy.deleted == []
