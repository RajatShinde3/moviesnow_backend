# tests/test_admin/test_assets/test_create_trailer.py

import uuid
import pytest
from sqlalchemy import select

from app.schemas.enums import TitleType, MediaAssetKind
from app.db.models.title import Title
from app.db.models.media_asset import MediaAsset

BASE_TITLES = "/api/v1/admin/titles"


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


# ────────────────────────────────────────────────────────────────────────────
# Test scaffolding (auth/mfa/audit/S3/redis)
# ────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _mock_admin_mfa(monkeypatch):
    # Bypass real admin/MFA checks so tests focus on route behavior.
    import app.dependencies.admin as admin_deps
    async def _noop(*args, **kwargs): return None
    monkeypatch.setattr(admin_deps, "ensure_admin", _noop)
    monkeypatch.setattr(admin_deps, "ensure_mfa", _noop)


@pytest.fixture(autouse=True)
async def _override_current_user(app):
    # Keep dependencies satisfied without touching real auth state.
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
    # Avoid FK violations into users table in tests and keep path non-blocking.
    import app.services.audit_log_service as audit_mod

    async def _noop(*args, **kwargs):
        return None

    monkeypatch.setattr(audit_mod, "log_audit_event", _noop)


@pytest.fixture(autouse=True)
def _fake_s3(monkeypatch):
    """
    Replace the trailer module's _ensure_s3() with a fake whose presigned URL
    is deterministic so we can assert on it.
    """
    import app.api.v1.routers.admin.assets.trailers as trailers_mod

    class _FakeS3:
        def presigned_put(self, key, content_type: str, public: bool = False):
            # Enough shape to assert correct key + content_type + privacy.
            return f"https://example.test/upload?key={key}&ct={content_type}&public={str(public).lower()}"

    def _ensure_s3():
        return _FakeS3()

    monkeypatch.setattr(trailers_mod, "_ensure_s3", _ensure_s3)


@pytest.fixture
def _idempotency_memstore(monkeypatch):
    """
    Optional: in-memory idempotency store for tests that set Idempotency-Key.
    Only patched for tests that need it (not autouse to keep scope tight).
    """
    import app.api.v1.routers.admin.assets.trailers as trailers_mod
    store = {}

    class _FakeRedis:
        async def idempotency_get(self, key: str):
            return store.get(key)

        async def idempotency_set(self, key: str, value, ttl_seconds: int = 600):
            store[key] = value

        # Lock not needed for create, but keep a minimal stub around.
        class _DummyLock:
            async def __aenter__(self): return None
            async def __aexit__(self, exc_type, exc, tb): return False
        def lock(self, *args, **kwargs):  # pragma: no cover
            return self._DummyLock()

    fake = _FakeRedis()
    monkeypatch.setattr(trailers_mod, "redis_wrapper", fake)
    return store


# ────────────────────────────────────────────────────────────────────────────
# Tests
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_create_trailer_success_with_language_and_label(async_client, db_session):
    t = await _mk_title(db_session)

    payload = {
        "content_type": "video/mp4",
        "language": "en-US",
        "is_primary": True,
        "label": "Teaser",
    }
    r = await async_client.post(f"{BASE_TITLES}/{t.id}/trailers", json=payload)
    assert r.status_code == 200, r.text

    body = r.json()
    assert set(body.keys()) == {"asset_id", "upload_url", "storage_key"}
    asset_id = uuid.UUID(body["asset_id"])
    skey = body["storage_key"]

    # presigned URL shape (from fake S3)
    assert "upload?key=" in body["upload_url"]
    assert f"key={skey}" in body["upload_url"]
    assert "ct=video/mp4" in body["upload_url"]
    assert "public=false" in body["upload_url"]

    # Row exists and has expected fields
    row = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one()
    assert row.kind == MediaAssetKind.TRAILER
    assert (getattr(row, "mime_type", None) or getattr(row, "content_type", None)) == "video/mp4"
    assert row.language == "en-US"
    assert bool(getattr(row, "is_primary", False)) is True

    # Storage key shape: video/title/{title_id}/trailers/en-US/{id}.mp4
    assert skey.startswith(f"video/title/{t.id}/trailers/en-US/")
    assert skey.endswith(f"{asset_id}.mp4")

    # Metadata label persisted
    md = (getattr(row, "metadata_json", {}) or {})
    assert md.get("label") == "Teaser"


@pytest.mark.anyio
async def test_create_trailer_success_without_language_uses_und_in_key(async_client, db_session):
    t = await _mk_title(db_session)

    r = await async_client.post(
        f"{BASE_TITLES}/{t.id}/trailers",
        json={"content_type": "video/webm", "language": None},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    asset_id = uuid.UUID(body["asset_id"])
    skey = body["storage_key"]

    # language None -> 'und' segment
    assert f"/trailers/und/" in skey
    assert skey.endswith(f"{asset_id}.webm")

    # row has language = None
    row = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one()
    assert row.language is None


@pytest.mark.anyio
async def test_create_trailer_persists_is_primary_false_by_default(async_client, db_session):
    t = await _mk_title(db_session)

    r = await async_client.post(
        f"{BASE_TITLES}/{t.id}/trailers",
        json={"content_type": "video/mpeg", "language": "fr"},
    )
    assert r.status_code == 200, r.text
    asset_id = uuid.UUID(r.json()["asset_id"])

    row = (await db_session.execute(select(MediaAsset).where(MediaAsset.id == asset_id))).scalar_one()
    assert row.kind == MediaAssetKind.TRAILER
    assert bool(getattr(row, "is_primary", False)) is False
    # content type mapping to extension
    assert r.json()["storage_key"].endswith(f"{asset_id}.mpg")


@pytest.mark.anyio
async def test_create_trailer_unsupported_content_type(async_client, db_session):
    t = await _mk_title(db_session)

    r = await async_client.post(
        f"{BASE_TITLES}/{t.id}/trailers",
        json={"content_type": "video/avi", "language": "en"},
    )
    assert r.status_code == 415
    assert "Unsupported video content" in r.text


@pytest.mark.anyio
async def test_create_trailer_invalid_language(async_client, db_session):
    t = await _mk_title(db_session)

    # "english" doesn't match the simple BCP-47-ish regex (2–3 alpha base)
    r = await async_client.post(
        f"{BASE_TITLES}/{t.id}/trailers",
        json={"content_type": "video/mp4", "language": "english"},
    )
    assert r.status_code == 400
    assert "Invalid language" in r.text


@pytest.mark.anyio
async def test_create_trailer_title_not_found(async_client):
    missing_title_id = uuid.uuid4()
    r = await async_client.post(
        f"{BASE_TITLES}/{missing_title_id}/trailers",
        json={"content_type": "video/mp4", "language": "en"},
    )
    assert r.status_code == 404
    assert "Title not found" in r.text


@pytest.mark.anyio
async def test_create_trailer_idempotency_replay_returns_same(async_client, db_session, _idempotency_memstore):
    t = await _mk_title(db_session)
    headers = {"Idempotency-Key": "same-key-123"}

    payload = {"content_type": "video/quicktime", "language": "en-GB", "label": "Main Trailer"}

    r1 = await async_client.post(f"{BASE_TITLES}/{t.id}/trailers", json=payload, headers=headers)
    assert r1.status_code == 200, r1.text
    body1 = r1.json()
    asset1 = uuid.UUID(body1["asset_id"])

    # Second request with same Idempotency-Key should replay SNAPSHOT, not create another DB row
    r2 = await async_client.post(f"{BASE_TITLES}/{t.id}/trailers", json=payload, headers=headers)
    assert r2.status_code == 200, r2.text
    body2 = r2.json()

    assert body2 == body1  # identical snapshot
    # DB has only one trailer for this title with that id
    rows = (await db_session.execute(
        select(MediaAsset).where(
            MediaAsset.title_id == t.id,
            MediaAsset.kind == MediaAssetKind.TRAILER
        )
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].id == asset1
    # storage key matches .mov for quicktime
    assert body1["storage_key"].endswith(f"{asset1}.mov")
