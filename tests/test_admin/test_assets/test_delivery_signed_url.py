import pytest
from fastapi import HTTPException

BASE = "/api/v1/admin"


# -----------------------------
# Test doubles
# -----------------------------
class _FakeS3:
    def __init__(self):
        self.calls = []

    def presigned_get(self, storage_key, expires_in=None, response_content_disposition=None):
        self.calls.append(
            {
                "storage_key": storage_key,
                "expires_in": expires_in,
                "disposition": response_content_disposition,
            }
        )
        # return a deterministic URL we can assert against
        return f"https://cdn.example.test/{storage_key}?exp={expires_in}"


async def _noop(*args, **kwargs):
    return None


# -----------------------------
# Fixtures
# -----------------------------
@pytest.fixture(autouse=True)
def _patch_admin_auth(monkeypatch):
    """
    Make ensure_admin / ensure_mfa no-ops by default so tests don't need real auth.
    Individual tests can override to simulate auth failures.
    """
    import app.dependencies.admin as admin_mod

    monkeypatch.setattr(admin_mod, "ensure_admin", _noop, raising=True)
    monkeypatch.setattr(admin_mod, "ensure_mfa", _noop, raising=True)


@pytest.fixture(autouse=True)
async def _override_current_user(app):
    """Provide an admin-ish user object with an id for the dependency."""
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


@pytest.fixture
def _fake_s3():
    return _FakeS3()


@pytest.fixture
def _patch_s3(monkeypatch, _fake_s3):
    """Patch the module's _ensure_s3() to return our fake S3 client."""
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    monkeypatch.setattr(mod, "_ensure_s3", lambda: _fake_s3, raising=True)
    return _fake_s3


# -----------------------------
# Tests
# -----------------------------
@pytest.mark.anyio
async def test_signed_url_success_no_attachment(async_client, _patch_s3):
    payload = {
        "storage_key": "media/posters/abc.jpg",
        "expires_in": 600,
        # no attachment_filename
    }
    r = await async_client.post(f"{BASE}/delivery/signed-url", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "url" in body
    assert body["url"] == "https://cdn.example.test/media/posters/abc.jpg?exp=600"

    # verify S3 was invoked with expected args
    assert len(_patch_s3.calls) == 1
    call = _patch_s3.calls[0]
    assert call["storage_key"] == payload["storage_key"]
    assert call["expires_in"] == payload["expires_in"]
    assert call["disposition"] is None  # no attachment filename provided


@pytest.mark.anyio
async def test_signed_url_success_with_attachment(async_client, _patch_s3):
    payload = {
        "storage_key": "video/teaser.mp4",
        "expires_in": 900,
        "attachment_filename": "teaser.mp4",
    }
    r = await async_client.post(f"{BASE}/delivery/signed-url", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["url"] == "https://cdn.example.test/video/teaser.mp4?exp=900"

    # verify Content-Disposition is passed through correctly
    call = _patch_s3.calls[0]
    assert call["disposition"] == 'attachment; filename="teaser.mp4"'


@pytest.mark.anyio
async def test_signed_url_s3_error_returns_503(async_client, monkeypatch):
    """
    If S3 client raises S3StorageError, route should translate to 503 with the error message.
    """
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    class _S3Err(Exception):
        pass

    class _BoomS3:
        def presigned_get(self, *a, **k):
            raise _S3Err("presign failed")

    monkeypatch.setattr(mod, "S3StorageError", _S3Err, raising=True)
    monkeypatch.setattr(mod, "_ensure_s3", lambda: _BoomS3(), raising=True)

    r = await async_client.post(
        f"{BASE}/delivery/signed-url",
        json={"storage_key": "x/y/z.png", "expires_in": 120},
    )
    assert r.status_code == 503
    assert r.json()["detail"] == "presign failed"


@pytest.mark.anyio
async def test_signed_url_auth_guard_forbidden(async_client, monkeypatch, _patch_s3):
    """
    If ensure_admin denies, the route must propagate a 403.
    """
    import app.dependencies.admin as admin_mod

    async def _deny(*_, **__):
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(admin_mod, "ensure_admin", _deny, raising=True)

    r = await async_client.post(
        f"{BASE}/delivery/signed-url",
        json={"storage_key": "x.bin", "expires_in": 60},
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "forbidden"
