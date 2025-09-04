import pytest

BASE = "/api/v1/admin"


# -----------------------------
# Fakes / helpers
# -----------------------------
class _FakeS3OK:
    def __init__(self, url="https://example.com/signed-manifest"):
        self.url = url
        self.calls = []

    def presigned_get(self, storage_key, expires_in, response_content_type=None):
        self.calls.append(
            {
                "storage_key": storage_key,
                "expires_in": expires_in,
                "ctype": response_content_type,
            }
        )
        return self.url

# -----------------------------
# Shared stubs
# -----------------------------
async def _noop(*args, **kwargs):
    return None

# -----------------------------
# Fixtures
# -----------------------------
@pytest.fixture
def _fake_s3_ok(monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    s3 = _FakeS3OK()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: s3, raising=True)
    return s3

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


# -----------------------------
# Tests
# -----------------------------
@pytest.mark.anyio
async def test_signed_manifest_hls_by_format_success(async_client, _fake_s3_ok):
    payload = {
        "storage_key": "private/path/master.m3u8",  # ext shouldn't matter when format is given
        "format": "hls",
        "expires_in": 300,
    }
    r = await async_client.post(f"{BASE}/delivery/signed-manifest", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["url"] == _fake_s3_ok.url
    assert body["content_type"] == "application/vnd.apple.mpegurl"

    # S3 call arguments
    assert len(_fake_s3_ok.calls) == 1
    call = _fake_s3_ok.calls[0]
    assert call["storage_key"] == payload["storage_key"]
    assert call["expires_in"] == 300
    assert call["ctype"] == "application/vnd.apple.mpegurl"


@pytest.mark.anyio
async def test_signed_manifest_dash_by_format_success(async_client, _fake_s3_ok):
    payload = {
        "storage_key": "private/path/stream.something",  # no .mpd; format drives ctype
        "format": "dash",
        "expires_in": 180,
    }
    r = await async_client.post(f"{BASE}/delivery/signed-manifest", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["url"] == _fake_s3_ok.url
    assert body["content_type"] == "application/dash+xml"

    call = _fake_s3_ok.calls[-1]
    assert call["storage_key"] == payload["storage_key"]
    assert call["expires_in"] == 180
    assert call["ctype"] == "application/dash+xml"


@pytest.mark.anyio
async def test_signed_manifest_infer_hls_from_extension(async_client, _fake_s3_ok):
    payload = {
        "storage_key": "vod/title/master.M3U8",  # case-insensitive extension
        "expires_in": 240,
        # no format provided → infer from extension
    }
    r = await async_client.post(f"{BASE}/delivery/signed-manifest", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["content_type"] == "application/vnd.apple.mpegurl"

    call = _fake_s3_ok.calls[-1]
    assert call["ctype"] == "application/vnd.apple.mpegurl"
    assert call["expires_in"] == 240


@pytest.mark.anyio
async def test_signed_manifest_infer_dash_from_extension(async_client, _fake_s3_ok):
    payload = {
        "storage_key": "vod/title/manifest.mpd",
        "expires_in": 600,
    }
    r = await async_client.post(f"{BASE}/delivery/signed-manifest", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["content_type"] == "application/dash+xml"

    call = _fake_s3_ok.calls[-1]
    assert call["ctype"] == "application/dash+xml"
    assert call["expires_in"] == 600


@pytest.mark.anyio
async def test_signed_manifest_unknown_extension_defaults_octet_stream(async_client, _fake_s3_ok):
    payload = {
        "storage_key": "weird/manifest.txt",
        "expires_in": 120,
    }
    r = await async_client.post(f"{BASE}/delivery/signed-manifest", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["content_type"] == "application/octet-stream"

    # when format can't be inferred, API still calls S3 with ctype=None
    call = _fake_s3_ok.calls[-1]
    assert call["ctype"] is None
    assert call["storage_key"] == "weird/manifest.txt"


@pytest.mark.anyio
async def test_signed_manifest_s3_error(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod
    from app.utils.aws import S3StorageError

    class _FakeS3Fail:
        def presigned_get(self, *_, **__):
            raise S3StorageError("signing failed")

    monkeypatch.setattr(mod, "_ensure_s3", lambda: _FakeS3Fail(), raising=True)

    payload = {"storage_key": "vod/manifest.m3u8", "expires_in": 300}
    r = await async_client.post(f"{BASE}/delivery/signed-manifest", json=payload)
    assert r.status_code == 503
    assert r.json()["detail"] == "signing failed"
