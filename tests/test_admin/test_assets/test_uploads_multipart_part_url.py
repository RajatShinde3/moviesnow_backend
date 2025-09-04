# tests/test_admin/test_assets/test_uploads_multipart_part_url.py
import pytest

BASE = "/api/v1/admin"

# ─────────────────────────────────────────────────────────────────────────────
# Autouse: make Admin/MFA checks no-ops by default (we test failures separately)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _mock_admin_mfa(monkeypatch):
    import app.dependencies.admin as admin_deps

    calls = {"ensure_admin": 0, "ensure_mfa": 0}

    async def _ensure_admin(user):
        calls["ensure_admin"] += 1

    async def _ensure_mfa(request):
        calls["ensure_mfa"] += 1

    monkeypatch.setattr(admin_deps, "ensure_admin", _ensure_admin)
    monkeypatch.setattr(admin_deps, "ensure_mfa", _ensure_mfa)

    return calls


# Make the auth dependency resolve to a fake admin user
@pytest.fixture(autouse=True)
async def _override_current_user(app):
    from app.core.security import get_current_user

    class _U:
        id = "00000000-0000-0000-0000-000000000001"
        is_superuser = True

    async def _dep():
        return _U()

    app.dependency_overrides[get_current_user] = _dep
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_current_user, None)


class _FakeS3Client:
    def __init__(self):
        self.calls = []

    def generate_presigned_url(self, *, ClientMethod, Params, ExpiresIn, HttpMethod):
        self.calls.append(
            {
                "ClientMethod": ClientMethod,
                "Params": Params,
                "ExpiresIn": ExpiresIn,
                "HttpMethod": HttpMethod,
            }
        )
        # Return a stable, fake URL
        return f"https://example.test/{Params['Key']}?uploadId={Params['UploadId']}&partNumber={Params['PartNumber']}"


class _FakeS3:
    def __init__(self):
        self.bucket = "test-bucket"
        self.client = _FakeS3Client()


@pytest.mark.anyio
async def test_multipart_part_url_happy_path(async_client, monkeypatch):
    fake_s3 = _FakeS3()
    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake_s3)

    upload_id = "UPID123"
    key = "uploads/multipart/asset.mp4"
    part = 7

    r = await async_client.get(
        f"{BASE}/uploads/multipart/{upload_id}/part-url",
        params={"key": key, "partNumber": part},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert "upload_url" in data and isinstance(data["upload_url"], str)

    # Cache headers applied (no-store)
    assert "no-store" in r.headers.get("Cache-Control", "")

    # Verify S3 call args
    assert len(fake_s3.client.calls) == 1
    call = fake_s3.client.calls[0]
    assert call["ClientMethod"] == "upload_part"
    assert call["HttpMethod"] == "PUT"
    assert call["ExpiresIn"] == 3600

    params = call["Params"]
    assert params["Bucket"] == "test-bucket"
    assert params["Key"] == key
    assert params["UploadId"] == upload_id
    assert params["PartNumber"] == part


@pytest.mark.anyio
@pytest.mark.parametrize("bad_part", [0, 10001])
async def test_multipart_part_url_partnumber_bounds_validation(async_client, monkeypatch, bad_part):
    fake_s3 = _FakeS3()
    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake_s3)

    r = await async_client.get(
        f"{BASE}/uploads/multipart/UPBOUND/part-url",
        params={"key": "k", "partNumber": bad_part},
    )
    assert r.status_code == 422  # FastAPI validation error


@pytest.mark.anyio
async def test_multipart_part_url_missing_key_is_422(async_client, monkeypatch):
    fake_s3 = _FakeS3()
    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake_s3)

    r = await async_client.get(
        f"{BASE}/uploads/multipart/UPMISS/part-url",
        params={"partNumber": 1},  # missing key
    )
    assert r.status_code == 422


@pytest.mark.anyio
async def test_multipart_part_url_allows_stringy_partnumber(async_client, monkeypatch):
    fake_s3 = _FakeS3()
    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake_s3)

    r = await async_client.get(
        f"{BASE}/uploads/multipart/UPSTR/part-url",
        params={"key": "uploads/multipart/file.mp4", "partNumber": "5"},
    )
    assert r.status_code == 200, r.text
    # Confirm S3 saw an int 5
    call = fake_s3.client.calls[0]
    assert call["Params"]["PartNumber"] == 5


@pytest.mark.anyio
async def test_multipart_part_url_s3_failure_returns_503(async_client, monkeypatch):
    class _BoomClient:
        def generate_presigned_url(self, **kwargs):
            raise Exception("kapow")

    class _BoomS3:
        bucket = "test-bucket"
        client = _BoomClient()

    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: _BoomS3())

    r = await async_client.get(
        f"{BASE}/uploads/multipart/UPERR/part-url",
        params={"key": "uploads/multipart/file.mp4", "partNumber": 3},
    )
    assert r.status_code == 503
    assert "Part URL failed" in r.text
