# tests/test_admin/test_assets/test_uploads_multipart_complete.py

import uuid as _uuid
import pytest
from fastapi import HTTPException

BASE = "/api/v1/admin"


# ─────────────────────────────────────────────────────────────────────────────
# Autouse: act as a superuser for all tests (mirrors your existing pattern)
# ─────────────────────────────────────────────────────────────────────────────
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



# ─────────────────────────────────────────────────────────────────────────────
# Autouse: patch MFA to a no-op for speed/stability in tests
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _patch_mfa(monkeypatch):
    import app.dependencies.admin as admin_mod

    async def _noop_mfa(request):  # signature matches ensure_mfa(request)
        return None

    monkeypatch.setattr(admin_mod, "ensure_mfa", _noop_mfa, raising=True)


# ─────────────────────────────────────────────────────────────────────────────
# Helper: Fake S3
# ─────────────────────────────────────────────────────────────────────────────
class _FakeS3:
    bucket = "test-bucket"

    class _Client:
        def __init__(self, parent):
            self.parent = parent
            self.last_complete_args = None

        def complete_multipart_upload(self, *, Bucket, Key, UploadId, MultipartUpload):
            # Record what we were called with so tests can assert
            self.last_complete_args = {
                "Bucket": Bucket,
                "Key": Key,
                "UploadId": UploadId,
                "Parts": MultipartUpload.get("Parts") or [],
            }
            # Success: nothing to return/raise

    def __init__(self):
        self.client = self._Client(self)


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_multipart_complete_happy_path(async_client, monkeypatch):
    # Arrange
    import app.api.v1.routers.admin.assets.uploads as mod
    fake = _FakeS3()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)

    upload_id = "UPLOAD-123"
    key = "uploads/multipart/movie_abc.mp4"
    parts = [{"ETag": '"etag1"', "PartNumber": "1"}, {"ETag": '"etag2"', "PartNumber": "2"}]

    # Act
    r = await async_client.post(
        f"{BASE}/uploads/multipart/{upload_id}/complete",
        json={"key": key, "parts": parts},
    )

    # Assert
    assert r.status_code == 200
    body = r.json()
    assert body["message"] == "Upload complete"
    assert body["storage_key"] == key

    # S3 call captured with coerced ints for PartNumber
    called = fake.client.last_complete_args
    assert called is not None
    assert called["Bucket"] == fake.bucket
    assert called["Key"] == key
    assert called["UploadId"] == upload_id
    assert called["Parts"] == [{"ETag": '"etag1"', "PartNumber": 1}, {"ETag": '"etag2"', "PartNumber": 2}]

    # Cache hardening headers present on final response
    assert "no-store" in r.headers.get("cache-control", "").lower()


@pytest.mark.anyio
async def test_multipart_complete_coerces_invalid_partnumber_raises_503(async_client, monkeypatch):
    # Arrange
    import app.api.v1.routers.admin.assets.uploads as mod
    # Ensure S3 is obtained so that the int() conversion happens inside the try-block
    fake = _FakeS3()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)

    upload_id = "UPLOAD-FAIL"
    key = "uploads/multipart/bad_parts.bin"
    # PartNumber is non-numeric -> int() will raise ValueError and the route should convert it to 503
    parts = [{"ETag": '"etag1"', "PartNumber": "x"}]

    # Act
    r = await async_client.post(
        f"{BASE}/uploads/multipart/{upload_id}/complete",
        json={"key": key, "parts": parts},
    )

    # Assert
    assert r.status_code == 503
    assert "Complete failed" in r.json()["detail"]


@pytest.mark.anyio
async def test_multipart_complete_s3_error_bubbles_as_503(async_client, monkeypatch):
    # Arrange
    import app.api.v1.routers.admin.assets.uploads as mod

    class _BoomS3(_FakeS3):
        class _Client(_FakeS3._Client):
            def complete_multipart_upload(self, **kwargs):
                raise RuntimeError("S3 down")

    boom = _BoomS3()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: boom, raising=True)

    # Act
    r = await async_client.post(
        f"{BASE}/uploads/multipart/UP-ERR/complete",
        json={"key": "k.bin", "parts": [{"ETag": '"e"', "PartNumber": "1"}]},
    )

    # Assert
    assert r.status_code == 503
    assert "Complete failed" in r.json()["detail"]


@pytest.mark.anyio
async def test_multipart_complete_emits_audit_log(async_client, monkeypatch):
    # Arrange
    import app.api.v1.routers.admin.assets.uploads as mod
    fake = _FakeS3()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)

    calls = {"count": 0, "args": None, "kwargs": None}

    async def _audit_stub(db, user, action, status, request, meta_data=None):
        calls["count"] += 1
        calls["args"] = (db, user, action, status, request, meta_data)
        calls["kwargs"] = {}

    monkeypatch.setattr(mod, "log_audit_event", _audit_stub, raising=True)

    # Act
    r = await async_client.post(
        f"{BASE}/uploads/multipart/UP-AUD/complete",
        json={"key": "uploads/multipart/aud.mp4", "parts": [{"ETag": '"e1"', "PartNumber": "1"}]},
    )

    # Assert
    assert r.status_code == 200
    assert calls["count"] == 1
    _, _user, action, status, _req, meta = calls["args"]
    assert action == "MULTIPART_COMPLETE"
    assert status == "SUCCESS"
    assert meta and meta["storage_key"] == "uploads/multipart/aud.mp4" and meta["upload_id"] == "UP-AUD"


@pytest.mark.anyio
async def test_multipart_complete_audit_error_is_swallowed(async_client, monkeypatch):
    # Arrange
    import app.api.v1.routers.admin.assets.uploads as mod
    fake = _FakeS3()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)

    async def _boom_audit(*_a, **_k):
        raise RuntimeError("audit sink down")

    monkeypatch.setattr(mod, "log_audit_event", _boom_audit, raising=True)

    # Act
    r = await async_client.post(
        f"{BASE}/uploads/multipart/UP-NO-AUD/complete",
        json={"key": "uploads/multipart/no_aud.mp4", "parts": [{"ETag": '"e1"', "PartNumber": "1"}]},
    )

    # Assert → request still succeeds
    assert r.status_code == 200
    assert r.json()["storage_key"] == "uploads/multipart/no_aud.mp4"


@pytest.mark.anyio
async def test_multipart_complete_admin_guard(async_client, monkeypatch):
    # Arrange: force the admin check to fail
    import app.dependencies.admin as admin_mod

    async def _deny_admin(_user):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    monkeypatch.setattr(admin_mod, "ensure_admin", _deny_admin, raising=True)

    # Also make sure the route won't touch S3 once auth fails
    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: (_ for _ in ()).throw(RuntimeError("should not reach S3")), raising=True)

    # Act
    r = await async_client.post(
        f"{BASE}/uploads/multipart/UP-NOPE/complete",
        json={"key": "k", "parts": [{"ETag": '"e"', "PartNumber": "1"}]},
    )

    # Assert
    assert r.status_code == 403
    assert r.json()["detail"].lower().startswith("admin")
