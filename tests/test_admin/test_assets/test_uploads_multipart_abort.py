# tests/test_admin/test_assets/test_uploads_multipart_abort.py

import uuid as _uuid
import pytest
from fastapi import HTTPException

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



# ─────────────────────────────────────────────────────────────────────────────
# Autouse: make MFA a no-op to keep tests fast/deterministic
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _patch_mfa(monkeypatch):
    import app.dependencies.admin as admin_mod

    async def _noop_mfa(request):  # signature matches ensure_mfa
        return None

    monkeypatch.setattr(admin_mod, "ensure_mfa", _noop_mfa, raising=True)


# ─────────────────────────────────────────────────────────────────────────────
# Helper: Fake S3 with abort capture
# ─────────────────────────────────────────────────────────────────────────────
class _FakeS3:
    bucket = "test-bucket"

    class _Client:
        def __init__(self, parent):
            self.parent = parent
            self.last_abort_args = None

        def abort_multipart_upload(self, *, Bucket, Key, UploadId):
            self.last_abort_args = {
                "Bucket": Bucket,
                "Key": Key,
                "UploadId": UploadId,
            }

    def __init__(self):
        self.client = self._Client(self)


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_multipart_abort_happy_path(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.uploads as mod
    fake = _FakeS3()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)

    upload_id = "UP-123"
    key = "uploads/multipart/movie_x.mp4"

    r = await async_client.post(
        f"{BASE}/uploads/multipart/{upload_id}/abort",
        json={"key": key},
    )

    assert r.status_code == 200
    assert r.json()["message"] == "Upload aborted"

    called = fake.client.last_abort_args
    assert called is not None
    assert called["Bucket"] == fake.bucket
    assert called["Key"] == key
    assert called["UploadId"] == upload_id

    # sensitive cache headers present
    assert "no-store" in r.headers.get("cache-control", "").lower()


@pytest.mark.anyio
async def test_multipart_abort_s3_error_bubbles_as_503(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.uploads as mod

    class _BoomS3(_FakeS3):
        class _Client(_FakeS3._Client):
            def abort_multipart_upload(self, **_k):
                raise RuntimeError("S3 down")

    boom = _BoomS3()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: boom, raising=True)

    r = await async_client.post(
        f"{BASE}/uploads/multipart/UP-ERR/abort",
        json={"key": "uploads/multipart/oops.bin"},
    )

    assert r.status_code == 503
    assert "Abort failed" in r.json()["detail"]


@pytest.mark.anyio
async def test_multipart_abort_emits_audit_log(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.uploads as mod
    fake = _FakeS3()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)

    calls = {"count": 0, "args": None, "kwargs": None}

    async def _audit_stub(db, user, action, status, request, meta_data=None):
        calls["count"] += 1
        calls["args"] = (db, user, action, status, request, meta_data)
        calls["kwargs"] = {}

    monkeypatch.setattr(mod, "log_audit_event", _audit_stub, raising=True)

    key = "uploads/multipart/aud.bin"
    upload_id = "UP-AUD"

    r = await async_client.post(
        f"{BASE}/uploads/multipart/{upload_id}/abort",
        json={"key": key},
    )

    assert r.status_code == 200
    assert calls["count"] == 1
    _, _user, action, status, _req, meta = calls["args"]
    assert action == "MULTIPART_ABORT"
    assert status == "SUCCESS"
    assert meta and meta["storage_key"] == key and meta["upload_id"] == upload_id


@pytest.mark.anyio
async def test_multipart_abort_audit_error_is_swallowed(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.uploads as mod
    fake = _FakeS3()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)

    async def _boom_audit(*_a, **_k):
        raise RuntimeError("audit sink down")

    monkeypatch.setattr(mod, "log_audit_event", _boom_audit, raising=True)

    r = await async_client.post(
        f"{BASE}/uploads/multipart/UP-NO-AUD/abort",
        json={"key": "uploads/multipart/noaud.mp4"},
    )

    # Route still succeeds
    assert r.status_code == 200
    assert r.json()["message"] == "Upload aborted"


@pytest.mark.anyio
async def test_multipart_abort_admin_guard(async_client, monkeypatch):
    # Force admin check to fail and ensure S3 is not touched
    import app.dependencies.admin as admin_mod

    async def _deny_admin(_user):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    monkeypatch.setattr(admin_mod, "ensure_admin", _deny_admin, raising=True)

    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(
        mod,
        "_ensure_s3",
        lambda: (_ for _ in ()).throw(RuntimeError("should not reach S3")),
        raising=True,
    )

    r = await async_client.post(
        f"{BASE}/uploads/multipart/UP-NOPE/abort",
        json={"key": "uploads/multipart/whatever.bin"},
    )

    assert r.status_code == 403
    assert r.json()["detail"].lower().startswith("admin")
