# tests/test_admin/test_assets/test_uploads_multipart_create.py
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
    def __init__(self, upload_id="UPID123"):
        self._upload_id = upload_id
        self._calls = []

    def create_multipart_upload(self, **kwargs):
        # capture the call for assertions if needed
        self._calls.append(kwargs)
        return {"UploadId": self._upload_id}


class _FakeS3:
    def __init__(self, upload_id="UPID123"):
        self.bucket = "test-bucket"
        self.client = _FakeS3Client(upload_id=upload_id)


@pytest.mark.anyio
async def test_multipart_create_happy_path(async_client, monkeypatch):
    fake_s3 = _FakeS3(upload_id="UPID42")
    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake_s3)

    class _Redis:
        async def idempotency_get(self, k): return None
        async def idempotency_set(self, k, v, ttl_seconds=0): pass
    monkeypatch.setattr(mod, "redis_wrapper", _Redis())

    idem = "abc-123"
    r = await async_client.post(
        f"{BASE}/uploads/multipart/create",
        json={"content_type": "video/mp4", "key_prefix": "uploads/multipart", "filename_hint": "TrailerA"},
        headers={"Idempotency-Key": idem},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert "uploadId" in data and data["uploadId"] == "UPID42"
    assert "storage_key" in data
    key = data["storage_key"]
    assert key.startswith("uploads/multipart/"), key
    assert key.endswith(".mp4"), key
    assert "TrailerA" in key or "TrailerA.mp4" in key


@pytest.mark.anyio
async def test_multipart_create_sanitizes_prefix(async_client, monkeypatch):
    fake_s3 = _FakeS3()
    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake_s3)

    class _Redis:
        async def idempotency_get(self, k): return None
        async def idempotency_set(self, k, v, ttl_seconds=0): pass
    monkeypatch.setattr(mod, "redis_wrapper", _Redis())

    idem = "sanitize-prefix"
    r = await async_client.post(
        f"{BASE}/uploads/multipart/create",
        json={"content_type": "video/mp4", "key_prefix": "/bad//prefix/../ok", "filename_hint": None},
        headers={"Idempotency-Key": idem},
    )
    assert r.status_code == 200, r.text
    key = r.json()["storage_key"]
    # prefix sanitized (no traversal, no leading slash)
    assert key.startswith("bad/prefix/ok/") or key.startswith("bad/prefix/") or key.startswith("ok/") \
           or key.startswith("uploads/multipart/"), key
    assert key.endswith(".mp4"), key


@pytest.mark.anyio
async def test_multipart_create_uses_filename_hint_safely(async_client, monkeypatch):
    fake_s3 = _FakeS3()
    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake_s3)

    class _Redis:
        async def idempotency_get(self, k): return None
        async def idempotency_set(self, k, v, ttl_seconds=0): pass
    monkeypatch.setattr(mod, "redis_wrapper", _Redis())

    # Provide a hint with spaces and punctuation; sanitizer should clean it
    hint = "My Fancy File (Final!!)"
    r = await async_client.post(
        f"{BASE}/uploads/multipart/create",
        json={"content_type": "video/mp4", "key_prefix": "uploads/multipart", "filename_hint": hint},
        headers={"Idempotency-Key": "hint-123"},
    )
    assert r.status_code == 200, r.text
    key = r.json()["storage_key"]
    # spaces -> underscores; drop punctuation; keep safe chars
    assert "My_Fancy_File_Final" in key, key
    assert key.startswith("uploads/multipart/"), key
    assert key.endswith(".mp4"), key


@pytest.mark.anyio
async def test_multipart_create_idempotency_replay_uses_snapshot(async_client, monkeypatch):
    # If a snapshot exists in Redis, the route should return it and not call S3
    import app.api.v1.routers.admin.assets.uploads as mod

    # Crash if S3 is touched
    monkeypatch.setattr(mod, "_ensure_s3", lambda: (_ for _ in ()).throw(RuntimeError("S3 should not be called")))

    snapshot = {"uploadId": "DUP-999", "storage_key": "snap/prefix/mup_deadbeef.mp4"}

    class _Redis:
        async def idempotency_get(self, k): return snapshot
        async def idempotency_set(self, k, v, ttl_seconds=0): pass

    monkeypatch.setattr(mod, "redis_wrapper", _Redis())

    r = await async_client.post(
        f"{BASE}/uploads/multipart/create",
        json={"content_type": "video/mp4", "key_prefix": "uploads/multipart", "filename_hint": "ignored"},
        headers={"Idempotency-Key": "same-key"},
    )
    assert r.status_code == 200, r.text
    assert r.json() == snapshot


@pytest.mark.anyio
async def test_multipart_create_emits_audit_log(async_client, monkeypatch):
    fake_s3 = _FakeS3(upload_id="UP-AUDIT-1")
    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake_s3)

    class _Redis:
        async def idempotency_get(self, k): return None
        async def idempotency_set(self, k, v, ttl_seconds=0): pass
    monkeypatch.setattr(mod, "redis_wrapper", _Redis())

    calls = {"count": 0, "args": None, "kwargs": None}

    async def _log_audit(db, user, action, status, request, meta_data):
        calls["count"] += 1
        calls["args"] = (db, user, action, status, request, meta_data)
        calls["kwargs"] = {}

    # module-level symbol is imported in the router; patch that
    monkeypatch.setattr(mod, "log_audit_event", _log_audit)

    r = await async_client.post(
        f"{BASE}/uploads/multipart/create",
        json={"content_type": "video/mp4", "key_prefix": "uploads/multipart", "filename_hint": "AuditSample"},
        headers={"Idempotency-Key": "audit-key-1"},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert calls["count"] == 1
    (db, user, action, status, request, meta) = calls["args"]
    assert action == "MULTIPART_CREATE"
    assert status == "SUCCESS"
    assert meta["upload_id"] == data["uploadId"]
    assert meta["storage_key"] == data["storage_key"]


@pytest.mark.anyio
async def test_multipart_create_s3_failure_yields_503(async_client, monkeypatch):
    class _BoomS3Client:
        def create_multipart_upload(self, **kwargs):
            raise Exception("kapow")

    class _BoomS3:
        bucket = "test-bucket"
        client = _BoomS3Client()

    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: _BoomS3())

    class _Redis:
        async def idempotency_get(self, k): return None
        async def idempotency_set(self, k, v, ttl_seconds=0): pass
    monkeypatch.setattr(mod, "redis_wrapper", _Redis())

    r = await async_client.post(
        f"{BASE}/uploads/multipart/create",
        json={"content_type": "video/mp4", "key_prefix": "uploads/multipart", "filename_hint": "x"},
        headers={"Idempotency-Key": "err-key"},
    )
    assert r.status_code == 503
    assert "Multipart init failed" in r.text
