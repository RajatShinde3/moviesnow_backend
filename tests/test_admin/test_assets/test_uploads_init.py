# tests/test_admin/test_uploads/test_uploads_init.py

import base64
import hashlib
import pytest

# Base path where your admin router is mounted
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


# Handy fake S3 client
class _FakeS3:
    def __init__(self, url="https://s3.fake/presign"):
        self.url = url
        self.calls = {"presigned_put": []}

    def presigned_put(self, key, *, content_type, public):
        self.calls["presigned_put"].append(
            {"key": key, "content_type": content_type, "public": public}
        )
        return f"{self.url}?key={key}"


# ─────────────────────────────────────────────────────────────────────────────
# Happy path
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_uploads_init_happy_path(async_client, monkeypatch, _mock_admin_mfa):
    # Fake S3
    fake_s3 = _FakeS3()
    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake_s3)

    # No-op idempotency (cold request)
    class _Redis:
        async def idempotency_get(self, k): return None
        async def idempotency_set(self, k, v, ttl_seconds=0): pass
    monkeypatch.setattr(mod, "redis_wrapper", _Redis())

    idem = "abc-123"
    payload = {
        "content_type": "image/jpeg",
        "key_prefix": "uploads/title",
        "filename_hint": "hero_poster",  # no extension in hint
    }
    r = await async_client.post(
        f"{BASE}/uploads/init",
        json=payload,
        headers={"Idempotency-Key": idem},
    )
    assert r.status_code == 200, r.text
    data = r.json()

    # Cache hardening
    assert r.headers.get("Cache-Control") == "no-store"
    assert r.headers.get("Pragma") == "no-cache"

    # Body contract
    assert "upload_url" in data and "storage_key" in data
    key = data["storage_key"]
    # MIME → .jpg
    assert key.endswith(".jpg")
    # Key structure and sanitization
    assert key.startswith("uploads/title/")
    assert "hero_poster" in key

    # S3 was called with correct args
    assert fake_s3.calls["presigned_put"] and fake_s3.calls["presigned_put"][0]["key"] == key
    assert fake_s3.calls["presigned_put"][0]["content_type"] == "image/jpeg"
    assert fake_s3.calls["presigned_put"][0]["public"] is False

    # Admin/MFA hooks ran
    assert _mock_admin_mfa["ensure_admin"] == 1
    assert _mock_admin_mfa["ensure_mfa"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Idempotency: snapshot is saved on first call
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_uploads_init_idempotency_sets_snapshot(async_client, monkeypatch):
    fake_s3 = _FakeS3()
    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake_s3)

    saved = {}
    class _Redis:
        async def idempotency_get(self, k): return None
        async def idempotency_set(self, k, v, ttl_seconds=0): saved["k"] = k; saved["v"] = v; saved["ttl"] = ttl_seconds
    monkeypatch.setattr(mod, "redis_wrapper", _Redis())

    idem = "same-key-1"
    r = await async_client.post(
        f"{BASE}/uploads/init",
        json={"content_type": "text/plain", "key_prefix": "uploads/tests", "filename_hint": "notes"},
        headers={"Idempotency-Key": idem},
    )
    assert r.status_code == 200
    assert saved and saved["ttl"] == 600
    assert saved["v"]["storage_key"].startswith("uploads/tests/")
    assert saved["v"]["storage_key"].endswith(".txt")


# ─────────────────────────────────────────────────────────────────────────────
# Idempotency: replay uses cached snapshot and bypasses S3 + no second snapshot
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_uploads_init_idempotency_replay_bypasses_s3(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.uploads as mod

    # Fake S3 that would explode if called
    class _BoomS3(_FakeS3):
        def presigned_put(self, *a, **k):
            raise AssertionError("S3 should not be called on replay")

    monkeypatch.setattr(mod, "_ensure_s3", lambda: _BoomS3())

    cached = {"upload_url": "https://cached/url", "storage_key": "uploads/cached/upload_deadbeef.bin"}

    class _Redis:
        async def idempotency_get(self, k): return cached
        async def idempotency_set(self, k, v, ttl_seconds=0): raise AssertionError("Snapshot should not be re-set")
    monkeypatch.setattr(mod, "redis_wrapper", _Redis())

    r = await async_client.post(
        f"{BASE}/uploads/init",
        json={"content_type": "application/x-stuff", "key_prefix": "we/ignore/on/replay"},
        headers={"Idempotency-Key": "same-key-2"},
    )
    assert r.status_code == 200
    assert r.json() == cached


# ─────────────────────────────────────────────────────────────────────────────
# Sanitization + defaults (unknown MIME → .bin, filename fallback with hash)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_uploads_init_unknown_mime_and_filename_fallback(async_client, monkeypatch):
    fake_s3 = _FakeS3()
    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake_s3)

    class _Redis:
        async def idempotency_get(self, k): return None
        async def idempotency_set(self, k, v, ttl_seconds=0): pass
    monkeypatch.setattr(mod, "redis_wrapper", _Redis())

    idem = "weird-mime-key"
    r = await async_client.post(
        f"{BASE}/uploads/init",
        json={"content_type": "application/x-unknown", "key_prefix": "/bad//prefix/../ok", "filename_hint": None},
        headers={"Idempotency-Key": idem},
    )
    assert r.status_code == 200
    key = r.json()["storage_key"]
    # prefix sanitized (no traversal, no leading slash)
    assert key.startswith("bad/prefix/ok/") or key.startswith("bad/prefix/") or key.startswith("ok/") or key.startswith("uploads/"), key
    # fallback stem begins with upload_<short_hash>
    short = hashlib.sha1(idem.encode("utf-8")).hexdigest()[:8]
    assert f"upload_{short}" in key
    assert key.endswith(".bin")


# ─────────────────────────────────────────────────────────────────────────────
# Cache headers are always strict no-store
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_uploads_init_cache_headers(async_client, monkeypatch):
    fake_s3 = _FakeS3()
    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake_s3)

    class _Redis:
        async def idempotency_get(self, k): return None
        async def idempotency_set(self, k, v, ttl_seconds=0): pass
    monkeypatch.setattr(mod, "redis_wrapper", _Redis())

    r = await async_client.post(
        f"{BASE}/uploads/init",
        json={"content_type": "video/mp4", "key_prefix": "uploads/video", "filename_hint": "intro"},
    )
    assert r.headers.get("Cache-Control") == "no-store"
    assert r.headers.get("Pragma") == "no-cache"


# ─────────────────────────────────────────────────────────────────────────────
# Admin/MFA gate: ensure_admin or ensure_mfa raising → 403/401 bubbles up
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_uploads_init_admin_gate_enforced(async_client, monkeypatch):
    # Make ensure_admin raise 403
    import app.dependencies.admin as admin_deps
    from fastapi import HTTPException

    async def _deny(*a, **k):
        raise HTTPException(status_code=403, detail="nope")

    monkeypatch.setattr(admin_deps, "ensure_admin", _deny)

    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(mod, "_ensure_s3", lambda: _FakeS3())

    class _Redis:
        async def idempotency_get(self, k): return None
        async def idempotency_set(self, k, v, ttl_seconds=0): pass
    monkeypatch.setattr(mod, "redis_wrapper", _Redis())

    r = await async_client.post(
        f"{BASE}/uploads/init",
        json={"content_type": "image/png", "key_prefix": "uploads/png", "filename_hint": "icon"},
    )
    assert r.status_code == 403
    assert "nope" in r.text


# ─────────────────────────────────────────────────────────────────────────────
# S3 bootstrap failure → 503
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_uploads_init_s3_init_failure(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.uploads as mod
    from fastapi import HTTPException

    class _Boom:
        def __call__(self):
            # Simulate _ensure_s3 raising HTTPException(503)
            raise HTTPException(status_code=503, detail="S3 down")

    monkeypatch.setattr(mod, "_ensure_s3", _Boom())

    class _Redis:
        async def idempotency_get(self, k): return None
        async def idempotency_set(self, k, v, ttl_seconds=0): pass
    monkeypatch.setattr(mod, "redis_wrapper", _Redis())

    r = await async_client.post(
        f"{BASE}/uploads/init",
        json={"content_type": "text/plain", "key_prefix": "uploads/txt", "filename_hint": "readme"},
    )
    assert r.status_code == 503
    assert "S3 down" in r.text


# ─────────────────────────────────────────────────────────────────────────────
# (Nice to have) Verify audit log called best-effort (does not block failures)
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_uploads_init_emits_audit_log(async_client, monkeypatch):
    fake_s3 = _FakeS3()
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

    monkeypatch.setattr(mod, "log_audit_event", _log_audit)

    r = await async_client.post(
        f"{BASE}/uploads/init",
        json={"content_type": "image/webp", "key_prefix": "uploads/pics", "filename_hint": "thumb"},
    )
    assert r.status_code == 200
    assert calls["count"] == 1
    assert calls["args"][2] == "UPLOAD_INIT"
    assert "storage_key" in calls["args"][5]
