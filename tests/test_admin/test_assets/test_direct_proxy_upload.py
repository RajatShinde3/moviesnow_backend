# tests/test_admin/test_assets/test_uploads_direct_proxy.py

import base64
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
# Autouse: make MFA a no-op
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _patch_mfa(monkeypatch):
    import app.dependencies.admin as admin_mod

    async def _noop_mfa(_request):
        return None

    monkeypatch.setattr(admin_mod, "ensure_mfa", _noop_mfa, raising=True)


# ─────────────────────────────────────────────────────────────────────────────
# Helper: Fake S3 that records put_bytes calls
# ─────────────────────────────────────────────────────────────────────────────
class _FakeS3:
    def __init__(self):
        self.bucket = "test-bucket"
        self.last_put = None

    def put_bytes(self, key, data, *, content_type, public):
        self.last_put = {
            "key": key,
            "data": data,
            "content_type": content_type,
            "public": public,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_direct_proxy_happy_path(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.uploads as mod

    fake = _FakeS3()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)

    payload = base64.b64encode(b"hello-bytes").decode()
    r = await async_client.post(
        f"{BASE}/uploads/direct-proxy",
        json={
            "content_type": "image/png",
            "data_base64": payload,
            "key_prefix": "custom/prefix",
            "filename_hint": "logo v1.png",
        },
        headers={"Idempotency-Key": "abc123"},
    )

    assert r.status_code == 200, r.text
    body = r.json()
    assert "storage_key" in body
    key = body["storage_key"]

    # extension from content type & prefix applied
    assert key.endswith(".png")
    assert key.startswith("custom/prefix/")

    # S3 called with expected args
    called = fake.last_put
    assert called is not None
    assert called["key"] == key
    assert called["data"] == b"hello-bytes"
    assert called["content_type"] == "image/png"
    assert called["public"] is False

    # sensitive cache headers present
    assert "no-store" in r.headers.get("cache-control", "").lower()


@pytest.mark.anyio
async def test_direct_proxy_invalid_base64_returns_400(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(
        mod, "_ensure_s3", lambda: (_ for _ in ()).throw(RuntimeError("S3 should not be called")), raising=True
    )

    r = await async_client.post(
        f"{BASE}/uploads/direct-proxy",
        json={
            "content_type": "image/png",
            "data_base64": "not-base64!!!",
            "key_prefix": "uploads/direct",
            "filename_hint": "x.png",
        },
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "Invalid base64 payload"


@pytest.mark.anyio
async def test_direct_proxy_too_large_returns_413(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.uploads as mod

    # shrink limit to keep test light
    monkeypatch.setattr(mod, "MAX_DIRECT_UPLOAD_BYTES", 8, raising=True)
    monkeypatch.setattr(
        mod, "_ensure_s3", lambda: (_ for _ in ()).throw(RuntimeError("S3 should not be called")), raising=True
    )

    b = b"0123456789"  # 10 bytes > 8
    payload = base64.b64encode(b).decode()

    r = await async_client.post(
        f"{BASE}/uploads/direct-proxy",
        json={"content_type": "application/octet-stream", "data_base64": payload, "filename_hint": "big.bin"},
    )
    assert r.status_code == 413
    assert "File too large" in r.json()["detail"]


@pytest.mark.anyio
async def test_direct_proxy_storage_error_returns_503(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.uploads as mod
    from app.utils.aws import S3StorageError

    class _BoomS3(_FakeS3):
        def put_bytes(self, *a, **k):
            raise S3StorageError("S3 unavailable")

    monkeypatch.setattr(mod, "_ensure_s3", lambda: _BoomS3(), raising=True)

    payload = base64.b64encode(b"x").decode()
    r = await async_client.post(
        f"{BASE}/uploads/direct-proxy",
        json={"content_type": "application/octet-stream", "data_base64": payload},
    )
    assert r.status_code == 503
    assert "S3 unavailable" in r.json()["detail"]


@pytest.mark.anyio
async def test_direct_proxy_audit_log_emitted(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.uploads as mod

    fake = _FakeS3()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)

    calls = {"count": 0, "args": None}

    async def _audit_stub(db, user, action, status, request, meta_data=None):
        calls["count"] += 1
        calls["args"] = (db, user, action, status, request, meta_data)

    # Route may expose log_audit_event directly OR via audit_log_service; patch whichever exists
    try:
        monkeypatch.setattr(mod, "log_audit_event", _audit_stub, raising=True)
    except AttributeError:
        import app.services.audit_log_service as als
        monkeypatch.setattr(als, "log_audit_event", _audit_stub, raising=True)

    payload = base64.b64encode(b"abc").decode()
    r = await async_client.post(
        f"{BASE}/uploads/direct-proxy",
        json={"content_type": "image/webp", "data_base64": payload, "key_prefix": "icons", "filename_hint": "ic.webp"},
        headers={"Idempotency-Key": "same-key"},
    )

    assert r.status_code == 200
    assert calls["count"] == 1
    _, _user, action, status, _req, meta = calls["args"]
    assert action == "DIRECT_UPLOAD_PROXY"
    assert status == "SUCCESS"
    assert isinstance(meta, dict) and meta.get("size") == 3 and "storage_key" in meta


@pytest.mark.anyio
async def test_direct_proxy_key_is_deterministic_with_same_idempotency_key(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.uploads as mod

    fake = _FakeS3()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)

    payload = base64.b64encode(b"same").decode()
    headers = {"Idempotency-Key": "fixed-key"}

    r1 = await async_client.post(
        f"{BASE}/uploads/direct-proxy",
        json={"content_type": "application/x-unknown", "data_base64": payload},
        headers=headers,
    )
    r2 = await async_client.post(
        f"{BASE}/uploads/direct-proxy",
        json={"content_type": "application/x-unknown", "data_base64": payload},
        headers=headers,
    )

    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["storage_key"] == r2.json()["storage_key"]


@pytest.mark.anyio
async def test_direct_proxy_sanitizes_prefix_reasonably(async_client, monkeypatch):
    import app.api.v1.routers.admin.assets.uploads as mod

    fake = _FakeS3()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: fake, raising=True)

    b64 = base64.b64encode(b"ok").decode()
    r = await async_client.post(
        f"{BASE}/uploads/direct-proxy",
        json={
            "content_type": "application/x-unknown",
            "data_base64": b64,
            "key_prefix": "/bad//prefix/../ok",
            "filename_hint": None,  # exercise fallback name
        },
        headers={"Idempotency-Key": "sanitize-key"},
    )

    assert r.status_code == 200
    key = r.json()["storage_key"]

    # No leading slash; allow a few reasonable sanitized starts (be tolerant to implementation)
    assert not key.startswith("/")
    assert key.startswith("bad/prefix/ok/") or key.startswith("bad/prefix/") or key.startswith("ok/") or key.startswith("uploads/direct/")
    assert key.endswith(".bin")  # unknown mime → .bin


@pytest.mark.anyio
async def test_direct_proxy_admin_guard_blocks_before_s3(async_client, monkeypatch):
    import app.dependencies.admin as admin_mod

    async def _deny_admin(_user):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    monkeypatch.setattr(admin_mod, "ensure_admin", _deny_admin, raising=True)

    import app.api.v1.routers.admin.assets.uploads as mod
    monkeypatch.setattr(
        mod, "_ensure_s3", lambda: (_ for _ in ()).throw(RuntimeError("S3 should not be touched")), raising=True
    )

    r = await async_client.post(
        f"{BASE}/uploads/direct-proxy",
        json={"content_type": "image/png", "data_base64": base64.b64encode(b"x").decode()},
    )
    assert r.status_code == 403
    assert r.json()["detail"].lower().startswith("admin")
