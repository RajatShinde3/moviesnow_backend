import pytest
from fastapi import HTTPException

BASE = "/api/v1/admin"


# -----------------------------
# Fakes / helpers
# -----------------------------
class _Lock:
    async def __aenter__(self):
        return None

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeRedis:
    def __init__(self):
        self.storage = {}
        self.deleted = []
        self.lock_calls = []
        self.client = self  # expose delete via .client like redis-py

    def lock(self, key: str, timeout=None, blocking_timeout=None):
        self.lock_calls.append({"key": key, "timeout": timeout, "blocking_timeout": blocking_timeout})
        return _Lock()

    async def json_get(self, key: str, default=None):
        return self.storage.get(key, default)

    async def json_set(self, key: str, data, ttl_seconds=None):
        self.storage[key] = data

    async def delete(self, key: str):
        self.deleted.append(key)
        self.storage.pop(key, None)


class _FakeS3OK:
    def __init__(self, url="https://example.com/signed"):
        self.url = url
        self.calls = []

    def presigned_get(self, storage_key, expires_in, response_content_disposition=None):
        self.calls.append(
            {
                "storage_key": storage_key,
                "expires_in": expires_in,
                "content_disp": response_content_disposition,
            }
        )
        return self.url


# -----------------------------
# Fixtures
# -----------------------------
@pytest.fixture
def _fake_redis(monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    r = _FakeRedis()
    monkeypatch.setattr(mod, "redis_wrapper", r, raising=True)
    return r


@pytest.fixture
def _fake_s3_ok(monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    s3 = _FakeS3OK()
    monkeypatch.setattr(mod, "_ensure_s3", lambda: s3, raising=True)
    return s3


# -----------------------------
# Tests
# -----------------------------
@pytest.mark.anyio
async def test_redeem_json_success(async_client, _fake_redis, _fake_s3_ok, monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    token = "tok-json-1"
    key = mod.DL_TOKEN_KEY_T.format(token=token)
    _fake_redis.storage[key] = {"storage_key": "secure/content/file.bin", "one_time": True}

    r = await async_client.get(
        f"{BASE}/delivery/download/{token}",
        params={"redirect": "false", "filename": "paid.bin", "expires_in": "120"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "url" in body and body["url"] == _fake_s3_ok.url

    # S3 was called with correct args
    assert len(_fake_s3_ok.calls) == 1
    call = _fake_s3_ok.calls[0]
    assert call["storage_key"] == "secure/content/file.bin"
    assert call["expires_in"] == 120
    assert call["content_disp"] == 'attachment; filename="paid.bin"'

    # Token should be deleted (best-effort)
    assert key in _fake_redis.deleted

    # Lock was taken
    assert any(c["key"] == f"lock:download:token:{token}" for c in _fake_redis.lock_calls)


@pytest.mark.anyio
async def test_redeem_redirect_success(async_client, _fake_redis, _fake_s3_ok, monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    token = "tok-redir-1"
    key = mod.DL_TOKEN_KEY_T.format(token=token)
    _fake_redis.storage[key] = {"storage_key": "movie/trailer.mp4", "one_time": True}

    r = await async_client.get(f"{BASE}/delivery/download/{token}")
    assert r.status_code == 307
    assert r.headers["location"] == _fake_s3_ok.url
    # cache busting headers present
    assert r.headers.get("cache-control") == "no-store"
    assert r.headers.get("pragma") == "no-cache"
    # token deletion happened
    assert key in _fake_redis.deleted


@pytest.mark.anyio
async def test_redeem_token_not_found(async_client, _fake_redis):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    token = "missing-one"
    key = mod.DL_TOKEN_KEY_T.format(token=token)
    assert key not in _fake_redis.storage

    r = await async_client.get(f"{BASE}/delivery/download/{token}", params={"redirect": "false"})
    assert r.status_code == 404
    assert r.json()["detail"] == "Token not found or expired"


@pytest.mark.anyio
async def test_redeem_missing_storage_key(async_client, _fake_redis, _fake_s3_ok, monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    token = "bad-payload"
    key = mod.DL_TOKEN_KEY_T.format(token=token)
    _fake_redis.storage[key] = {"one_time": True}  # no storage_key

    r = await async_client.get(f"{BASE}/delivery/download/{token}", params={"redirect": "false"})
    assert r.status_code == 400
    assert r.json()["detail"] == "Token missing storage_key"
    # deletion still attempted
    assert key in _fake_redis.deleted


@pytest.mark.anyio
async def test_redeem_s3_error(async_client, _fake_redis, monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod
    from app.utils.aws import S3StorageError

    token = "tok-s3-fail"
    key = mod.DL_TOKEN_KEY_T.format(token=token)
    _fake_redis.storage[key] = {"storage_key": "secure/asset.bin", "one_time": True}

    class _FakeS3Fail:
        def presigned_get(self, *args, **kwargs):
            raise S3StorageError("signing failed")

    monkeypatch.setattr(mod, "_ensure_s3", lambda: _FakeS3Fail(), raising=True)

    r = await async_client.get(f"{BASE}/delivery/download/{token}", params={"redirect": "false"})
    assert r.status_code == 503
    assert r.json()["detail"] == "signing failed"
    # token already deleted before signing
    assert key in _fake_redis.deleted


@pytest.mark.anyio
@pytest.mark.parametrize("bad_ttl", ["59", "3601"])
async def test_redeem_expires_in_validation_422(async_client, _fake_redis, _fake_s3_ok, bad_ttl):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    token = f"tok-badttl-{bad_ttl}"
    key = mod.DL_TOKEN_KEY_T.format(token=token)
    _fake_redis.storage[key] = {"storage_key": "ok.bin", "one_time": True}

    r = await async_client.get(
        f"{BASE}/delivery/download/{token}",
        params={"redirect": "false", "expires_in": bad_ttl},
    )
    assert r.status_code == 422  # FastAPI validation on query param range
