import pytest
from datetime import datetime, timezone
from fastapi import HTTPException

BASE = "/api/v1/admin"


# -----------------------------
# Test doubles / helpers
# -----------------------------
class _FakeRedis:
    def __init__(self):
        self.calls = []

    async def json_set(self, key, data, ttl_seconds=None):
        # record inputs for assertions
        self.calls.append({"key": key, "data": data, "ttl": ttl_seconds})


async def _noop(*args, **kwargs):
    return None


# -----------------------------
# Fixtures
# -----------------------------
@pytest.fixture(autouse=True)
def _patch_admin_auth(monkeypatch):
    """
    Default: make ensure_admin / ensure_mfa no-ops so tests don't need real auth.
    Individual tests override as needed.
    """
    import app.dependencies.admin as admin_mod

    monkeypatch.setattr(admin_mod, "ensure_admin", _noop, raising=True)
    monkeypatch.setattr(admin_mod, "ensure_mfa", _noop, raising=True)


@pytest.fixture(autouse=True)
async def _override_current_user(app):
    """Provide a stable 'current_user' with an id for dependency injection."""
    import uuid as _uuid
    from app.core.security import get_current_user

    uid = _uuid.uuid4()

    async def _test_user_dep():
        class _U:
            id = uid
            is_superuser = True

        return _U()

    app.dependency_overrides[get_current_user] = _test_user_dep
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def _fake_redis(monkeypatch):
    """
    Patch the route module's redis_wrapper to our fake wrapper.
    """
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    r = _FakeRedis()
    # swap the whole wrapper object so tests can tweak methods per-case
    monkeypatch.setattr(mod, "redis_wrapper", r, raising=True)
    return r


# -----------------------------
# Tests
# -----------------------------
@pytest.mark.anyio
async def test_download_token_success(async_client, _fake_redis, monkeypatch):
    """
    Happy path: returns token + expires_at, and writes correct structure to Redis with TTL.
    """
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    ttl = 300
    payload = {"storage_key": "premium/video/master.m3u8", "ttl_seconds": ttl}

    t0 = datetime.now(timezone.utc)
    r = await async_client.post(f"{BASE}/delivery/download-token", json=payload)
    assert r.status_code == 200, r.text

    body = r.json()
    assert "token" in body and "expires_at" in body

    token = body["token"]
    # uuid4().hex → 32 hex chars
    assert isinstance(token, str) and len(token) == 32
    int(token, 16)  # raises if not hex

    # expires_at is close to now() + ttl (allow a few seconds tolerance)
    exp = datetime.fromisoformat(body["expires_at"])
    delta = (exp - t0).total_seconds()
    assert 290 <= delta <= 310  # tolerant window

    # verify Redis write
    assert len(_fake_redis.calls) == 1
    call = _fake_redis.calls[0]
    # key should be formatted using the module's template and the returned token
    expected_key = mod.DL_TOKEN_KEY_T.format(token=token)
    assert call["key"] == expected_key
    assert call["ttl"] == ttl

    data = call["data"]
    assert data["storage_key"] == payload["storage_key"]
    assert data["one_time"] is True
    # issued_by must be a string uuid matching our injected user id
    assert isinstance(data["issued_by"], str) and len(data["issued_by"]) > 0
    assert data["expires_at"] == body["expires_at"]


@pytest.mark.anyio
async def test_download_token_redis_error(async_client, _fake_redis, monkeypatch):
    """
    If Redis fails on json_set, the route should return 503 with a helpful message.
    """
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    async def boom(*args, **kwargs):
        raise RuntimeError("redis is down")

    monkeypatch.setattr(mod.redis_wrapper, "json_set", boom, raising=True)

    r = await async_client.post(
        f"{BASE}/delivery/download-token",
        json={"storage_key": "x/y/z.bin", "ttl_seconds": 60},
    )
    assert r.status_code == 503
    assert r.json()["detail"] == "Could not store token"


@pytest.mark.anyio
async def test_download_token_auth_forbidden(async_client, monkeypatch, _fake_redis):
    """
    If ensure_admin denies, the route must propagate a 403.
    """
    import app.dependencies.admin as admin_mod

    async def _deny(*_, **__):
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(admin_mod, "ensure_admin", _deny, raising=True)

    r = await async_client.post(
        f"{BASE}/delivery/download-token",
        json={"storage_key": "x.bin", "ttl_seconds": 60},
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "forbidden"


@pytest.mark.anyio
async def test_download_token_mfa_required(async_client, monkeypatch, _fake_redis):
    """
    If ensure_mfa rejects, surface its status code and message (e.g., 401).
    """
    import app.dependencies.admin as admin_mod

    async def _deny_mfa(*_, **__):
        raise HTTPException(status_code=401, detail="mfa required")

    monkeypatch.setattr(admin_mod, "ensure_mfa", _deny_mfa, raising=True)

    r = await async_client.post(
        f"{BASE}/delivery/download-token",
        json={"storage_key": "secure.dat", "ttl_seconds": 120},
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "mfa required"


@pytest.mark.anyio
async def test_download_token_validation_422(async_client, _fake_redis):
    """
    Missing required fields should yield 422 from pydantic validation.
    (Assumes DownloadTokenIn requires storage_key and ttl_seconds.)
    """
    r = await async_client.post(f"{BASE}/delivery/download-token", json={})
    assert r.status_code == 422
