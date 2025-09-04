import re
import pytest
from datetime import datetime as real_datetime, timezone, timedelta

BASE = "/api/v1/admin"


# -----------------------------
# Fakes / helpers
# -----------------------------
class _FixedDT(real_datetime):
    """Freeze datetime.now() used inside the route for deterministic expires_at."""
    @classmethod
    def now(cls, tz=None):
        return real_datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


class _FakeRedisOK:
    def __init__(self):
        self.set_calls = []
        self.store = {}

    async def json_set(self, key, data, ttl_seconds):
        # Record calls and stash values by key
        self.set_calls.append((key, data, ttl_seconds))
        self.store[key] = {"value": data, "ttl": ttl_seconds}


class _FakeRedisWithFault:
    def __init__(self, boom_storage_key: str):
        self.boom_storage_key = boom_storage_key
        self.set_calls = []

    async def json_set(self, key, data, ttl_seconds):
        self.set_calls.append((key, data, ttl_seconds))
        if data.get("storage_key") == self.boom_storage_key:
            raise RuntimeError("redis write failed")
# -----------------------------
# Shared stubs
# -----------------------------
async def _noop(*args, **kwargs):
    return None

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

def _expect_iso_at(base_dt: real_datetime, seconds: int) -> str:
    return (base_dt + timedelta(seconds=seconds)).isoformat()


def _is_token(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{32}", s))


# -----------------------------
# Fixtures
# -----------------------------
@pytest.fixture
def _patch_datetime(monkeypatch):
    """Patch the module's datetime class so expires_at is deterministic."""
    import app.api.v1.routers.admin.assets.cdn_delivery as mod
    monkeypatch.setattr(mod, "datetime", _FixedDT, raising=True)
    return _FixedDT.now(timezone.utc)


@pytest.fixture
def _fake_redis_ok(monkeypatch):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod
    r = _FakeRedisOK()
    monkeypatch.setattr(mod, "redis_wrapper", r, raising=True)
    return r


# -----------------------------
# Tests
# -----------------------------
@pytest.mark.anyio
async def test_batch_tokens_success_multiple(async_client, _fake_redis_ok, _patch_datetime):
    # Two items with different TTLs → different expires_at values
    payload = {
        "items": [
            {"storage_key": "s3/private/a.mp4", "ttl_seconds": 300},
            {"storage_key": "s3/private/b.jpg", "ttl_seconds": 90},
            {"storage_key": "s3/private/c.zip", "ttl_seconds": 1200},
        ]
    }

    r = await async_client.post(f"{BASE}/delivery/download-tokens/batch", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "results" in body and len(body["results"]) == 3

    # Each result has a token and correct expires_at (based on frozen time)
    now_fixed = _patch_datetime
    expected = [
        _expect_iso_at(now_fixed, 300),
        _expect_iso_at(now_fixed, 90),
        _expect_iso_at(now_fixed, 1200),
    ]
    tokens = []
    for idx, res in enumerate(body["results"]):
        assert res["storage_key"] == payload["items"][idx]["storage_key"]
        assert res["expires_at"] == expected[idx]
        assert _is_token(res["token"])
        tokens.append(res["token"])

    # Tokens should be unique
    assert len(set(tokens)) == len(tokens)

    # Redis got one json_set per item with the right TTL
    assert len(_fake_redis_ok.set_calls) == 3
    for call, item in zip(_fake_redis_ok.set_calls, payload["items"]):
        _key, data, ttl = call
        assert data["storage_key"] == item["storage_key"]
        assert data["one_time"] is True
        assert isinstance(data.get("issued_by"), str)
        assert ttl == item["ttl_seconds"]


@pytest.mark.anyio
async def test_batch_tokens_no_items_400(async_client, _fake_redis_ok):
    r = await async_client.post(f"{BASE}/delivery/download-tokens/batch", json={"items": []})
    assert r.status_code == 400
    assert r.json()["detail"] == "No items provided"


@pytest.mark.anyio
async def test_batch_tokens_too_many_items_400(async_client, _fake_redis_ok):
    # 101 items (limit is 100)
    big_list = [{"storage_key": f"s3/obj/{i}", "ttl_seconds": 120} for i in range(101)]
    r = await async_client.post(f"{BASE}/delivery/download-tokens/batch", json={"items": big_list})
    assert r.status_code == 400
    assert r.json()["detail"] == "Too many items (max 100)"


@pytest.mark.anyio
async def test_batch_tokens_partial_failure(async_client, monkeypatch, _patch_datetime):
    import app.api.v1.routers.admin.assets.cdn_delivery as mod

    # Make Redis fail for one specific item; others should still succeed.
    boom_key = "s3/private/broken.mov"
    rfake = _FakeRedisWithFault(boom_storage_key=boom_key)
    monkeypatch.setattr(mod, "redis_wrapper", rfake, raising=True)

    payload = {
        "items": [
            {"storage_key": "s3/private/ok1.m4v", "ttl_seconds": 60},
            {"storage_key": boom_key, "ttl_seconds": 300},
            {"storage_key": "s3/private/ok2.png", "ttl_seconds": 180},
        ]
    }

    r = await async_client.post(f"{BASE}/delivery/download-tokens/batch", json=payload)
    assert r.status_code == 200
    results = r.json()["results"]
    assert len(results) == 3

    # First and last succeed with tokens; middle has an error
    assert _is_token(results[0]["token"])
    assert results[0]["storage_key"] == "s3/private/ok1.m4v"
    assert "error" not in results[0]

    assert results[1]["storage_key"] == boom_key
    assert "error" in results[1]
    assert "redis write failed" in results[1]["error"]

    assert _is_token(results[2]["token"])
    assert results[2]["storage_key"] == "s3/private/ok2.png"
    assert "error" not in results[2]
