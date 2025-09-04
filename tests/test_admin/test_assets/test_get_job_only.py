# tests/test_admin/test_bulk/test_get_job_only.py
import uuid
import pytest
from typing import Any, Dict, List

BASE = "/api/v1/admin"

# ─────────────────────────────────────────────────────────────────────────────
# Minimal in-memory Redis fakes (same style as list-jobs tests)
# ─────────────────────────────────────────────────────────────────────────────

class _FakeRedisClient:
    def __init__(self):
        self.kv: Dict[str, Any] = {}
        self.sets: Dict[str, set] = {}
        self.lists: Dict[str, List[str]] = {}

    async def sadd(self, key: str, member: str) -> int:
        s = self.sets.setdefault(key, set())
        before = len(s)
        s.add(member)
        return 1 if len(s) > before else 0

    async def smembers(self, key: str):
        return self.sets.get(key, set())

    async def rpush(self, key: str, value: str) -> int:
        self.lists.setdefault(key, []).append(value)
        return len(self.lists[key])


class _FakeRedisWrapper:
    def __init__(self):
        self.client = _FakeRedisClient()
        self._idem: Dict[str, Any] = {}

    async def json_set(self, key: str, value: Any, ttl_seconds: int | None = None):
        self.client.kv[key] = value

    async def json_get(self, key: str, default: Any | None = None):
        return self.client.kv.get(key, default)

    async def idempotency_get(self, key: str):
        return self._idem.get(key)

    async def idempotency_set(self, key: str, value: Any, ttl_seconds: int | None = None):
        self._idem[key] = value


# ─────────────────────────────────────────────────────────────────────────────
# Global fixtures: admin/MFA no-ops, user override, audit no-op, Redis fake
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _mock_admin_mfa(monkeypatch):
    import app.dependencies.admin as admin_deps
    async def _noop(*_a, **_k): return None
    monkeypatch.setattr(admin_deps, "ensure_admin", _noop)
    monkeypatch.setattr(admin_deps, "ensure_mfa", _noop)


@pytest.fixture(autouse=True)
async def _override_current_user(app):
    from app.core.security import get_current_user
    async def _dep():
        class _U:
            id = uuid.UUID("00000000-0000-0000-0000-000000000001")
            is_superuser = True
        return _U()
    app.dependency_overrides[get_current_user] = _dep
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch):
    # Route doesn't log, but keep this to avoid accidental audit side effects
    import app.services.audit_log_service as als
    async def _noop(**_k): return None
    monkeypatch.setattr(als, "log_audit_event", _noop)


@pytest.fixture(autouse=True)
def _fake_redis(monkeypatch):
    fake = _FakeRedisWrapper()

    # Bind both where it's defined and where it's imported into the router
    import app.core.redis_client as rc
    monkeypatch.setattr(rc, "redis_wrapper", fake, raising=True)

    import app.api.v1.routers.admin.assets.bulk as bulk_mod
    monkeypatch.setattr(bulk_mod, "redis_wrapper", fake, raising=True)

    return fake


@pytest.fixture(scope="module")
def _bulk_consts():
    import app.api.v1.routers.admin.assets.bulk as bulk_mod
    return {
        "JOB_KEY_T": bulk_mod.JOB_KEY_T,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _seed_job(fake, consts, job_id: str, **env_overrides):
    key = consts["JOB_KEY_T"].format(job_id=job_id)
    env = {
        "id": job_id,
        "status": "QUEUED",
        "submitted_at_ms": 1,
        **env_overrides,
    }
    await fake.json_set(key, env)
    return env


# ─────────────────────────────────────────────────────────────────────────────
# Tests — GET /bulk/jobs/{job_id}
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_get_job_success_returns_envelope(async_client, _fake_redis, _bulk_consts):
    expected = await _seed_job(_fake_redis, _bulk_consts, "job123", status="RUNNING", submitted_at_ms=9999)
    r = await async_client.get(f"{BASE}/bulk/jobs/job123")
    assert r.status_code == 200
    assert r.json() == expected


@pytest.mark.anyio
async def test_get_job_404_when_missing(async_client):
    r = await async_client.get(f"{BASE}/bulk/jobs/nope")
    assert r.status_code == 404
    assert "Job not found" in r.text


@pytest.mark.anyio
async def test_get_job_redis_exception_bubbles(async_client, _fake_redis, _bulk_consts, monkeypatch):
    # If Redis raises, the route doesn't catch it. Depending on the app's
    # test middleware stack, this may surface as a 500 response OR as a raised
    # exception. Accept either outcome.
    key = _bulk_consts["JOB_KEY_T"].format(job_id="boom")

    async def _boom(_key: str, default=None):
        assert _key == key
        raise RuntimeError("redis down")

    monkeypatch.setattr(_fake_redis, "json_get", _boom, raising=True)

    try:
        r = await async_client.get(f"{BASE}/bulk/jobs/boom")
        # If we get here, middleware converted it to a 500 response.
        assert r.status_code == 500
    except RuntimeError as exc:
        # In this test environment, the exception bubbles out directly.
        assert "redis down" in str(exc)

