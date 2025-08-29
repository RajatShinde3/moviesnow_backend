# tests/test_auth/test_trusted_devices.py
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

import pytest
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport

from app.api.v1.routers.auth import trusted_devices as td
from app.core.dependencies import get_async_db
from app.core.security import create_access_token
from tests.fixtures.db import get_override_get_db

pytestmark = pytest.mark.anyio

# ──────────────────────────────────────────────────────────────────────────────
# Minimal in-memory Redis fake with the subset used by the router (incl. ZSETs)
# ──────────────────────────────────────────────────────────────────────────────
class FakeRedis:
    def __init__(self) -> None:
        self.kv: Dict[str, Any] = {}
        self.ttl: Dict[str, Optional[float]] = {}
        self.hashes: Dict[str, Dict[str, Any]] = {}
        self.zsets: Dict[str, Dict[str, float]] = {}

    # time helpers
    def _now(self) -> float:
        return asyncio.get_event_loop().time()

    def _expired(self, k: str) -> bool:
        exp = self.ttl.get(k)
        return exp is not None and exp <= self._now()

    async def _purge(self):
        for k in list(self.kv.keys()):
            if self._expired(k):
                self.kv.pop(k, None); self.ttl.pop(k, None)
        for k in list(self.hashes.keys()):
            if self._expired(k):
                self.hashes.pop(k, None); self.ttl.pop(k, None)
        for k in list(self.zsets.keys()):
            if self._expired(k):
                self.zsets.pop(k, None); self.ttl.pop(k, None)

    # KV
    async def get(self, key: str):
        await self._purge()
        return self.kv.get(key)

    async def set(self, key: str, value: Any, ex: int | None = None, px: int | None = None, nx: bool = False, **_):
        await self._purge()
        exists = key in self.kv and not self._expired(key)
        if nx and exists:
            return False
        self.kv[key] = value
        if ex is not None:
            self.ttl[key] = self._now() + int(ex)
        elif px is not None:
            self.ttl[key] = self._now() + (int(px) / 1000)
        else:
            self.ttl[key] = None
        return True

    async def setex(self, key: str, secs: int, value: Any):
        return await self.set(key, value, ex=secs)

    async def expire(self, key: str, secs: int):
        if key in self.kv or key in self.hashes or key in self.zsets:
            self.ttl[key] = self._now() + int(secs)
            return True
        return False

    async def incr(self, key: str, amount: int = 1) -> int:
        await self._purge()
        cur = int(self.kv.get(key, 0)) + int(amount)
        self.kv[key] = cur
        return cur

    async def delete(self, *keys: str) -> int:
        removed = 0
        for k in keys:
            removed += int(self.kv.pop(k, None) is not None)
            removed += int(self.hashes.pop(k, None) is not None)
            self.ttl.pop(k, None)
            z = self.zsets.pop(k, None)
            if z is not None:
                removed += 1
        return removed

    # Hashes
    async def hset(self, name: str, mapping: Dict[str, Any] | None = None, **kwargs):
        await self._purge()
        h = self.hashes.setdefault(name, {})
        data = {}
        if mapping: data.update(mapping)
        if kwargs: data.update(kwargs)
        added = 0
        for k, v in data.items():
            if k not in h: added += 1
            h[k] = v
        return added

    async def hget(self, name: str, key: str):
        await self._purge()
        return self.hashes.get(name, {}).get(key)

    async def hgetall(self, name: str) -> Dict[str, Any]:
        await self._purge()
        return dict(self.hashes.get(name, {}))

    # ZSETs (score: float, member: str)
    async def zadd(self, key: str, mapping: Dict[str, float]):
        await self._purge()
        z = self.zsets.setdefault(key, {})
        for member, score in mapping.items():
            z[str(member)] = float(score)
        return len(mapping)

    async def zcard(self, key: str) -> int:
        await self._purge()
        return len(self.zsets.get(key, {}))

    def _zrange_core(self, key: str, start: int, end: int, reverse: bool = False) -> List[str]:
        z = self.zsets.get(key, {})
        items = sorted(z.items(), key=lambda kv: kv[1], reverse=reverse)
        if end == -1:
            end = len(items) - 1
        sl = items[start:end + 1] if items else []
        return [m for (m, _) in sl]

    async def zrange(self, key: str, start: int, end: int):
        await self._purge()
        return self._zrange_core(key, start, end, reverse=False)

    async def zrevrange(self, key: str, start: int, end: int):
        await self._purge()
        return self._zrange_core(key, start, end, reverse=True)

    async def zrem(self, key: str, *members: str) -> int:
        await self._purge()
        z = self.zsets.get(key, {})
        before = len(z)
        for m in members:
            z.pop(str(m), None)
        return before - len(z)

    # Lua (rate-limit INCR + first-hit EXPIRE)
    async def eval(self, script: str, *args, **kwargs):
        if "keys" in kwargs or "args" in kwargs:
            keys = list(kwargs.get("keys") or [])
            argv = list(kwargs.get("args") or [])
            key = keys[0]
            ttl = int(argv[0]) if argv else 0
        else:
            _, key, ttl = args
            ttl = int(ttl)
        val = await self.incr(key)
        if val == 1 and ttl > 0:
            await self.expire(key, ttl)
        return val

    async def setnx(self, key: str, value: Any):
        return await self.set(key, value, nx=True)


# ──────────────────────────────────────────────────────────────────────────────
# Test app & common fixtures
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture
async def td_app(db_session):
    app = FastAPI()
    app.include_router(td.router, prefix="/api/v1/auth")
    app.dependency_overrides[get_async_db] = get_override_get_db(db_session)
    return app


@pytest.fixture
async def client(td_app):
    async with AsyncClient(transport=ASGITransport(app=td_app), base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
def patch_audit_log(monkeypatch):
    async def _noop(*_, **__):
        return None
    monkeypatch.setattr(td, "log_audit_event", _noop, raising=False)


@pytest.fixture(autouse=True)
def patch_redis(monkeypatch):
    fake = FakeRedis()
    # Patch the private slot behind the read-only `.client` property
    monkeypatch.setattr(td.redis_wrapper, "_client", fake, raising=False)

    # Async verification helper: validate HMAC, skip Redis revocation lookup
    async def _verify_no_redis(value: str) -> Optional[str]:
        try:
            dev_id, sig = value.split(".", 1)
            expected = td._sign_device_id(dev_id).split(".", 1)[1]
            import hmac as _h
            return dev_id if _h.compare_digest(sig, expected) else None
        except Exception:
            return None

    # Router awaits this function
    monkeypatch.setattr(td, "_verify_signed_device_id", _verify_no_redis, raising=False)
    return fake


async def _auth_headers_for(user_id, *, mfa_authenticated: bool = True) -> Dict[str, str]:
    token = await create_access_token(
        user_id=str(user_id),
        mfa_authenticated=mfa_authenticated,
    )
    return {"Authorization": f"Bearer {token}", "User-Agent": "pytest-UA"}


# Helpers to access module constants/keys
def _dev_key(dev_id: str) -> str:
    return td.TD_DEV_KEY(dev_id)

def _z_key(user_id) -> str:
    return td.TD_Z_KEY(user_id)

def _rev_key(dev_id: str) -> str:
    return td.TD_REV_KEY(dev_id)


# ──────────────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────────────
async def test_register_happy_path_sets_cookie_and_redis(create_test_user, client, patch_redis):
    user = await create_test_user(email="td1@example.com")
    headers = await _auth_headers_for(user.id, mfa_authenticated=True)

    resp = await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["cookie_name"] == td.TD_COOKIE_NAME
    device_id = body["id"]

    # Cookie present and signed
    set_cookie = resp.headers.get("set-cookie", "")
    assert f"{td.TD_COOKIE_NAME}=" in set_cookie
    assert await td._verify_signed_device_id(client.cookies.get(td.TD_COOKIE_NAME)) == device_id

    # Redis: device hash + user zset entry exist
    meta = await patch_redis.hgetall(_dev_key(device_id))
    assert meta.get("user_id") == str(user.id)
    assert await patch_redis.zcard(_z_key(user.id)) == 1


async def test_register_requires_fresh_mfa(create_test_user, client):
    user = await create_test_user(email="td2@example.com")
    headers = await _auth_headers_for(user.id, mfa_authenticated=False)  # ❌ not fresh
    resp = await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers)
    assert resp.status_code == 401
    assert resp.json()["detail"].lower().startswith("mfa")


async def test_register_idempotent_refresh_extends_expiry(create_test_user, client, patch_redis):
    user = await create_test_user(email="td3@example.com")
    headers = await _auth_headers_for(user.id, mfa_authenticated=True)

    r1 = await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers)
    assert r1.status_code == 200
    did = r1.json()["id"]
    before = (await patch_redis.hgetall(_dev_key(did)))["expires_at"]

    # Ensure the cookie is actually sent on the next request
    cookie_val = td._sign_device_id(did)
    client.cookies.set(td.TD_COOKIE_NAME, cookie_val, domain="test", path="/")
    headers_with_cookie = {**headers, "Cookie": f"{td.TD_COOKIE_NAME}={cookie_val}"}

    # Second call reuses cookie, refreshes expiry
    r2 = await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers_with_cookie)
    assert r2.status_code == 200
    assert r2.json()["id"] == did
    after = (await patch_redis.hgetall(_dev_key(did)))["expires_at"]

    dt_before = datetime.fromisoformat(before)
    dt_after = datetime.fromisoformat(after)
    assert dt_after > dt_before


async def test_list_devices_shows_hashed_ua_and_masked_ip(create_test_user, client):
    user = await create_test_user(email="td4@example.com")
    headers = await _auth_headers_for(user.id, mfa_authenticated=True)
    await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers)

    resp = await client.get("/api/v1/auth/mfa/trusted-devices", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    item = body["devices"][0]
    assert item["ua_hash"] and isinstance(item["ua_hash"], str)
    assert isinstance(item["ip"], str)


async def test_list_cleans_up_expired_records(create_test_user, client, patch_redis):
    user = await create_test_user(email="td5@example.com")
    headers = await _auth_headers_for(user.id, mfa_authenticated=True)
    r = await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers)
    did = r.json()["id"]

    meta = await patch_redis.hgetall(_dev_key(did))
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    meta["expires_at"] = past
    await patch_redis.hset(_dev_key(did), mapping=meta)

    resp = await client.get("/api/v1/auth/mfa/trusted-devices", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 0
    assert await patch_redis.zcard(_z_key(user.id)) == 0


async def test_revoke_single_device_and_clear_cookie(create_test_user, client, patch_redis):
    user = await create_test_user(email="td6@example.com")
    headers = await _auth_headers_for(user.id, mfa_authenticated=True)
    r = await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers)
    did = r.json()["id"]

    # Present the cookie so the server clears it in the response
    cookie_val = td._sign_device_id(did)
    client.cookies.set(td.TD_COOKIE_NAME, cookie_val, domain="test", path="/")
    headers_with_cookie = {**headers, "Cookie": f"{td.TD_COOKIE_NAME}={cookie_val}"}

    resp = await client.delete(f"/api/v1/auth/mfa/trusted-devices/{did}", headers=headers_with_cookie)
    assert resp.status_code == 200
    assert resp.json()["revoked"] == 1
    assert await patch_redis.hget(_dev_key(did), "user_id") is None
    assert await patch_redis.get(_rev_key(did)) == "revoked"

    set_cookie = resp.headers.get("set-cookie", "")
    assert f"{td.TD_COOKIE_NAME}=" in set_cookie and ("Max-Age=0" in set_cookie or "Expires=" in set_cookie)


async def test_revoke_forbidden_on_foreign_device(create_test_user, client):
    user_a = await create_test_user(email="td7a@example.com")
    headers_a = await _auth_headers_for(user_a.id, mfa_authenticated=True)
    r = await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers_a)
    did = r.json()["id"]

    user_b = await create_test_user(email="td7b@example.com")
    headers_b = await _auth_headers_for(user_b.id, mfa_authenticated=True)
    resp = await client.delete(f"/api/v1/auth/mfa/trusted-devices/{did}", headers=headers_b)
    assert resp.status_code == 403


async def test_revoke_nonexistent_returns_zero(create_test_user, client):
    user = await create_test_user(email="td8@example.com")
    headers = await _auth_headers_for(user.id, mfa_authenticated=True)
    resp = await client.delete("/api/v1/auth/mfa/trusted-devices/does-not-exist", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["revoked"] == 0


async def test_revoke_all_clears_inventory_and_cookie(create_test_user, client, patch_redis):
    user = await create_test_user(email="td9@example.com")
    headers = await _auth_headers_for(user.id, mfa_authenticated=True)

    r1 = await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers)
    did1 = r1.json()["id"]
    client.cookies.clear()
    r2 = await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers)
    did2 = r2.json()["id"]

    assert did1 != did2
    assert await patch_redis.zcard(_z_key(user.id)) == 2

    resp = await client.delete("/api/v1/auth/mfa/trusted-devices", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["revoked"] == 2
    assert await patch_redis.zcard(_z_key(user.id)) == 0

    set_cookie = resp.headers.get("set-cookie", "")
    assert f"{td.TD_COOKIE_NAME}=" in set_cookie and ("Max-Age=0" in set_cookie or "Expires=" in set_cookie)


async def test_tampered_cookie_does_not_refresh_creates_new_device(create_test_user, client):
    user = await create_test_user(email="td10@example.com")
    headers = await _auth_headers_for(user.id, mfa_authenticated=True)

    r1 = await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers)
    did1 = r1.json()["id"]

    # Tamper cookie signature (flip a char)
    raw = client.cookies.get(td.TD_COOKIE_NAME)
    assert raw
    tampered = raw[:-1] + ("A" if raw[-1] != "A" else "B")
    client.cookies.set(td.TD_COOKIE_NAME, tampered, domain="test", path="/")
    headers_with_cookie = {**headers, "Cookie": f"{td.TD_COOKIE_NAME}={tampered}"}

    r2 = await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers_with_cookie)
    did2 = r2.json()["id"]
    assert did2 != did1  # not refreshed; new device created


async def test_samesite_none_forces_secure_flag(monkeypatch, create_test_user, client):
    # Patch helpers instead of Pydantic settings
    monkeypatch.setattr(td, "_normalize_samesite", lambda v: "none", raising=False)
    monkeypatch.setattr(td, "_require_secure_if_none", lambda s: True, raising=False)

    user = await create_test_user(email="td11@example.com")
    headers = await _auth_headers_for(user.id, mfa_authenticated=True)

    resp = await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers)
    set_cookie = resp.headers.get("set-cookie", "")
    s = set_cookie.lower()
    assert "samesite=none" in s and "secure" in s


async def test_evicts_oldest_when_over_cap(monkeypatch, create_test_user, client, patch_redis):
    monkeypatch.setattr(td, "TD_MAX_DEVICES", 3, raising=False)

    user = await create_test_user(email="td12@example.com")
    headers = await _auth_headers_for(user.id, mfa_authenticated=True)

    created: List[str] = []
    for _ in range(4):
        client.cookies.clear()
        r = await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers)
        created.append(r.json()["id"])
        await asyncio.sleep(0.01)

    assert await patch_redis.zcard(_z_key(user.id)) == 3
    oldest = created[0]
    assert await patch_redis.hget(_dev_key(oldest), "user_id") is None
    assert await patch_redis.get(_rev_key(oldest)) == "revoked"


async def test_registration_user_budget_enforced_with_429(create_test_user, client):
    user = await create_test_user(email="td13@example.com")
    headers = await _auth_headers_for(user.id, mfa_authenticated=True)

    r0 = await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers)
    assert r0.status_code == 200

    ok = 0
    for _ in range(25):
        r = await client.post("/api/v1/auth/mfa/trusted-devices/register", headers=headers)
        if r.status_code == 200:
            ok += 1
        else:
            assert r.status_code == 429
            break
    assert ok < 22
