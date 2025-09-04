# tests/test_admin/test_auth/test_admin_login.py

import importlib
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Minimal fake async DB that returns canned rows for .execute()
# ─────────────────────────────────────────────────────────────────────────────

class _Result:
    def __init__(self, row: Any | None):
        self._row = row
    def scalar_one_or_none(self):
        return self._row

class FakeDB:
    """Provide one result for the single SELECT in login."""
    def __init__(self, row: Any | None):
        self._row = row
        self.exec_calls: int = 0
        self.last_query = None

    async def execute(self, query, *_a, **_k):
        self.exec_calls += 1
        self.last_query = query
        return _Result(self._row)


# Simple user stub with the attributes the route reads
class UserRow:
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        email: str = "admin@example.com",
        hashed_password: str = "HASH",
        is_verified: bool = True,
        is_active: bool = True,
        mfa_enabled: bool = True,
        totp_secret: Optional[str] = "BASE32SECRET",
    ):
        self.id = id or uuid.uuid4()
        self.email = email
        self.hashed_password = hashed_password
        self.is_verified = is_verified
        self.is_active = is_active
        self.mfa_enabled = mfa_enabled
        self.totp_secret = totp_secret


# ─────────────────────────────────────────────────────────────────────────────
# Test app factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    db_row: Any | None,
    verify_password_impl: Optional[Callable[[str, str], bool]] = None,
    create_refresh_impl: Optional[Callable[[uuid.UUID], Dict[str, Any]]] = None,
    create_access_impl: Optional[Callable[..., str]] = None,
    store_refresh_impl: Optional[Callable[..., Any]] = None,
    is_admin_impl: Optional[Callable[[Any], bool]] = None,
    now_dt: Optional[datetime] = None,
):
    mod = importlib.import_module("app.api.v1.routers.admin.auth")

    # Disable SlowAPI via env (belt-and-suspenders)
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Fix now for stable JWT timestamps
    monkeypatch.setattr(mod, "_now_utc", lambda: (now_dt or datetime(2025, 1, 1, tzinfo=timezone.utc)), raising=False)

    # Settings used by the route
    class _Secret:
        def get_secret_value(self): return "secret"
    monkeypatch.setattr(mod.settings, "JWT_SECRET_KEY", _Secret(), raising=False)
    monkeypatch.setattr(mod.settings, "JWT_ALGORITHM", "HS256", raising=False)
    monkeypatch.setattr(mod.settings, "ADMIN_LOGIN_NEUTRAL_ERRORS", True, raising=False)
    monkeypatch.setattr(mod.settings, "ADMIN_REQUIRE_MFA", True, raising=False)
    if hasattr(mod.settings, "JWT_ISSUER"):
        monkeypatch.setattr(mod.settings, "JWT_ISSUER", None, raising=False)
    if hasattr(mod.settings, "JWT_AUDIENCE"):
        monkeypatch.setattr(mod.settings, "JWT_AUDIENCE", None, raising=False)

    # Auth helpers
    monkeypatch.setattr(mod, "verify_password", verify_password_impl or (lambda p, h: p == "correct"), raising=False)
    monkeypatch.setattr(mod, "_is_admin", is_admin_impl or (lambda _u: True), raising=False)

    # Async token & session helpers (the route awaits these)
    async def _default_create_refresh(_uid: uuid.UUID) -> Dict[str, Any]:
        return {"token": "refresh123", "jti": "jti123", "expires_at": "2099-01-01T00:00:00Z"}

    async def _default_register_session_and_meta(*_a, **_k):
        return None

    async def _default_create_access(**_k) -> str:
        return "access123"

    async def _default_push_activity(*_a, **_k):
        return None

    async def _default_audit(*_a, **_k):
        return None

    monkeypatch.setattr(mod, "create_refresh_token", create_refresh_impl or _default_create_refresh, raising=False)
    monkeypatch.setattr(mod, "_register_session_and_meta", _default_register_session_and_meta, raising=False)
    monkeypatch.setattr(mod, "create_access_token", create_access_impl or _default_create_access, raising=False)
    monkeypatch.setattr(mod, "_push_activity_event", _default_push_activity, raising=False)
    monkeypatch.setattr(mod, "log_audit_event", _default_audit, raising=False)

    # store_refresh_token is imported inside the handler from app.services.token_service
    token_service_mod = importlib.import_module("app.services.token_service")
    async def _default_store_refresh_token(**_k): return None
    monkeypatch.setattr(token_service_mod, "store_refresh_token", store_refresh_impl or _default_store_refresh_token, raising=False)

    # Redis utils (rate limits + idempotency)
    rl_calls: List[Tuple[str, int, int]] = []
    idem_sets: List[Tuple[str, Dict[str, Any], int]] = []
    idem_get_value: Dict[str, Any] | None = None  # mutable via closure

    async def _enforce_rate_limit(key_suffix: str, seconds: int, max_calls: int, error_message: str):
        rl_calls.append((key_suffix, seconds, max_calls))

    async def _idempotency_get(_k: str):
        return idem_get_value

    async def _idempotency_set(k: str, v: Dict[str, Any], ttl_seconds: int):
        idem_sets.append((k, v, ttl_seconds))

    monkeypatch.setattr(mod.redis_utils, "enforce_rate_limit", _enforce_rate_limit, raising=False)
    monkeypatch.setattr(mod.redis_utils, "idempotency_get", _idempotency_get, raising=False)
    monkeypatch.setattr(mod.redis_utils, "idempotency_set", _idempotency_set, raising=False)

    # Build app and wire DB dependency
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    app.dependency_overrides[mod.get_async_db] = lambda: FakeDB(db_row)

    # ---- Neutralize the SlowAPI rate-limit wrapper on this specific route ----
    # We unwrap the decorated endpoint and recompile the handler to bypass 429s.
    login_path = "/api/v1/admin/login"
    for route in app.routes:
        if getattr(route, "path", None) == login_path and "POST" in getattr(route, "methods", set()):
            fn = route.endpoint
            # peel functools.wraps layers if present
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn
            # Starlette needs the handler recompiled
            if hasattr(route, "app") and hasattr(route, "get_route_handler"):
                route.app = route.get_route_handler()
            break

    client = TestClient(app)
    # expose mutable state to tests
    return app, client, mod, {"rl_calls": rl_calls, "idem_sets": idem_sets, "set_idem_get": lambda v: locals().update(idem_get_value=v)}


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_login_mfa_challenge_happy_path_and_no_store(monkeypatch):
    user = UserRow(mfa_enabled=True, is_verified=True, is_active=True)
    app, client, mod, state = _mk_app(monkeypatch, db_row=user)

    r = client.post("/api/v1/admin/login", json={"email": "Admin@Example.Com", "password": "correct"},
                    headers={"Idempotency-Key": "k1"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "mfa_token" in body and isinstance(body["mfa_token"], str)

    # cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # rate limits called for email and IP
    keys = [k for (k, *_rest) in state["rl_calls"]]
    assert any(k.startswith("adminlogin:email:") for k in keys)
    assert any(k.startswith("adminlogin:ip:") for k in keys)

    # idempotency snapshot saved with TTL 600
    k, snap, ttl = state["idem_sets"][-1]
    assert k == "idem:adminlogin:k1"
    assert ttl == 600
    assert "mfa_token" in snap


def test_login_token_happy_path_when_mfa_not_required(monkeypatch):
    user = UserRow(mfa_enabled=False, is_verified=True, is_active=True)
    app, client, mod, state = _mk_app(monkeypatch, db_row=user)
    # Turn off policy requirement
    monkeypatch.setattr(mod.settings, "ADMIN_REQUIRE_MFA", False, raising=False)

    r = client.post("/api/v1/admin/login", json={"email": "admin@example.com", "password": "correct"},
                    headers={"Idempotency-Key": "keyz"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_token"] == "access123"
    assert body["refresh_token"] == "refresh123"
    assert body["token_type"] == "bearer"

    k, snap, ttl = state["idem_sets"][-1]
    assert k == "idem:adminlogin:keyz"
    assert ttl == 600
    assert "access_token" in snap and "refresh_token" in snap


def test_login_user_not_found_neutral_error(monkeypatch):
    app, client, mod, _ = _mk_app(monkeypatch, db_row=None)
    r = client.post("/api/v1/admin/login", json={"email": "x@example.com", "password": "whatever"})
    assert r.status_code == 401
    assert "Invalid email or password" in r.text


def test_login_invalid_password_neutral_error(monkeypatch):
    user = UserRow()
    app, client, mod, _ = _mk_app(monkeypatch, db_row=user, verify_password_impl=lambda p, h: False)
    r = client.post("/api/v1/admin/login", json={"email": "admin@example.com", "password": "wrong"})
    assert r.status_code == 401
    assert "Invalid email or password" in r.text


@pytest.mark.parametrize("neutral,expected_status,expected_detail", [
    (True, 401, "Invalid email or password"),
    (False, 403, "Email not verified"),
])
def test_login_unverified_account(monkeypatch, neutral, expected_status, expected_detail):
    user = UserRow(is_verified=False, is_active=True, mfa_enabled=True)
    app, client, mod, _ = _mk_app(monkeypatch, db_row=user)
    monkeypatch.setattr(mod.settings, "ADMIN_LOGIN_NEUTRAL_ERRORS", neutral, raising=False)

    r = client.post("/api/v1/admin/login", json={"email": "admin@example.com", "password": "correct"})
    assert r.status_code == expected_status
    assert expected_detail in r.text


@pytest.mark.parametrize("neutral,expected_status,expected_detail", [
    (True, 401, "Invalid email or password"),
    (False, 403, "Account is deactivated"),
])
def test_login_deactivated_account(monkeypatch, neutral, expected_status, expected_detail):
    user = UserRow(is_verified=True, is_active=False, mfa_enabled=True)
    app, client, mod, _ = _mk_app(monkeypatch, db_row=user)
    monkeypatch.setattr(mod.settings, "ADMIN_LOGIN_NEUTRAL_ERRORS", neutral, raising=False)

    r = client.post("/api/v1/admin/login", json={"email": "admin@example.com", "password": "correct"})
    assert r.status_code == expected_status
    assert expected_detail in r.text


def test_login_rbac_non_admin_neutral_error(monkeypatch):
    user = UserRow()
    app, client, mod, _ = _mk_app(monkeypatch, db_row=user, is_admin_impl=lambda _u: False)
    r = client.post("/api/v1/admin/login", json={"email": "admin@example.com", "password": "correct"})
    assert r.status_code == 401
    assert "Invalid email or password" in r.text


def test_login_policy_requires_mfa_but_user_mfa_disabled(monkeypatch):
    user = UserRow(mfa_enabled=False)
    app, client, mod, _ = _mk_app(monkeypatch, db_row=user)
    r = client.post("/api/v1/admin/login", json={"email": "admin@example.com", "password": "correct"})
    assert r.status_code == 403
    assert "MFA required for admin login" in r.text


def test_login_idempotency_replay_token_response(monkeypatch):
    user = UserRow(mfa_enabled=False)
    app, client, mod, state = _mk_app(monkeypatch, db_row=user)
    monkeypatch.setattr(mod.settings, "ADMIN_REQUIRE_MFA", False, raising=False)

    async def _idem_get(_k): return {"access_token": "A", "refresh_token": "R", "token_type": "bearer"}
    monkeypatch.setattr(mod.redis_utils, "idempotency_get", _idem_get, raising=False)

    r = client.post("/api/v1/admin/login", json={"email": "admin@example.com", "password": "correct"},
                    headers={"Idempotency-Key": "same"})
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"] == "A" and body["refresh_token"] == "R" and body["token_type"] == "bearer"


def test_login_idempotency_replay_mfa_response(monkeypatch):
    user = UserRow(mfa_enabled=True)
    app, client, mod, state = _mk_app(monkeypatch, db_row=user)

    async def _idem_get(_k): return {"mfa_token": "MFAT"}
    monkeypatch.setattr(mod.redis_utils, "idempotency_get", _idem_get, raising=False)

    r = client.post("/api/v1/admin/login", json={"email": "admin@example.com", "password": "correct"},
                    headers={"Idempotency-Key": "same"})
    assert r.status_code == 200
    assert "mfa_token" in r.json()


def test_login_rate_limit_and_idempotency_errors_are_swallowed(monkeypatch):
    user = UserRow()
    app, client, mod, state = _mk_app(monkeypatch, db_row=user)

    async def _rl_boom(*_a, **_k): raise RuntimeError("rl down")
    async def _idem_boom(*_a, **_k): raise RuntimeError("idem down")
    monkeypatch.setattr(mod.redis_utils, "enforce_rate_limit", _rl_boom, raising=False)
    monkeypatch.setattr(mod.redis_utils, "idempotency_get", _idem_boom, raising=False)

    r = client.post("/api/v1/admin/login", json={"email": "admin@example.com", "password": "correct"})
    assert r.status_code == 200
    assert "mfa_token" in r.json()
