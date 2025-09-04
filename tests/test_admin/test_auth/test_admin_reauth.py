# tests/test_admin/test_auth/test_admin_reauth.py

import importlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Callable

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Minimal async DB stub (route only passes it to audit logger)
# ─────────────────────────────────────────────────────────────────────────────

class _Result:
    def __init__(self, row: Any | None): self._row = row
    def scalar_one_or_none(self): return self._row

class FakeDB:
    def __init__(self, row: Any | None = None):
        self._row = row
    async def execute(self, query, *_a, **_k): return _Result(self._row)


# Simple user stub with fields used by the route
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
    current_user: Optional[UserRow] = None,
    is_admin_impl: Optional[Callable[[Any], bool]] = None,
    verify_password_impl: Optional[Callable[[str, str], bool]] = None,
    decode_token_impl: Optional[Callable[..., Dict[str, Any]] | Callable[..., Any]] = None,
    mint_impl: Optional[Callable[..., Tuple[str, int]]] = None,
):
    mod = importlib.import_module("app.api.v1.routers.admin.auth")

    # Bypass rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Stable "now" for any time math (if touched)
    monkeypatch.setattr(mod, "_now_utc", lambda: datetime(2025, 1, 1, tzinfo=timezone.utc), raising=False)

    # Security helpers
    monkeypatch.setattr(mod, "_is_admin", is_admin_impl or (lambda _u: True), raising=False)
    # Password verify (sync)
    monkeypatch.setattr(mod, "verify_password", verify_password_impl or (lambda p, h: p == "correct"), raising=False)

    # Token decode (async, best-effort)
    async def _default_decode_token(_bearer, expected_types=None, verify_revocation=False):
        return {"session_id": "sess-123"}
    monkeypatch.setattr(mod, "decode_token", decode_token_impl or _default_decode_token, raising=False)

    # Bearer extractor can be left as-is; provide header in tests
    # TOTP generator fake (returns object with .verify(code, valid_window))
    class _TotpObj:
        def __init__(self, good: str = "123456", raise_on: Optional[str] = None):
            self.good = good; self.raise_on = raise_on
        def verify(self, code: str, valid_window: int = 1):
            if self.raise_on is not None and code == self.raise_on:
                raise ValueError("bad format")
            return code == self.good

    def _default_generate_totp(secret: str):
        return _TotpObj()
    monkeypatch.setattr(mod, "generate_totp", _default_generate_totp, raising=False)

    # Attempts counters (async) and captures
    incr_calls: List[str] = []
    reset_calls: List[str] = []

    async def increment_attempts(*, key_suffix: str, limit: int, ttl: int):
        incr_calls.append(key_suffix)

    async def reset_attempts(*, key_suffix: str):
        reset_calls.append(key_suffix)

    monkeypatch.setattr(mod, "increment_attempts", increment_attempts, raising=False)
    monkeypatch.setattr(mod, "reset_attempts", reset_attempts, raising=False)

    # Audit (async no-op)
    async def _audit(*_a, **_k): return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Reauth mint (sync)
    def _default_mint(user_id, *, session_id, mfa_authenticated: bool):
        return "reauth_tok", 300
    seen_mint: Dict[str, Any] = {}
    def _mint_wrapped(user_id, *, session_id, mfa_authenticated: bool):
        seen_mint["user_id"] = str(user_id)
        seen_mint["session_id"] = session_id
        seen_mint["mfa_authenticated"] = mfa_authenticated
        return (mint_impl or _default_mint)(user_id, session_id=session_id, mfa_authenticated=mfa_authenticated)
    monkeypatch.setattr(mod, "_mint_admin_reauth_token", _mint_wrapped, raising=False)

    # Settings (ensure they exist for JWT decode path if referenced)
    if hasattr(mod, "settings"):
        if hasattr(mod.settings, "JWT_ISSUER"): monkeypatch.setattr(mod.settings, "JWT_ISSUER", None, raising=False)
        if hasattr(mod.settings, "JWT_AUDIENCE"): monkeypatch.setattr(mod.settings, "JWT_AUDIENCE", None, raising=False)

    # Build app and override deps
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    app.dependency_overrides[mod.get_async_db] = lambda: FakeDB(None)
    app.dependency_overrides[mod.get_current_user] = lambda: (current_user or UserRow())

    # Unwrap SlowAPI decorator to avoid 429s
    path = "/api/v1/admin/reauth"
    for route in app.routes:
        if getattr(route, "path", None) == path and "POST" in getattr(route, "methods", set()):
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):  # peel wraps
                fn = fn.__wrapped__
            route.endpoint = fn
            if hasattr(route, "app") and hasattr(route, "get_route_handler"):
                route.app = route.get_route_handler()
            break

    client = TestClient(app)
    return app, client, mod, {"incr_calls": incr_calls, "reset_calls": reset_calls, "seen_mint": seen_mint}


# ─────────────────────────────────────────────────────────────────────────────
# Tests — password path
# ─────────────────────────────────────────────────────────────────────────────

def test_reauth_password_success_returns_token_and_no_store(monkeypatch):
    user = UserRow(mfa_enabled=False)  # MFA not required for password path
    app, client, mod, st = _mk_app(monkeypatch, current_user=user)

    r = client.post(
        "/api/v1/admin/reauth",
        json={"password": "correct"},
        headers={"Authorization": "Bearer abc"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reauth_token"] == "reauth_tok"
    assert body["expires_in"] == 300

    # cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # counters reset on success (two keys: pw + ip)
    assert any(k.startswith("reauth:admin:pw:") for k in st["reset_calls"])
    assert any(k.startswith("reauth:admin:ip:") for k in st["reset_calls"])

    # session lineage propagated to mint (decode_token default returns session_id)
    assert st["seen_mint"]["session_id"] == "sess-123"
    assert st["seen_mint"]["mfa_authenticated"] is False


def test_reauth_password_bad_password_increments_and_401(monkeypatch):
    user = UserRow()
    app, client, mod, st = _mk_app(monkeypatch, current_user=user, verify_password_impl=lambda _p, _h: False)

    r = client.post("/api/v1/admin/reauth", json={"password": "wrong"})
    assert r.status_code == 401
    assert "Invalid credentials" in r.text

    # counters incremented (pw + ip)
    assert any(k.startswith("reauth:admin:pw:") for k in st["incr_calls"])
    assert any(k.startswith("reauth:admin:ip:") for k in st["incr_calls"])


# ─────────────────────────────────────────────────────────────────────────────
# Tests — TOTP path
# ─────────────────────────────────────────────────────────────────────────────

def test_reauth_totp_success_returns_token_and_resets_attempts(monkeypatch):
    user = UserRow(mfa_enabled=True, totp_secret="S")
    app, client, mod, st = _mk_app(monkeypatch, current_user=user)

    r = client.post(
        "/api/v1/admin/reauth",
        json={"code": "123456"},
        headers={"Authorization": "Bearer abc"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reauth_token"] == "reauth_tok"
    assert body["expires_in"] == 300

    # counters reset (mfa + ip)
    assert any(k.startswith("reauth:admin:mfa:") for k in st["reset_calls"])
    assert any(k.startswith("reauth:admin:ip:") for k in st["reset_calls"])

    # mint called with mfa_authenticated=True
    assert st["seen_mint"]["mfa_authenticated"] is True

def test_reauth_totp_invalid_code_increments_and_400(monkeypatch):
    # Make .verify return False (no parsing error, just an invalid code)
    class _TotpFalse:
        def verify(self, *_a, **_k):
            return False

    def _gen(_secret):
        return _TotpFalse()

    user = UserRow(mfa_enabled=True, totp_secret="S")
    app, client, mod, st = _mk_app(monkeypatch, current_user=user)
    # Force the invalid-code branch
    monkeypatch.setattr(mod, "generate_totp", _gen, raising=False)

    r = client.post(
        "/api/v1/admin/reauth",
        json={"code": "000000"},
        headers={"Authorization": "Bearer test"},
    )
    # The route catches the 401 and re-raises as 400
    assert r.status_code == 400
    assert "Invalid code format" in r.text

    # Counters incremented (mfa + ip)
    assert any(k.startswith("reauth:admin:mfa:") for k in st["incr_calls"])
    assert any(k.startswith("reauth:admin:ip:") for k in st["incr_calls"])


def test_reauth_totp_invalid_code_format_returns_400(monkeypatch):
    class _TotpRaise:
        def verify(self, *_a, **_k): raise ValueError("parse error")
    def _gen(_secret): return _TotpRaise()

    user = UserRow(mfa_enabled=True, totp_secret="S")
    app, client, mod, st = _mk_app(monkeypatch, current_user=user)
    monkeypatch.setattr(mod, "generate_totp", _gen, raising=False)

    r = client.post("/api/v1/admin/reauth", json={"code": "bad-format"})
    assert r.status_code == 400
    assert "Invalid code format" in r.text


def test_reauth_totp_when_mfa_not_enabled_returns_400(monkeypatch):
    user = UserRow(mfa_enabled=False, totp_secret=None)
    app, client, mod, st = _mk_app(monkeypatch, current_user=user)

    r = client.post("/api/v1/admin/reauth", json={"code": "123456"})
    assert r.status_code == 400
    assert "MFA not enabled" in r.text


# ─────────────────────────────────────────────────────────────────────────────
# RBAC & lineage error handling
# ─────────────────────────────────────────────────────────────────────────────

def test_reauth_requires_admin(monkeypatch):
    user = UserRow()
    app, client, mod, st = _mk_app(monkeypatch, current_user=user, is_admin_impl=lambda _u: False)

    r = client.post("/api/v1/admin/reauth", json={"password": "correct"})
    assert r.status_code == 403
    assert "Insufficient permissions" in r.text


def test_reauth_lineage_decode_errors_are_ignored(monkeypatch):
    async def _bad_decode(*_a, **_k): raise RuntimeError("decode boom")

    user = UserRow(mfa_enabled=True)
    app, client, mod, st = _mk_app(monkeypatch, current_user=user, decode_token_impl=_bad_decode)

    r = client.post("/api/v1/admin/reauth", json={"code": "123456"})
    assert r.status_code == 200
    # session_id falls back to None in mint when decode fails
    assert st["seen_mint"]["session_id"] is None
