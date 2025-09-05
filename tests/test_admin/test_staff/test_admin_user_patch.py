# tests/test_admin/test_staff/test_admin_user_patch.py

import importlib
import uuid
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone
import inspect

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.routing import request_response  # robust unwrap for SlowAPI


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class _OneResult:
    def __init__(self, row: Any | None):
        self._row = row
    def scalar_one_or_none(self):
        return self._row

class FakeDB:
    """Very small async DB stub to satisfy the route's usage pattern."""
    def __init__(self, row: Any | None):
        self._row = row
        self.execute_calls: List[Tuple[Any, tuple, dict]] = []
        self.flush_calls = 0
        self.commit_calls = 0
    async def execute(self, query, *a, **k):
        self.execute_calls.append((query, a, k))
        return _OneResult(self._row)
    async def flush(self):
        self.flush_calls += 1
    async def commit(self):
        self.commit_calls += 1

class FakeCurrentUser:
    def __init__(self, *, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()

class RowUser:
    """Mimics the fields that _serialize_user reads / the route updates."""
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        email: str = "user@example.com",
        role: str = "USER",
        full_name: Optional[str] = None,
        is_active: bool = True,
        is_verified: bool = False,
        is_email_verified: bool = False,
        is_phone_verified: bool = False,
        mfa_enabled: bool = False,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None,
        last_login_at: Optional[datetime] = None,
        name: Optional[str] = None,  # if serializer references name
    ):
        self.id = id or uuid.uuid4()
        self.email = email
        self.role = role
        self.full_name = full_name
        self.is_active = is_active
        self.is_verified = is_verified
        self.is_email_verified = is_email_verified
        self.is_phone_verified = is_phone_verified
        self.mfa_enabled = mfa_enabled
        self.created_at = created_at or datetime(2025, 1, 1, tzinfo=timezone.utc)
        self.updated_at = updated_at
        self.last_login_at = last_login_at
        self.name = name


# ─────────────────────────────────────────────────────────────────────────────
# App factory (version-proof SlowAPI unwrap)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    row: Any | None,
    current_user: Optional[FakeCurrentUser] = None,
):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")

    # Disable rate limiting for tests (evaluated at call time by our decorators)
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Security gates → no-op
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Capture reauth token if invoked
    state: Dict[str, Any] = {"reauth_token": None}
    async def _ensure_reauth(tok: str, _user: Any):
        state["reauth_token"] = tok
        return None
    monkeypatch.setattr(mod, "_ensure_reauth", _ensure_reauth, raising=False)

    # Audit is best-effort; stub to no-op
    async def _audit(*_a, **_k): return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Fake Redis with a simple lock context that records the key
    class _Lock:
        def __init__(self, key: str, *, timeout: int, blocking_timeout: int):
            self.key = key
        async def __aenter__(self): return None
        async def __aexit__(self, exc_type, exc, tb): return False

    class _Redis:
        def __init__(self):
            self.lock_keys: List[str] = []
        def lock(self, key: str, *, timeout: int, blocking_timeout: int):
            self.lock_keys.append(key)
            return _Lock(key, timeout=timeout, blocking_timeout=blocking_timeout)

    r = _Redis()
    monkeypatch.setattr(mod, "redis_wrapper", r, raising=False)

    # Build app and dependency overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(row)
    user_ctx = current_user or FakeCurrentUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user_ctx

    # Robustly unwrap SlowAPI/Starlette handler
    path = "/api/v1/admin/users/{user_id}"
    for route in app.routes:
        if getattr(route, "path", None) == path and "PATCH" in getattr(route, "methods", set()):
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn
            try:
                handler = route.get_request_handler() if hasattr(route, "get_request_handler") else route.get_route_handler()
                try:
                    params = list(inspect.signature(handler).parameters.values())
                except Exception:
                    params = []
                route.app = request_response(handler) if len(params) == 1 else handler
            except Exception:
                _h = route.get_route_handler()
                try:
                    _p = list(inspect.signature(_h).parameters.values())
                except Exception:
                    _p = []
                route.app = request_response(_h) if len(_p) == 1 else _h
            break

    client = TestClient(app)
    return app, client, mod, db, r, state, user_ctx


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_patch_user_updates_name_only(monkeypatch):
    row = RowUser(full_name=None)
    app, client, mod, db, r, st, _ = _mk_app(monkeypatch, row=row)

    resp = client.patch(f"/api/v1/admin/users/{row.id}", json={"full_name": "Alice A."})
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # Response serialization should include updated name
    assert data.get("full_name") == "Alice A."
    # Row actually mutated
    assert row.full_name == "Alice A."

    # Cache headers (no-store)
    cc = (resp.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (resp.headers.get("pragma") or "").lower() == "no-cache"

    # DB flush/commit under lock
    assert db.flush_calls >= 1 and db.commit_calls >= 1
    assert r.lock_keys and r.lock_keys[-1].endswith(str(row.id))


def test_patch_user_requires_reauth_for_verification_flags(monkeypatch):
    row = RowUser(is_verified=False)
    app, client, mod, db, r, st, _ = _mk_app(monkeypatch, row=row)

    resp = client.patch(f"/api/v1/admin/users/{row.id}", json={"is_verified": True})
    assert resp.status_code == 400
    assert "reauth_token required" in resp.text
    # Ensure we didn't flush/commit
    assert db.flush_calls == 0 and db.commit_calls == 0


def test_patch_user_verification_with_reauth_updates_and_calls_reauth(monkeypatch):
    row = RowUser(is_verified=False)
    app, client, mod, db, r, st, _ = _mk_app(monkeypatch, row=row)

    resp = client.patch(
        f"/api/v1/admin/users/{row.id}",
        json={"is_verified": True, "reauth_token": "rtok-123"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # reauth was enforced
    assert st["reauth_token"] == "rtok-123"
    # Row mutated (serializer doesn't include verification flags)
    assert row.is_verified is True
    # DB persisted
    assert db.flush_calls >= 1 and db.commit_calls >= 1


def test_patch_user_multiple_flags_and_name_with_reauth(monkeypatch):
    row = RowUser(full_name="Old", is_email_verified=False, is_phone_verified=False)
    app, client, mod, db, r, st, _ = _mk_app(monkeypatch, row=row)

    payload = {
        "full_name": "New Name",
        "is_email_verified": True,
        "is_phone_verified": True,
        "reauth_token": "T-123",
    }
    resp = client.patch(f"/api/v1/admin/users/{row.id}", json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # All updates applied (flags reflected only on the row; name shows in response)
    assert row.full_name == "New Name"
    assert row.is_email_verified is True
    assert row.is_phone_verified is True
    assert data.get("full_name") == "New Name"
    # Reauth called
    assert st["reauth_token"] == "T-123"


def test_patch_user_404_when_not_found(monkeypatch):
    app, client, mod, db, r, st, _ = _mk_app(monkeypatch, row=None)
    uid = uuid.uuid4()

    resp = client.patch(f"/api/v1/admin/users/{uid}", json={"full_name": "X"})
    assert resp.status_code == 404
    assert "User not found" in resp.text


def test_patch_user_empty_body_400(monkeypatch):
    row = RowUser()
    app, client, mod, db, r, st, _ = _mk_app(monkeypatch, row=row)

    resp = client.patch(f"/api/v1/admin/users/{row.id}", json={})
    assert resp.status_code == 400
    assert "Empty body" in resp.text


def test_patch_user_no_allowed_fields_400(monkeypatch):
    row = RowUser()
    app, client, mod, db, r, st, _ = _mk_app(monkeypatch, row=row)

    # Only disallowed fields provided
    resp = client.patch(
        f"/api/v1/admin/users/{row.id}",
        json={"role": "ADMIN", "unknown": "x"},
    )
    assert resp.status_code == 400
    assert "No allowed fields to update" in resp.text
