# tests/test_admin/test_staff/test_promote_to_superuser.py

import importlib
import uuid
from typing import Any, Optional, Tuple, List, Dict
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

class FakeUser:
    def __init__(self, *, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()

class RowUser:
    """Simple row with email + role; role will use mod.UserRole values."""
    def __init__(self, *, email: str, role: Any):
        self.email = email
        self.role = role


# ─────────────────────────────────────────────────────────────────────────────
# App factory (version-proof SlowAPI unwrap)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    db_row: Any | None,
    current_user: Optional[FakeUser] = None,
    idem_snapshot: Optional[dict] = None,
    fail_idem_set: bool = False,
):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")

    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Security gates no-op
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Track that reauth was enforced and with what token
    state: Dict[str, Any] = {"reauth_token": None}
    async def _ensure_reauth(token: str, _user: Any):
        state["reauth_token"] = token
        return None
    monkeypatch.setattr(mod, "_ensure_reauth", _ensure_reauth, raising=False)

    # Fake Redis wrapper (idempotency + lock)
    class _Lock:
        def __init__(self, key: str, *, timeout: int, blocking_timeout: int):
            self.key = key
        async def __aenter__(self): return None
        async def __aexit__(self, exc_type, exc, tb): return False

    class _Redis:
        def __init__(self):
            self.get_calls: List[str] = []
            self.set_calls: List[Tuple[str, Any, int]] = []
            self.lock_keys: List[str] = []
            self.snapshot = idem_snapshot
            self.fail_set = fail_idem_set
        async def idempotency_get(self, key: str):
            self.get_calls.append(key)
            return self.snapshot
        async def idempotency_set(self, key: str, val: Any, *, ttl_seconds: int):
            self.set_calls.append((key, val, ttl_seconds))
            if self.fail_set:
                raise RuntimeError("idem set boom")
            return True
        def lock(self, key: str, *, timeout: int, blocking_timeout: int):
            self.lock_keys.append(key)
            return _Lock(key, timeout=timeout, blocking_timeout=blocking_timeout)

    r = _Redis()
    monkeypatch.setattr(mod, "redis_wrapper", r, raising=False)

    # Build app + overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB(db_row)
    user = current_user or FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Robustly unwrap SlowAPI rate_limit
    path = "/api/v1/admin/staff/{user_id}/promote"
    for route in app.routes:
        if getattr(route, "path", None) == path and "POST" in getattr(route, "methods", set()):
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
    return app, client, mod, db, r, state, user


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_promote_happy_path_promotes_and_sets_snapshot(monkeypatch):
    # Import module first to access the enum BEFORE calling _mk_app
    mod = importlib.import_module("app.api.v1.routers.admin.staff")
    db_row = RowUser(email="u@example.com", role=mod.UserRole.ADMIN)

    app, client, mod2, db, r, st, _ = _mk_app(
        monkeypatch,
        db_row=db_row,
        idem_snapshot=None,
    )
    user_id = uuid.uuid4()

    resp = client.post(
        f"/api/v1/admin/staff/{user_id}/promote",
        json={"reauth_token": "rtok"},
        headers={"Idempotency-Key": "k1"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body == {"message": "Promoted to SUPERUSER", "user": {"email": "u@example.com"}, "role": "SUPERUSER"}

    # cache headers
    cc = (resp.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (resp.headers.get("pragma") or "").lower() == "no-cache"

    # DB hit + flush/commit executed
    assert db.execute_calls
    assert db.flush_calls >= 1 and db.commit_calls >= 1

    # Lock key captured
    assert r.lock_keys and r.lock_keys[-1].endswith(str(user_id))

    # Reauth enforced with provided token
    assert st["reauth_token"] == "rtok"

    # Idempotency snapshot with TTL 600 set after success
    assert r.set_calls and r.set_calls[-1][2] == 600
    key_used = r.set_calls[-1][0]
    assert str(user_id) in key_used and "k1" in key_used


def test_promote_already_superuser_returns_message_and_sets_snapshot(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")
    db_row = RowUser(email="root@example.com", role=mod.UserRole.SUPERUSER)

    app, client, mod2, db, r, st, _ = _mk_app(
        monkeypatch,
        db_row=db_row,
        idem_snapshot=None,
    )
    user_id = uuid.uuid4()

    resp = client.post(
        f"/api/v1/admin/staff/{user_id}/promote",
        json={"reauth_token": "tok"},
        headers={"Idempotency-Key": "key-abc"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["message"] == "Already SUPERUSER"
    assert body["role"] == mod.UserRole.SUPERUSER.value  # route returns enum.value in this branch

    # Snapshot set with TTL 600
    assert r.set_calls and r.set_calls[-1][2] == 600
    assert "key-abc" in r.set_calls[-1][0]


def test_promote_idempotency_replay_skips_db(monkeypatch):
    snap = {"message": "Promoted to SUPERUSER", "user": {"email": "snap@example.com"}, "role": "SUPERUSER"}

    # For replay, DB row won't be used; pass None
    app, client, mod2, db, r, st, _ = _mk_app(
        monkeypatch,
        db_row=None,
        idem_snapshot=snap,
    )
    user_id = uuid.uuid4()

    resp = client.post(
        f"/api/v1/admin/staff/{user_id}/promote",
        json={"reauth_token": "tok"},
        headers={"Idempotency-Key": "replay1"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == snap

    # DB not touched on replay; no new snapshot set
    assert not db.execute_calls
    assert not r.set_calls


def test_promote_requires_reauth_token(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")
    db_row = RowUser(email="x@example.com", role=mod.UserRole.ADMIN)

    app, client, mod2, db, r, st, _ = _mk_app(
        monkeypatch,
        db_row=db_row,
    )
    user_id = uuid.uuid4()

    resp = client.post(f"/api/v1/admin/staff/{user_id}/promote", json={})
    assert resp.status_code == 400
    assert "reauth_token required" in resp.text


def test_promote_cannot_change_own_role(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")
    db_row = RowUser(email="self@example.com", role=mod.UserRole.ADMIN)

    me = FakeUser()
    app, client, mod2, db, r, st, _ = _mk_app(
        monkeypatch,
        db_row=db_row,
        current_user=me,
    )

    resp = client.post(
        f"/api/v1/admin/staff/{me.id}/promote",
        json={"reauth_token": "rt"},
    )
    assert resp.status_code == 400
    assert "Cannot change your own role" in resp.text


def test_promote_404_when_user_not_found(monkeypatch):
    app, client, mod2, db, r, st, _ = _mk_app(monkeypatch, db_row=None)
    user_id = uuid.uuid4()

    resp = client.post(
        f"/api/v1/admin/staff/{user_id}/promote",
        json={"reauth_token": "rt"},
    )
    assert resp.status_code == 404
    assert "User not found" in resp.text


def test_promote_idempotency_set_failure_is_swallowed(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")
    db_row = RowUser(email="u2@example.com", role=mod.UserRole.ADMIN)

    app, client, mod2, db, r, st, _ = _mk_app(
        monkeypatch,
        db_row=db_row,
        idem_snapshot=None,
        fail_idem_set=True,  # force set failure
    )
    user_id = uuid.uuid4()

    resp = client.post(
        f"/api/v1/admin/staff/{user_id}/promote",
        json={"reauth_token": "tok"},
        headers={"Idempotency-Key": "k-fail"},
    )
    # Still succeeds even if snapshot set fails
    assert resp.status_code == 200
    assert resp.json()["role"] == "SUPERUSER"
