# tests/test_admin/test_staff/test_demote_to_user.py

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
    """Row object with the minimal fields the route mutates/returns."""
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

    # Reauth ensure: capture token
    state: Dict[str, Any] = {"reauth_token": None}
    async def _ensure_reauth(token: str, _user: Any):
        state["reauth_token"] = token
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

    # Robustly unwrap SlowAPI decorator on this route
    path = "/api/v1/admin/staff/{user_id}/demote"
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

def test_demote_happy_path_demotes_and_sets_snapshot(monkeypatch):
    staff_mod = importlib.import_module("app.api.v1.routers.admin.staff")
    app, client, _mod, db, r, st, _ = _mk_app(
        monkeypatch,
        db_row=RowUser(email="root@example.com", role=staff_mod.UserRole.SUPERUSER),
        idem_snapshot=None,
    )
    target_id = uuid.uuid4()

    resp = client.post(
        f"/api/v1/admin/staff/{target_id}/demote",
        json={"reauth_token": "rtok"},
        headers={"Idempotency-Key": "k1"},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body == {"message": "Demoted to USER", "user": {"email": "root@example.com"}, "role": "USER"}

    # cache headers
    cc = (resp.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (resp.headers.get("pragma") or "").lower() == "no-cache"

    # DB + lock + snapshot
    assert db.execute_calls
    assert db.flush_calls >= 1 and db.commit_calls >= 1
    assert r.lock_keys and r.lock_keys[-1].endswith(str(target_id))
    assert st["reauth_token"] == "rtok"
    assert r.set_calls and r.set_calls[-1][2] == 600
    key_used = r.set_calls[-1][0]
    assert str(target_id) in key_used and "k1" in key_used


def test_demote_target_not_superuser_400(monkeypatch):
    staff_mod = importlib.import_module("app.api.v1.routers.admin.staff")
    app, client, _mod, db, r, st, _ = _mk_app(
        monkeypatch,
        db_row=RowUser(email="u@example.com", role=staff_mod.UserRole.ADMIN),
        idem_snapshot=None,
    )
    target_id = uuid.uuid4()

    resp = client.post(
        f"/api/v1/admin/staff/{target_id}/demote",
        json={"reauth_token": "tok"},
    )
    assert resp.status_code == 400
    assert "Target is not SUPERUSER" in resp.text


def test_demote_idempotency_replay_skips_db(monkeypatch):
    snapshot = {"message": "Demoted to USER", "user": {"email": "snap@example.com"}, "role": "USER"}
    app, client, _mod, db, r, st, _ = _mk_app(
        monkeypatch,
        db_row=None,
        idem_snapshot=snapshot
    )
    target_id = uuid.uuid4()

    resp = client.post(
        f"/api/v1/admin/staff/{target_id}/demote",
        json={"reauth_token": "tok"},
        headers={"Idempotency-Key": "replay1"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == snapshot
    assert not db.execute_calls
    assert not r.set_calls


def test_demote_requires_reauth_token(monkeypatch):
    staff_mod = importlib.import_module("app.api.v1.routers.admin.staff")
    app, client, _mod, db, r, st, _ = _mk_app(
        monkeypatch,
        db_row=RowUser(email="x@example.com", role=staff_mod.UserRole.SUPERUSER),
    )
    target_id = uuid.uuid4()

    resp = client.post(f"/api/v1/admin/staff/{target_id}/demote", json={})
    assert resp.status_code == 400
    assert "reauth_token required" in resp.text


def test_demote_cannot_change_own_role(monkeypatch):
    staff_mod = importlib.import_module("app.api.v1.routers.admin.staff")
    me = FakeUser()
    app, client, _mod, db, r, st, _ = _mk_app(
        monkeypatch,
        db_row=RowUser(email="self@example.com", role=staff_mod.UserRole.SUPERUSER),
        current_user=me,
    )

    resp = client.post(
        f"/api/v1/admin/staff/{me.id}/demote",
        json={"reauth_token": "rt"},
    )
    assert resp.status_code == 400
    assert "Cannot change your own role" in resp.text


def test_demote_404_when_user_not_found(monkeypatch):
    app, client, _mod, db, r, st, _ = _mk_app(monkeypatch, db_row=None)
    target_id = uuid.uuid4()

    resp = client.post(
        f"/api/v1/admin/staff/{target_id}/demote",
        json={"reauth_token": "rt"},
    )
    assert resp.status_code == 404
    assert "User not found" in resp.text


def test_demote_idempotency_set_failure_is_swallowed(monkeypatch):
    staff_mod = importlib.import_module("app.api.v1.routers.admin.staff")
    app, client, _mod, db, r, st, _ = _mk_app(
        monkeypatch,
        db_row=RowUser(email="root2@example.com", role=staff_mod.UserRole.SUPERUSER),
        idem_snapshot=None,
        fail_idem_set=True,
    )
    target_id = uuid.uuid4()

    resp = client.post(
        f"/api/v1/admin/staff/{target_id}/demote",
        json={"reauth_token": "tok"},
        headers={"Idempotency-Key": "k-fail"},
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "USER"
