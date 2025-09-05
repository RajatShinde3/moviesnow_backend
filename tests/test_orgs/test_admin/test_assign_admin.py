import importlib
import uuid
from typing import Any, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi import HTTPException


class _FakeResult:
    def __init__(self, row):
        self._row = row
    def scalar_one_or_none(self):
        return self._row


class FakeDB:
    def __init__(self, row):
        self.row = row
        self.flush_calls = 0
        self.commit_calls = 0
        self.refresh_calls = 0
        self.execute_calls = 0
        self.rollback_calls = 0
    async def execute(self, query, *a, **k):
        self.execute_calls += 1
        return _FakeResult(self.row)
    async def flush(self):
        self.flush_calls += 1
    async def commit(self):
        self.commit_calls += 1
    async def refresh(self, *_a, **_k):
        self.refresh_calls += 1
    async def rollback(self):
        self.rollback_calls += 1


class FakeUserRow:
    def __init__(self, *, id: Optional[uuid.UUID] = None, email: str = "u@example.com", role: str = "USER"):
        self.id = id or uuid.uuid4()
        self.email = email
        self.role = role


class Caller:
    def __init__(self, *, id: Optional[uuid.UUID] = None, role: str = "ADMIN"):
        self.id = id or uuid.uuid4()
        self.role = role


class FakeRedis:
    def __init__(self):
        self._snap = {}
        self.lock_names = []
        self.set_calls = 0
        self.get_calls = 0
    async def idempotency_get(self, key: str):
        self.get_calls += 1
        return self._snap.get(key)
    async def idempotency_set(self, key: str, value: Any, *, ttl_seconds: int = 600):
        self.set_calls += 1
        self._snap[key] = value
    class _Lock:
        def __init__(self, parent, name):
            self.parent = parent
            self.name = name
        async def __aenter__(self):
            self.parent.lock_names.append(self.name)
            return True
        async def __aexit__(self, exc_type, exc, tb):
            return False
    def lock(self, name: str, *, timeout: int = 10, blocking_timeout: int = 3):  # noqa: ARG002
        return FakeRedis._Lock(self, name)


def _mk_app(monkeypatch, *, target_row: Optional[FakeUserRow], caller: Caller):
    mod = importlib.import_module("app.api.v1.routers.orgs.admin")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/orgs/admin")

    db = FakeDB(target_row)
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: caller

    # Fake redis + budget enforcer
    r = FakeRedis()
    monkeypatch.setattr(mod, "redis_wrapper", r, raising=False)

    async def _ok_budget(**_k):
        return None
    monkeypatch.setattr(mod, "enforce_rate_limit", _ok_budget, raising=False)

    # No-op audit
    async def _audit(*_a, **_k):
        return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    return app, TestClient(app), mod, db, r


def test_assign_admin_happy_path(monkeypatch):
    target = FakeUserRow(email="t@example.com", role="USER")
    caller = Caller(role="ADMIN")
    app, client, mod, db, r = _mk_app(monkeypatch, target_row=target, caller=caller)

    resp = client.put(f"/api/v1/orgs/admin/{target.id}/assign-ADMIN", headers={"Idempotency-Key": "k1"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["user"]["email"] == "t@example.com"
    assert "ADMIN" in body["role"]
    # header
    assert (resp.headers.get("Cache-Control") or "").startswith("no-store")
    # db mutated
    assert db.flush_calls == 1 and db.commit_calls == 1
    # idempotency snapshot set
    assert r.set_calls >= 1


def test_assign_admin_idempotency_hit(monkeypatch):
    target = FakeUserRow(email="t@example.com", role="USER")
    caller = Caller(role="ADMIN")
    app, client, mod, db, r = _mk_app(monkeypatch, target_row=target, caller=caller)

    key = f"idemp:admin:assign:{caller.id}:{target.id}:k2"
    r._snap[key] = {"message": "Role updated to ADMIN", "user": {"email": target.email}, "role": "ADMIN"}

    resp = client.put(f"/api/v1/orgs/admin/{target.id}/assign-ADMIN", headers={"Idempotency-Key": "k2"})
    assert resp.status_code == 200
    # DB not executed because of idempotency
    assert db.execute_calls == 0


def test_assign_admin_forbidden_and_self_promotion(monkeypatch):
    target = FakeUserRow(email="t@example.com", role="USER")
    caller = Caller(role="USER")
    app, client, mod, db, r = _mk_app(monkeypatch, target_row=target, caller=caller)
    # forbidden
    resp = client.put(f"/api/v1/orgs/admin/{target.id}/assign-ADMIN")
    assert resp.status_code == 403

    # self promotion
    caller_admin = Caller(id=target.id, role="ADMIN")
    app, client, mod, db, r = _mk_app(monkeypatch, target_row=target, caller=caller_admin)
    resp2 = client.put(f"/api/v1/orgs/admin/{target.id}/assign-ADMIN")
    assert resp2.status_code == 400

