# tests/test_admin/test_taxonomy/test_delete_credit.py

import importlib
import uuid
from typing import Any, Dict, List, Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class _Result:
    def __init__(self, value: Any):
        self._value = value
    def scalars(self): return self  # not used but keeps parity
    def all(self): return []

class FakeDB:
    """
    Minimal fake for DELETE flow:
      • execute(delete(Credit).where(...))
      • commit()
    """
    def __init__(self):
        self.execute_calls = 0
        self.delete_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0
        self.last_stmt = None

    async def execute(self, stmt, *a, **k):
        self.execute_calls += 1
        self.delete_calls += 1
        self.last_stmt = stmt
        return _Result(None)

    async def commit(self):
        self.commit_calls += 1

    async def rollback(self):
        self.rollback_calls += 1


class FakeUser:
    def __init__(self, id: uuid.UUID | None = None):
        self.id = id or uuid.uuid4()


# ─────────────────────────────────────────────────────────────────────────────
# App factory (no unwraps; env disables rate limit)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, make_audit_raise: bool = False):
    mod = importlib.import_module("app.api.v1.routers.admin.taxonomy")

    # Disable rate limiting for tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Patch security checks to no-ops but count calls
    dep_mod = importlib.import_module("app.dependencies.admin")
    calls = {"ensure_admin": 0, "ensure_mfa": 0}

    async def _ensure_admin(user):  # noqa: ARG001
        calls["ensure_admin"] += 1
    async def _ensure_mfa(request):  # noqa: ARG001
        calls["ensure_mfa"] += 1

    monkeypatch.setattr(dep_mod, "ensure_admin", _ensure_admin, raising=False)
    monkeypatch.setattr(dep_mod, "ensure_mfa", _ensure_mfa, raising=False)

    # Capture audit calls (and optionally raise)
    audit_calls: List[Tuple[str, Dict[str, Any]]] = []
    async def _audit(db, user, action, status, request, meta_data):  # noqa: ARG001
        audit_calls.append((action, meta_data))
        if make_audit_raise:
            raise RuntimeError("audit boom")

    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Fake redis lock that records keys
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

    # Build app + overrides
    app = FastAPI()
    # NOTE: keep router itself unprefixed; tests add /api/v1/admin here.
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB()
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, r, audit_calls, calls


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_delete_credit_happy_path_no_store_and_lock(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch)
    cid = uuid.uuid4()

    resp = client.delete(f"/api/v1/admin/credits/{cid}")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Credit deleted"}

    # DB delete + commit happens
    assert db.execute_calls >= 1
    assert db.delete_calls >= 1
    assert db.commit_calls >= 1
    assert db.rollback_calls == 0

    # Lock was used with expected key suffix
    assert r.lock_keys and r.lock_keys[-1].endswith(str(cid))

    # Cache headers (from _json helper)
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Audit logged with expected shape
    assert audit_calls, "audit event was not recorded"
    action, meta = audit_calls[-1]
    assert action == "CREDITS_DELETE"
    assert meta == {"credit_id": str(cid)}

    # Security checks were invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_delete_credit_idempotent_when_not_found_still_200(monkeypatch):
    """
    Route doesn't check rows affected; deleting a non-existent credit still succeeds.
    We just assert 200 + commit, no rollback.
    """
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch)
    cid = uuid.uuid4()

    resp = client.delete(f"/api/v1/admin/credits/{cid}")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Credit deleted"}

    # Delete executed and committed
    assert db.delete_calls >= 1
    assert db.commit_calls >= 1
    assert db.rollback_calls == 0

    # Lock + cache headers still correct
    assert r.lock_keys and r.lock_keys[-1].endswith(str(cid))
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_delete_credit_audit_error_is_swallowed(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, make_audit_raise=True)
    cid = uuid.uuid4()

    resp = client.delete(f"/api/v1/admin/credits/{cid}")
    # still succeeds even if audit raises
    assert resp.status_code == 200
    assert resp.json() == {"message": "Credit deleted"}

    # DB delete + commit called
    assert db.delete_calls >= 1
    assert db.commit_calls >= 1

    # Lock used + cache headers present
    assert r.lock_keys and r.lock_keys[-1].endswith(str(cid))
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_delete_credit_calls_security_checks(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch)
    cid = uuid.uuid4()

    resp = client.delete(f"/api/v1/admin/credits/{cid}")
    assert resp.status_code == 200

    # Ensure both checks were actually invoked exactly once
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
