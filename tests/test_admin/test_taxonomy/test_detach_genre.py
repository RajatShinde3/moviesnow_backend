# tests/test_admin/test_taxonomy/test_detach_genre.py

import importlib
import uuid
from typing import Any, List, Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class _Result:
    def __init__(self, value: Any):
        self._value = value
    def scalar_one_or_none(self):
        return self._value

class FakeDB:
    """
    Minimal fake DB for the detach flow:
    - One or more DELETE executes
    - A commit
    """
    def __init__(self):
        self.execute_calls = 0
        self.delete_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0

    async def execute(self, _stmt):
        self.execute_calls += 1
        self.delete_calls += 1
        # Route doesn't inspect the returned result; just return a placeholder
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

    # Capture audit calls (and optionally raise to ensure errors are swallowed)
    audit_calls: List[Tuple[str, dict]] = []

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

    # Build app + dependency overrides
    app = FastAPI()
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

def test_detach_genre_happy_path_no_store_and_lock(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch)
    tid = uuid.uuid4()
    gid = uuid.uuid4()

    resp = client.delete(f"/api/v1/admin/titles/{tid}/genres/{gid}")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Detached"}

    # DB delete + commit happens, no rollback
    assert db.execute_calls >= 1
    assert db.delete_calls >= 1
    assert db.commit_calls >= 1
    assert db.rollback_calls == 0

    # Lock was used with expected key suffix
    assert r.lock_keys and r.lock_keys[-1].endswith(f"{tid}:{gid}")

    # Cache headers (from _json helper)
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Audit logged with expected shape
    assert audit_calls, "audit event was not recorded"
    action, meta = audit_calls[-1]
    assert action == "TITLES_GENRE_DETACH"
    assert meta == {"title_id": str(tid), "genre_id": str(gid)}

    # Security checks were invoked (but patched as no-ops)
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_detach_genre_idempotent_when_not_present_still_200(monkeypatch):
    """
    Route doesn't check existence; deleting a non-existent association should still succeed.
    We just assert 200 + commit, no rollback.
    """
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch)
    tid = uuid.uuid4()
    gid = uuid.uuid4()

    resp = client.delete(f"/api/v1/admin/titles/{tid}/genres/{gid}")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Detached"}

    # Even if nothing was actually removed, we executed a delete and committed.
    assert db.delete_calls >= 1
    assert db.commit_calls >= 1
    assert db.rollback_calls == 0

    # Lock + cache headers still correct
    assert r.lock_keys and r.lock_keys[-1].endswith(f"{tid}:{gid}")
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_detach_genre_audit_error_is_swallowed(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, make_audit_raise=True)
    tid = uuid.uuid4()
    gid = uuid.uuid4()

    resp = client.delete(f"/api/v1/admin/titles/{tid}/genres/{gid}")
    # still succeeds even if audit raises
    assert resp.status_code == 200
    assert resp.json() == {"message": "Detached"}

    # DB delete + commit called
    assert db.delete_calls >= 1
    assert db.commit_calls >= 1

    # Lock used + cache headers present
    assert r.lock_keys and r.lock_keys[-1].endswith(f"{tid}:{gid}")
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_detach_genre_calls_security_checks(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch)
    tid = uuid.uuid4()
    gid = uuid.uuid4()

    resp = client.delete(f"/api/v1/admin/titles/{tid}/genres/{gid}")
    assert resp.status_code == 200

    # Ensure both checks were actually invoked exactly once
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
