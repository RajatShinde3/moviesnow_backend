# tests/test_admin/test_taxonomy/test_delete_genre.py

import importlib
import uuid
from typing import Any, List, Tuple, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class _Result:
    def scalar_one_or_none(self):
        return None

class FakeDB:
    def __init__(self):
        self.execute_calls: List[Tuple[Any, tuple, dict]] = []
        self.commit_calls = 0

    async def execute(self, query, *a, **k):
        self.execute_calls.append((query, a, k))
        return _Result()

    async def commit(self):
        self.commit_calls += 1

class FakeUser:
    def __init__(self, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


# ─────────────────────────────────────────────────────────────────────────────
# App factory (no unwrap needed)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, make_audit_raise: bool = False):
    mod = importlib.import_module("app.api.v1.routers.admin.taxonomy")

    # Disable rate limiting for tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # The route imports these from app.dependencies.admin at call time,
    # so patch that module directly.
    dep_mod = importlib.import_module("app.dependencies.admin")

    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(dep_mod, "ensure_admin", _ok, raising=False)
    monkeypatch.setattr(dep_mod, "ensure_mfa", _ok, raising=False)

    # Capture audit calls (and optionally raise to ensure errors are swallowed)
    audit_calls: List[Tuple[str, dict]] = []

    async def _audit(db, user, action, status, request, meta_data):
        audit_calls.append((action, meta_data))
        if make_audit_raise:
            raise RuntimeError("audit boom")

    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Fake redis lock
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

    db = FakeDB()
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, r, audit_calls


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_delete_genre_happy_path_deletes_and_no_store(monkeypatch):
    app, client, mod, db, r, audits = _mk_app(monkeypatch)
    gid = uuid.uuid4()

    resp = client.delete(f"/api/v1/admin/genres/{gid}")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"message": "Genre deleted"}

    # cache headers
    cc = (resp.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (resp.headers.get("pragma") or "").lower() == "no-cache"

    # DB delete + commit called
    assert db.execute_calls, "Expected a DELETE to be executed"
    assert db.commit_calls >= 1

    # Lock key includes the id
    assert r.lock_keys and any(k.endswith(str(gid)) and "lock:admin:genres:" in k for k in r.lock_keys)

    # Audit called with id in metadata
    assert audits and audits[-1][0] == "GENRES_DELETE"
    assert audits[-1][1].get("id") == str(gid)


def test_delete_genre_audit_error_is_swallowed(monkeypatch):
    app, client, mod, db, r, audits = _mk_app(monkeypatch, make_audit_raise=True)
    gid = uuid.uuid4()

    resp = client.delete(f"/api/v1/admin/genres/{gid}")
    # still succeeds even if audit raises
    assert resp.status_code == 200
    assert resp.json() == {"message": "Genre deleted"}

    # DB delete + commit called
    assert db.execute_calls
    assert db.commit_calls >= 1

    # Lock was used
    assert r.lock_keys and r.lock_keys[-1].endswith(str(gid))


def test_delete_genre_always_200_even_if_not_found(monkeypatch):
    # Route does not check existence; result is still 200
    app, client, mod, db, r, audits = _mk_app(monkeypatch)
    gid = uuid.uuid4()

    resp = client.delete(f"/api/v1/admin/genres/{gid}")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Genre deleted"}
    assert db.execute_calls
    assert db.commit_calls >= 1
