# tests/test_admin/test_sessions/test_revoke_session.py

import importlib
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Minimal DB + models stubs
# ─────────────────────────────────────────────────────────────────────────────

class _Result:
    def __init__(self, row: Any | None):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


class FakeDB:
    def __init__(self, rows: List[Any]):
        self._rows = list(rows)
        self._selected_row = None
        self.update_calls: List[Dict[str, Any]] = []
        self.commits = 0
        self.rollbacks = 0

    async def execute(self, query, *_a, **_k):
        # Heuristic: use the SQLAlchemy construct class name to decide
        name = getattr(query.__class__, "__name__", "").lower()
        if "select" in name:
            row = self._rows.pop(0) if self._rows else None
            self._selected_row = row
            return _Result(row)
        if "update" in name:
            # record the call and flip the row's is_revoked for realism
            self.update_calls.append({"query": query, "params": _k})
            if self._selected_row is not None:
                try:
                    setattr(self._selected_row, "is_revoked", True)
                except Exception:
                    pass
            class _Dummy: ...
            return _Dummy()
        # default
        return _Result(None)

    async def commit(self): self.commits += 1
    async def flush(self):  pass
    async def rollback(self): self.rollbacks += 1


class UserRow:
    def __init__(self, *, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


class RefreshTokenRow:
    def __init__(self, *, jti: str, user_id: uuid.UUID, is_revoked: bool = False, session_id: Optional[str] = None):
        self.jti = jti
        self.user_id = user_id
        self.is_revoked = is_revoked
        self.session_id = session_id


# ─────────────────────────────────────────────────────────────────────────────
# Test app factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    rows: List[Any],
    ensure_admin_ok: bool = True,
):
    mod = importlib.import_module("app.api.v1.routers.admin.sessions")

    # Disable rate limiting in tests (if your decorator reads these)
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Bypass ADMIN + MFA checks
    async def _ok(*_a, **_k): return None
    async def _deny(*_a, **_k): raise HTTPException(status_code=403, detail="Insufficient permissions")
    monkeypatch.setattr(mod, "_ensure_admin", _ok if ensure_admin_ok else _deny, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Capture Redis lock usage
    lock_keys: List[str] = []
    class _ALock:
        def __init__(self, key, timeout=10, blocking_timeout=3):
            self.key = key
            lock_keys.append(key)
        async def __aenter__(self): return self
        async def __aexit__(self, *exc): return False
    def _lock(key, timeout=10, blocking_timeout=3): return _ALock(key, timeout, blocking_timeout)
    monkeypatch.setattr(mod.redis_wrapper, "lock", _lock, raising=False)

    # Capture SREM calls
    srem_calls: List[tuple[str, str]] = []
    async def _srem(key: str, member: str):
        srem_calls.append((key, member))
    monkeypatch.setattr(mod, "_redis_srem", _srem, raising=False)

    # Audit no-op by default
    async def _audit(*_a, **_k): return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Build app and register the **unwrapped** endpoint to avoid SlowAPI wrapper
    app = FastAPI()
    fn = mod.revoke_session
    while hasattr(fn, "__wrapped__"):  # peel any decorators (e.g., @rate_limit)
        fn = fn.__wrapped__
    app.post("/api/v1/admin/sessions/revoke")(fn)

    # Override dependencies
    db = FakeDB(rows)
    user = UserRow()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, {"user": user, "lock_keys": lock_keys, "srem_calls": srem_calls}


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_revoke_happy_path_revokes_and_sets_no_store(monkeypatch):
    user = UserRow()
    row = RefreshTokenRow(jti="J1", user_id=user.id, is_revoked=False)
    app, client, mod, db, st = _mk_app(monkeypatch, rows=[row])

    r = client.post("/api/v1/admin/sessions/revoke", json={"jti": "J1"})
    assert r.status_code == 200, r.text
    assert r.json() == {"revoked": 1}

    # cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # DB update + commit happened and row is marked revoked
    assert db.commits == 1
    assert getattr(row, "is_revoked", False) is True

    # lock used with correct key
    assert st["lock_keys"] and st["lock_keys"][0] == "lock:session:revoke:J1"

    # session set membership cleaned up
    assert st["srem_calls"] and st["srem_calls"][0] == (f"session:{st['user'].id}", "J1")


def test_revoke_already_revoked_returns_0_and_no_update(monkeypatch):
    user = UserRow()
    row = RefreshTokenRow(jti="J2", user_id=user.id, is_revoked=True)
    app, client, mod, db, st = _mk_app(monkeypatch, rows=[row])

    r = client.post("/api/v1/admin/sessions/revoke", json={"jti": "J2"})
    assert r.status_code == 200
    assert r.json() == {"revoked": 0, "message": "Already revoked"}

    # No DB commit; no set removal
    assert db.commits == 0
    assert st["srem_calls"] == []


def test_revoke_404_when_session_not_found(monkeypatch):
    app, client, mod, db, st = _mk_app(monkeypatch, rows=[None])

    r = client.post("/api/v1/admin/sessions/revoke", json={"jti": "MISSING"})
    assert r.status_code == 404
    assert "Session not found" in r.text

    assert db.commits == 0
    assert st["srem_calls"] == []


def test_revoke_audit_failure_is_swallowed(monkeypatch):
    user = UserRow()
    row = RefreshTokenRow(jti="J3", user_id=user.id, is_revoked=False)
    app, client, mod, db, st = _mk_app(monkeypatch, rows=[row])

    async def _boom(*_a, **_k): raise RuntimeError("audit down")
    monkeypatch.setattr(mod, "log_audit_event", _boom, raising=False)

    r = client.post("/api/v1/admin/sessions/revoke", json={"jti": "J3"})
    assert r.status_code == 200
    assert r.json() == {"revoked": 1}
    # Even with audit error, we still updated, committed, and cleaned up session set
    assert db.commits == 1
    assert st["srem_calls"] and st["srem_calls"][0][1] == "J3"


def test_revoke_uses_lock_key_per_jti(monkeypatch):
    user = UserRow()
    row = RefreshTokenRow(jti="LOCKKEY", user_id=user.id, is_revoked=False)
    app, client, mod, db, st = _mk_app(monkeypatch, rows=[row])

    r = client.post("/api/v1/admin/sessions/revoke", json={"jti": "LOCKKEY"})
    assert r.status_code == 200
    assert "lock:session:revoke:LOCKKEY" in st["lock_keys"]


def test_revoke_403_when_not_admin(monkeypatch):
    user = UserRow()
    row = RefreshTokenRow(jti="JX", user_id=user.id, is_revoked=False)
    app, client, mod, db, st = _mk_app(monkeypatch, rows=[row], ensure_admin_ok=False)

    r = client.post("/api/v1/admin/sessions/revoke", json={"jti": "JX"})
    assert r.status_code == 403
    assert "Insufficient permissions" in r.text
