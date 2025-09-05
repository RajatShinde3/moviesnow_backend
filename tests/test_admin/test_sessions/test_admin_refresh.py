# tests/test_admin/test_sessions/test_admin_refresh.py

import importlib
import inspect
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class _ScalarResult:
    def __init__(self, row: Any | None): self._row = row
    def scalar_one_or_none(self): return self._row
    def all(self): return self._row if isinstance(self._row, list) else []

class FakeDB:
    """AsyncSession-ish stub that serves queued scalar results and records writes."""
    def __init__(self, results: List[Any]):
        self._results = list(results)
        self.exec_calls: List[Any] = []
        self.commit_calls = 0

    async def execute(self, query, *_a, **_k):
        self.exec_calls.append(query)
        row = self._results.pop(0) if self._results else None
        return _ScalarResult(row)

    async def commit(self):
        self.commit_calls += 1

    async def rollback(self):
        pass


class UserRow:
    def __init__(self, *, id: Optional[uuid.UUID] = None, email: str = "a@b.c"):
        self.id = id or uuid.uuid4()
        self.email = email


class RefreshTokenRow:
    def __init__(self, *, jti: str, user_id: uuid.UUID, is_revoked: bool = False, session_id: Optional[str] = None):
        self.jti = jti
        self.user_id = user_id
        self.is_revoked = is_revoked
        self.session_id = session_id or jti
        self.expires_at = None
        self.created_at = None
        self.ip_address = None
        self.user_agent = None


class _AsyncLockCtx:
    def __init__(self, key: str, capture: List[str]): self.key = key; self.capture = capture
    async def __aenter__(self): self.capture.append(self.key)
    async def __aexit__(self, *_): return False


# ─────────────────────────────────────────────────────────────────────────────
# Test app factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    db_results: List[Any],
    decode_token_impl=None,
    ensure_admin_ok: bool = True,
):
    mod = importlib.import_module("app.api.v1.routers.admin.sessions")

    # Disable SlowAPI in tests (the decorator checks these at runtime)
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Ensure ADMIN gate
    async def _ensure_admin(user):
        if not ensure_admin_ok:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return None
    monkeypatch.setattr(mod, "_ensure_admin", _ensure_admin, raising=False)

    # decode_token (accept sync or async and expose as async)
    if decode_token_impl is None:
        async def _decode(tok, expected_types=None, verify_revocation=True):
            return {"sub": "00000000-0000-0000-0000-000000000001", "jti": "J1", "session_id": "sess-1"}
        wrapped_decode = _decode
    else:
        if inspect.iscoroutinefunction(decode_token_impl):
            wrapped_decode = decode_token_impl
        else:
            async def wrapped_decode(*a, **k):
                return decode_token_impl(*a, **k)
    monkeypatch.setattr(mod, "decode_token", wrapped_decode, raising=False)

    # Redis idempotency
    idem_get_calls: List[str] = []
    idem_set_calls: List[Tuple[str, Dict[str, Any], int]] = []

    async def _idem_get(k):
        idem_get_calls.append(k)
        return None

    async def _idem_set(k, v, ttl_seconds=600):
        idem_set_calls.append((k, v, ttl_seconds))
        return True

    monkeypatch.setattr(mod.redis_wrapper, "idempotency_get", _idem_get, raising=False)
    monkeypatch.setattr(mod.redis_wrapper, "idempotency_set", _idem_set, raising=False)

    # Redis lock
    lock_keys: List[str] = []
    def _lock(key: str, timeout=10, blocking_timeout=3):
        return _AsyncLockCtx(key, lock_keys)
    monkeypatch.setattr(mod.redis_wrapper, "lock", _lock, raising=False)

    # create_refresh_token, create_access_token, store_refresh_token, session meta
    crt_calls: List[Dict[str, Any]] = []
    async def _create_refresh_token(*, user_id, parent_jti, session_id):
        crt_calls.append({"user_id": str(user_id), "parent_jti": parent_jti, "session_id": session_id})
        return {"token": "new_refresh", "jti": "J2", "expires_at": "2099-01-01T00:00:00Z", "parent_jti": parent_jti}
    monkeypatch.setattr(mod, "create_refresh_token", _create_refresh_token, raising=False)

    access_calls: List[Dict[str, Any]] = []
    async def _create_access_token(*, user_id, session_id, mfa_authenticated: bool):
        access_calls.append({"user_id": str(user_id), "session_id": session_id, "mfa": mfa_authenticated})
        return "new_access"
    monkeypatch.setattr(mod, "create_access_token", _create_access_token, raising=False)

    srt_calls: List[Dict[str, Any]] = []
    async def _store_refresh_token(*, db, user_id, token, jti, expires_at, parent_jti, ip_address, user_agent=None):
        srt_calls.append({
            "user_id": str(user_id), "token": token, "jti": jti, "parent_jti": parent_jti,
            "ip": ip_address, "ua": user_agent
        })
        return None
    monkeypatch.setattr(mod, "store_refresh_token", _store_refresh_token, raising=False)

    reg_meta_calls: List[Dict[str, Any]] = []
    async def _register_session_and_meta(user_id, refresh_data, session_id, request):
        reg_meta_calls.append({"user_id": str(user_id), "session_id": session_id})
        return None
    monkeypatch.setattr(mod, "_register_session_and_meta", _register_session_and_meta, raising=False)

    # Audit (async)
    audit_calls: List[Dict[str, Any]] = []
    async def _audit(*_a, **k):
        audit_calls.append(k)
        return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Make RefreshToken.__table__.columns.keys() exist and include user_agent
    class _Cols:
        def keys(self): return {"jti", "user_id", "session_id", "ip_address", "user_agent"}
    class _Table: pass
    _Table.columns = _Cols()
    if hasattr(mod, "RefreshToken"):
        monkeypatch.setattr(mod.RefreshToken, "__table__", _Table(), raising=False)

    # Build app (no route unwrapping; avoid touching route.app)
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(db_results)
    app.dependency_overrides[mod.get_async_db] = lambda: db

    client = TestClient(app)
    return (
        app, client, mod, db,
        {
            "idem_get_calls": idem_get_calls,
            "idem_set_calls": idem_set_calls,
            "lock_keys": lock_keys,
            "crt_calls": crt_calls,
            "access_calls": access_calls,
            "srt_calls": srt_calls,
            "reg_meta_calls": reg_meta_calls,
            "audit_calls": audit_calls,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_refresh_happy_path_rotates_and_sets_no_store(monkeypatch):
    user = UserRow()
    token_row = RefreshTokenRow(jti="J1", user_id=user.id, is_revoked=False, session_id="sess-1")

    app, client, mod, db, st = _mk_app(
        monkeypatch,
        db_results=[user, token_row],
        decode_token_impl=lambda *_a, **_k: {"sub": str(user.id), "jti": "J1", "session_id": "sess-1"},
    )

    r = client.post("/api/v1/admin/refresh", json={"refresh_token": "r1"}, headers={"User-Agent": "UA/1"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body.keys()) == {"access_token", "refresh_token", "token_type"}
    assert body["token_type"] == "bearer"

    # Cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # Revoke commit executed once
    assert db.commit_calls == 1

    # Lock used on jti
    assert st["lock_keys"] and st["lock_keys"][0].endswith("J1")

    # Session/meta + store_refresh_token + access mint called
    assert st["crt_calls"] and st["crt_calls"][-1]["parent_jti"] == "J1"
    assert st["reg_meta_calls"] and st["reg_meta_calls"][-1]["session_id"] == "sess-1"
    assert st["srt_calls"] and st["srt_calls"][-1]["jti"] == "J2"
    assert st["access_calls"] and st["access_calls"][-1]["mfa"] is True


def test_refresh_invalid_refresh_token_returns_401(monkeypatch):
    async def _bad_decode(*_a, **_k): raise RuntimeError("bad")
    app, client, mod, db, st = _mk_app(monkeypatch, db_results=[], decode_token_impl=_bad_decode)

    r = client.post("/api/v1/admin/refresh", json={"refresh_token": "bad"})
    assert r.status_code == 401
    assert "Invalid refresh token" in r.text


def test_refresh_404_when_user_not_found(monkeypatch):
    user_id = uuid.uuid4()
    app, client, mod, db, st = _mk_app(
        monkeypatch,
        db_results=[None],
        decode_token_impl=lambda *_a, **_k: {"sub": str(user_id), "jti": "J1", "session_id": "S"},
    )
    r = client.post("/api/v1/admin/refresh", json={"refresh_token": "r"})
    assert r.status_code == 404
    assert "User not found" in r.text


def test_refresh_401_when_token_missing_or_revoked(monkeypatch):
    user = UserRow()
    revoked = RefreshTokenRow(jti="J1", user_id=user.id, is_revoked=True)

    app, client, mod, db, st = _mk_app(
        monkeypatch,
        db_results=[user, revoked],
        decode_token_impl=lambda *_a, **_k: {"sub": str(user.id), "jti": "J1"},
    )
    r = client.post("/api/v1/admin/refresh", json={"refresh_token": "r"})
    assert r.status_code == 401
    assert "Invalid or revoked refresh token" in r.text
    assert st["audit_calls"]
    assert st["audit_calls"][-1]["status"] == "REUSE_OR_REVOKED"


def test_refresh_idempotency_replay_uses_snapshot_and_skips_rotation(monkeypatch):
    user = UserRow()
    token_row = RefreshTokenRow(jti="J1", user_id=user.id)
    snapshot = {"access_token": "A", "refresh_token": "R", "token_type": "bearer"}

    def _mk_app_with_snapshot():
        app, client, mod, db, st = _mk_app(
            monkeypatch,
            db_results=[user, token_row],
            decode_token_impl=lambda *_a, **_k: {"sub": str(user.id), "jti": "J1"},
        )
        async def _idem_get(k):
            st["idem_get_calls"].append(k)
            return snapshot
        monkeypatch.setattr(mod.redis_wrapper, "idempotency_get", _idem_get, raising=False)
        return app, client, mod, db, st

    app, client, mod, db, st = _mk_app_with_snapshot()
    r = client.post("/api/v1/admin/refresh", json={"refresh_token": "r"}, headers={"Idempotency-Key": "abc"})
    assert r.status_code == 200
    assert r.json() == snapshot
    assert st["crt_calls"] == []
    assert st["srt_calls"] == []
    assert st["access_calls"] == []
    assert db.commit_calls == 0


def test_refresh_idempotency_snapshot_is_set_on_success(monkeypatch):
    user = UserRow()
    token_row = RefreshTokenRow(jti="J1", user_id=user.id)

    app, client, mod, db, st = _mk_app(
        monkeypatch,
        db_results=[user, token_row],
        decode_token_impl=lambda *_a, **_k: {"sub": str(user.id), "jti": "J1"},
    )
    r = client.post("/api/v1/admin/refresh", json={"refresh_token": "r"}, headers={"Idempotency-Key": "xyz"})
    assert r.status_code == 200

    assert st["idem_set_calls"], "idempotency_set should be called"
    key, body, ttl = st["idem_set_calls"][-1]
    assert "idemp:admin:refresh:J1:xyz" in key
    assert ttl == 600
    assert set(body.keys()) == {"access_token", "refresh_token", "token_type"}


def test_refresh_audit_failure_is_swallowed(monkeypatch):
    user = UserRow()
    token_row = RefreshTokenRow(jti="J1", user_id=user.id)
    app, client, mod, db, st = _mk_app(
        monkeypatch,
        db_results=[user, token_row],
        decode_token_impl=lambda *_a, **_k: {"sub": str(user.id), "jti": "J1"},
    )

    async def _boom(*_a, **_k): raise RuntimeError("audit down")
    monkeypatch.setattr(mod, "log_audit_event", _boom, raising=False)

    r = client.post("/api/v1/admin/refresh", json={"refresh_token": "r"})
    assert r.status_code == 200  # still succeeds despite audit error


def test_refresh_403_when_not_admin(monkeypatch):
    user = UserRow()
    token_row = RefreshTokenRow(jti="J1", user_id=user.id)

    app, client, mod, db, st = _mk_app(
        monkeypatch,
        db_results=[user, token_row],
        decode_token_impl=lambda *_a, **_k: {"sub": str(user.id), "jti": "J1"},
        ensure_admin_ok=False,
    )
    r = client.post("/api/v1/admin/refresh", json={"refresh_token": "r"})
    assert r.status_code == 403
    assert "Insufficient permissions" in r.text
    assert db.commit_calls == 0
