# tests/test_admin/test_sessions/test_list_sessions.py

import importlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Callable

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Minimal DB + rows
# ─────────────────────────────────────────────────────────────────────────────

class _Scalars:
    def __init__(self, rows): self._rows = rows
    def all(self): return list(self._rows or [])

class _Result:
    def __init__(self, rows): self._rows = rows
    def scalars(self): return _Scalars(self._rows)

class FakeDB:
    """Return a fixed list of rows for any .execute()."""
    def __init__(self, rows: List[Any]): self._rows = rows; self.executed = []
    async def execute(self, query, *_a, **_k):
        self.executed.append(query)
        return _Result(self._rows)


class UserRow:
    def __init__(self, *, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


class RefreshTokenRow:
    def __init__(
        self,
        *,
        jti: str,
        user_id: uuid.UUID,
        session_id: Optional[str] = None,
        is_revoked: bool = False,
        expires_at: Optional[str] = None,
        created_at: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        # Keep attrs simple; route just getattr()s them
        self.jti = jti
        self.user_id = user_id
        self.session_id = session_id
        self.is_revoked = is_revoked
        # keep as ISO strings or datetime — route passes through as-is
        self.expires_at = expires_at or datetime(2025, 1, 1, tzinfo=timezone.utc).isoformat()
        self.created_at = created_at or datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc).isoformat()
        self.ip_address = ip_address
        self.user_agent = user_agent


# ─────────────────────────────────────────────────────────────────────────────
# Test app factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    rows: List[Any],
    decode_token_impl: Optional[Callable[..., Dict[str, Any]]] = None,
    ensure_admin_ok: bool = True,
    ensure_mfa_ok: bool = True,
    include_meta_columns: Optional[List[str]] = None,
):
    mod = importlib.import_module("app.api.v1.routers.admin.sessions")

    # Disable rate limiting
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # RBAC/MFA gates
    async def _ok(*_a, **_k): return None
    if ensure_admin_ok:
        monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    else:
        async def _deny(*_a, **_k): raise HTTPException(status_code=403, detail="Insufficient permissions")
        monkeypatch.setattr(mod, "_ensure_admin", _deny, raising=False)

    if ensure_mfa_ok:
        monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)
    else:
        async def _mfa_deny(*_a, **_k): raise HTTPException(status_code=403, detail="MFA required")
        monkeypatch.setattr(mod, "_ensure_mfa", _mfa_deny, raising=False)

    # No-op audit
    async def _audit(*_a, **_k): return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Token decode (async)
    if decode_token_impl is None:
        async def _dec(_bearer, expected_types=None, verify_revocation=False):
            return {"session_id": "sess-cur"}
        decode_token_impl = _dec
    monkeypatch.setattr(mod, "decode_token", decode_token_impl, raising=False)

    # Optionally pretend these columns exist on the model
    if include_meta_columns is not None:
        class _Cols:
            def keys(self): return list(include_meta_columns)
        monkeypatch.setattr(mod.RefreshToken.__table__, "columns", _Cols(), raising=False)

    # Build app with dependency overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(rows)
    user = UserRow()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user
    client = TestClient(app)
    return app, client, mod, db, {"user": user}


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_list_sessions_happy_path_sets_no_store_and_current_flag(monkeypatch):
    user = UserRow()
    # two sessions; mark second as "current" via decode_token
    rows = [
        RefreshTokenRow(jti="J-older", user_id=user.id, session_id="sess-1",
                        created_at=datetime(2025,1,1,10,0,tzinfo=timezone.utc).isoformat()),
        RefreshTokenRow(jti="J-cur", user_id=user.id, session_id="sess-cur",
                        created_at=datetime(2025,1,1,12,0,tzinfo=timezone.utc).isoformat()),
    ]
    async def _dec(_bearer, expected_types=None, verify_revocation=False):
        return {"session_id": "sess-cur"}

    app, client, mod, db, st = _mk_app(monkeypatch, rows=rows, decode_token_impl=_dec)
    r = client.get("/api/v1/admin/sessions", headers={"Authorization": "Bearer A"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data, list) and len(data) == 2

    # cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # shape + current flag
    got_ids = {item["session_id"] for item in data}
    assert {"sess-1", "sess-cur"} <= got_ids
    cur_items = [it for it in data if it.get("current")]
    assert len(cur_items) == 1 and cur_items[0]["session_id"] == "sess-cur"


def test_list_sessions_decode_errors_are_ignored(monkeypatch):
    async def _bad_decode(*_a, **_k): raise RuntimeError("decode failed")

    user = UserRow()
    rows = [
        RefreshTokenRow(jti="J1", user_id=user.id, session_id="S1"),
        RefreshTokenRow(jti="J2", user_id=user.id, session_id="S2"),
    ]
    app, client, mod, db, st = _mk_app(monkeypatch, rows=rows, decode_token_impl=_bad_decode)
    r = client.get("/api/v1/admin/sessions")  # no Authorization header (also fine)
    assert r.status_code == 200
    data = r.json()
    assert all(not it.get("current") for it in data)  # nothing marked current


def test_list_sessions_includes_optional_meta_when_columns_present(monkeypatch):
    user = UserRow()
    rows = [
        RefreshTokenRow(
            jti="J1", user_id=user.id, session_id="S1",
            ip_address="203.0.113.10", user_agent="UA/1",
        )
    ]
    app, client, mod, db, st = _mk_app(
        monkeypatch,
        rows=rows,
        include_meta_columns=["ip_address", "user_agent"],
    )
    r = client.get("/api/v1/admin/sessions", headers={"Authorization": "Bearer A"})
    assert r.status_code == 200
    item = r.json()[0]
    # present since we pretended those columns exist
    assert item.get("ip_address") == "203.0.113.10"
    assert item.get("user_agent") == "UA/1"


def test_list_sessions_current_matches_jti_when_session_id_missing(monkeypatch):
    user = UserRow()
    row = RefreshTokenRow(jti="JONLY", user_id=user.id, session_id=None)

    # Make the attribute *absent* so getattr(..., "session_id", <fallback>) uses the fallback.
    try:
        delattr(row, "session_id")
    except Exception:
        row.__dict__.pop("session_id", None)

    # If decode returns session_id == jti, route should mark it current
    async def _dec(_bearer, *_a, **_k):
        return {"session_id": "JONLY"}

    app, client, mod, db, st = _mk_app(monkeypatch, rows=[row], decode_token_impl=_dec)
    r = client.get("/api/v1/admin/sessions", headers={"Authorization": "Bearer A"})
    assert r.status_code == 200
    item = r.json()[0]
    assert item["session_id"] == "JONLY"   # fell back to jti
    assert item["current"] is True         # marked as current



def test_list_sessions_empty_list_ok(monkeypatch):
    app, client, mod, db, st = _mk_app(monkeypatch, rows=[])
    r = client.get("/api/v1/admin/sessions")
    assert r.status_code == 200
    assert r.json() == []


def test_list_sessions_403_when_not_admin(monkeypatch):
    app, client, mod, db, st = _mk_app(monkeypatch, rows=[], ensure_admin_ok=False)
    r = client.get("/api/v1/admin/sessions")
    assert r.status_code == 403
    assert "Insufficient permissions" in r.text


def test_list_sessions_403_when_mfa_check_fails(monkeypatch):
    app, client, mod, db, st = _mk_app(monkeypatch, rows=[], ensure_mfa_ok=False)
    r = client.get("/api/v1/admin/sessions")
    assert r.status_code == 403
    assert "MFA required" in r.text
