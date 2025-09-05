# tests/test_admin/test_series/test_delete_episode.py

import importlib
import uuid
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes / doubles
# ─────────────────────────────────────────────────────────────────────────────

class FakeDB:
    """AsyncSession-ish stub that records execute/commit calls."""
    def __init__(self):
        self.exec_calls: List[Any] = []
        self.commit_calls = 0

    async def execute(self, query, *_a, **_k):
        self.exec_calls.append(query)
        return None

    async def commit(self):
        self.commit_calls += 1


class FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    admin_ok: bool = True,
    mfa_ok: bool = True,
):
    mod = importlib.import_module("app.api.v1.routers.admin.series")

    # Disable SlowAPI rate limiting for tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # ADMIN / MFA gates
    async def _ensure_admin(user):
        if not admin_ok:
            raise HTTPException(status_code=403, detail="Insufficient permissions")

    async def _ensure_mfa(request):
        if not mfa_ok:
            raise HTTPException(status_code=401, detail="MFA required")

    monkeypatch.setattr(mod, "_ensure_admin", _ensure_admin, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ensure_mfa, raising=False)

    # Capture audit calls
    audit_calls: List[Dict[str, Any]] = []

    async def _audit(*_a, **k):
        audit_calls.append(k)
        return None

    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Build app with dependency overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB()
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap SlowAPI @rate_limit to avoid 429 during tests
    path = "/api/v1/admin/episodes/{episode_id}"
    for route in app.routes:
        if getattr(route, "path", None) == path and "DELETE" in getattr(route, "methods", set()):
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn
            break

    client = TestClient(app)
    return app, client, mod, db, {"audit_calls": audit_calls}


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_delete_episode_happy_path_executes_delete_commits_audits_and_no_store(monkeypatch):
    app, client, mod, db, st = _mk_app(monkeypatch, admin_ok=True, mfa_ok=True)
    eid = uuid.uuid4()

    r = client.delete(f"/api/v1/admin/episodes/{eid}")
    assert r.status_code == 200, r.text
    assert r.json() == {"message": "Episode deleted"}

    # DB delete executed and committed
    assert len(db.exec_calls) == 1
    assert db.commit_calls == 1

    # Cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # Audit called with episode_id
    assert st["audit_calls"], "log_audit_event should be invoked"
    meta = st["audit_calls"][-1]["meta_data"]
    assert meta.get("episode_id") == str(eid)


def test_delete_episode_forbidden_when_not_admin(monkeypatch):
    app, client, mod, db, st = _mk_app(monkeypatch, admin_ok=False, mfa_ok=True)
    eid = uuid.uuid4()

    r = client.delete(f"/api/v1/admin/episodes/{eid}")
    assert r.status_code == 403
    assert "Insufficient permissions" in r.text

    # No DB writes or audit when forbidden
    assert db.commit_calls == 0
    assert len(db.exec_calls) == 0
    assert st["audit_calls"] == []


def test_delete_episode_blocked_when_mfa_required(monkeypatch):
    app, client, mod, db, st = _mk_app(monkeypatch, admin_ok=True, mfa_ok=False)
    eid = uuid.uuid4()

    r = client.delete(f"/api/v1/admin/episodes/{eid}")
    assert r.status_code == 401
    assert "MFA required" in r.text

    # No DB writes or audit when MFA gate fails
    assert db.commit_calls == 0
    assert len(db.exec_calls) == 0
    assert st["audit_calls"] == []
