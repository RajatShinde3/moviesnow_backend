# tests/test_admin/test_series/test_delete_season.py

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
        # route doesn't inspect result
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

    # Disable SlowAPI RL in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Gate controls
    async def _ensure_admin(_user):
        if not admin_ok:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
    async def _ensure_mfa(_request):
        if not mfa_ok:
            raise HTTPException(status_code=401, detail="MFA required")

    monkeypatch.setattr(mod, "_ensure_admin", _ensure_admin, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ensure_mfa, raising=False)

    # No-op audit but capture meta
    audit_calls: List[Dict[str, Any]] = []
    async def _audit(*_a, **k):
        audit_calls.append(k)
        return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Build app + overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB()
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap SlowAPI rate-limit decorator (only replace endpoint)
    path = "/api/v1/admin/seasons/{season_id}"
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

def test_delete_season_happy_path_deletes_commits_audits_and_no_store(monkeypatch):
    app, client, mod, db, st = _mk_app(monkeypatch, admin_ok=True, mfa_ok=True)
    sid = uuid.uuid4()

    r = client.delete(f"/api/v1/admin/seasons/{sid}")
    assert r.status_code == 200, r.text
    assert r.json() == {"message": "Season deleted"}

    # DB delete called once and commit performed
    assert len(db.exec_calls) == 1
    assert db.commit_calls == 1

    # Cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # Audit captured with season_id in meta
    assert st["audit_calls"], "log_audit_event should be called"
    meta = st["audit_calls"][-1]["meta_data"]
    assert meta.get("season_id") == str(sid)


def test_delete_season_forbidden_when_not_admin(monkeypatch):
    app, client, mod, db, st = _mk_app(monkeypatch, admin_ok=False, mfa_ok=True)
    sid = uuid.uuid4()

    r = client.delete(f"/api/v1/admin/seasons/{sid}")
    assert r.status_code == 403
    assert "Insufficient permissions" in r.text

    # No write happened
    assert db.commit_calls == 0
    assert len(db.exec_calls) == 0
    assert st["audit_calls"] == []


def test_delete_season_blocked_when_mfa_required(monkeypatch):
    app, client, mod, db, st = _mk_app(monkeypatch, admin_ok=True, mfa_ok=False)
    sid = uuid.uuid4()

    r = client.delete(f"/api/v1/admin/seasons/{sid}")
    assert r.status_code == 401
    assert "MFA required" in r.text

    # No write happened
    assert db.commit_calls == 0
    assert len(db.exec_calls) == 0
    assert st["audit_calls"] == []
