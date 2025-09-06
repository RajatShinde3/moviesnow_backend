import importlib
import uuid
from fastapi import FastAPI
from fastapi.testclient import TestClient


class _FakeDB:
    def __init__(self):
        self.executed = False
        self.commits = 0
    async def execute(self, _stmt):
        self.executed = True
        class _R:
            def scalars(self):
                return []
        return _R()
    async def commit(self):
        self.commits += 1


def _mk_app(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.admin.sessions")

    # Disable limiter
    async def _no_rate_limit(*_, **__):
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # Gates no-op
    async def _ok(*_, **__):
        return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # get_current_user -> admin stub
    class _U:
        id = uuid.uuid4()
    monkeypatch.setattr(mod, "get_current_user", lambda: _U(), raising=False)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = _FakeDB()
    monkeypatch.setattr(mod, "get_async_db", lambda: db, raising=False)

    return app, TestClient(app), db


def test_revoke_other_sessions_revokes_and_no_store(monkeypatch):
    app, client, db = _mk_app(monkeypatch)

    r = client.post("/api/v1/admin/sessions/revoke-others")
    assert r.status_code == 200
    assert r.json().get("revoked") in {"others", "all"}
    assert db.executed and db.commits >= 1
    cc = (r.headers.get("Cache-Control") or "").lower()
    assert "no-store" in cc

