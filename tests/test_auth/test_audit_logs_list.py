import importlib
import uuid
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.testclient import TestClient


class _FakeResult:
    def __init__(self, rows): self._rows = rows
    def scalars(self):
        class _S:
            def __init__(self, rows): self._rows = rows
            def all(self): return list(self._rows)
        return _S(self._rows)


class _FakeDB:
    def __init__(self, rows): self.rows = rows
    async def execute(self, *_a, **_k): return _FakeResult(self.rows)


class _Row:
    def __init__(self):
        self.id = uuid.uuid4()
        self.user_id = uuid.uuid4()
        self.action = "LOGIN"
        self.status = "SUCCESS"
        self.occurred_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
        self.ip_address = "127.0.0.1"
        self.user_agent = "pytest"
        self.metadata_json = {"k": "v"}
        self.request_id = "rid-1"


def _mk_app(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.auth.audit_log")

    # Disable rate limiting
    async def _no_rate_limit(*_, **__): return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # Current user as admin
    class _U: pass
    u = _U(); u.is_superuser = True
    async def _get_user(): return u
    monkeypatch.setattr(mod, "get_current_user", _get_user, raising=False)

    # Simple admin check
    monkeypatch.setattr(mod, "_is_admin", lambda _u: True, raising=False)

    # DB rows
    db = _FakeDB([_Row()])
    monkeypatch.setattr(mod, "get_async_db", lambda: db, raising=False)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/auth")
    return app, TestClient(app)


def test_list_audit_logs_happy(monkeypatch):
    app, client = _mk_app(monkeypatch)
    r = client.get("/api/v1/auth/audit-logs/audit?limit=1")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list) and len(body) == 1
    assert body[0]["action"] == "LOGIN"
    cc = (r.headers.get("Cache-Control") or "").lower()
    assert "no-store" in cc

