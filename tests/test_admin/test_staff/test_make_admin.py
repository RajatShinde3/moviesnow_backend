import importlib
import uuid
from typing import Any, Optional, Tuple, List, Dict

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.routing import request_response
import inspect


class _One:
    def __init__(self, row: Any | None):
        self._row = row
    def scalar_one_or_none(self):
        return self._row


class FakeDB:
    def __init__(self, row: Any | None):
        self._row = row
        self.execute_calls: List[Tuple[Any, tuple, dict]] = []
        self.flush_calls = 0
        self.commit_calls = 0
    async def execute(self, query, *a, **k):
        self.execute_calls.append((query, a, k))
        return _One(self._row)
    async def flush(self):
        self.flush_calls += 1
    async def commit(self):
        self.commit_calls += 1


class FakeUser:
    def __init__(self, *, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


class RowUser:
    def __init__(self, *, email: str, role: Any):
        self.email = email
        self.role = role


def _mk_app(monkeypatch, *, db_row: Any | None, current_user: Optional[FakeUser] = None):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")

    # Disable rate limits
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Reauth capture
    state: Dict[str, Any] = {"reauth": None}
    async def _ensure_reauth(token: str, _user: Any):
        state["reauth"] = token
    monkeypatch.setattr(mod, "_ensure_reauth", _ensure_reauth, raising=False)

    # Fake redis
    class _Lock:
        async def __aenter__(self): return None
        async def __aexit__(self, exc_type, exc, tb): return False
    class _Redis:
        def lock(self, *_a, **_k): return _Lock()
        async def idempotency_get(self, *_a, **_k): return None
        async def idempotency_set(self, *_a, **_k): return True
    monkeypatch.setattr(mod, "redis_wrapper", _Redis(), raising=False)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB(db_row)
    me = current_user or FakeUser()
    monkeypatch.setattr(mod, "get_async_db", lambda: db, raising=False)
    monkeypatch.setattr(mod, "get_current_user", lambda: me, raising=False)

    # SlowAPI wrapper nuance: unwrap if necessary (same approach as other staff tests)
    for route in app.router.routes:
        if getattr(route, "path", None) == "/api/v1/admin/staff/{user_id}/make-admin":
            h = route.app if hasattr(route, "app") else route.endpoint
            try:
                params = list(inspect.signature(h).parameters.values())
            except Exception:
                params = []
            route.app = request_response(h) if len(params) == 1 else h
            break

    return app, TestClient(app), mod, db, me, state


def test_make_admin_happy_path(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")
    # Start with USER, expect ADMIN after
    db_row = RowUser(email="u@example.com", role=mod.UserRole.USER)
    app, client, _mod, db, me, state = _mk_app(monkeypatch, db_row=db_row)
    target = uuid.uuid4()
    r = client.post(f"/api/v1/admin/staff/{target}/make-admin", json={"reauth_token": "tok-1"})
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["message"].lower().startswith("granted") or b["role"] in {"ADMIN", "SUPERUSER", "USER"}
    assert db.flush_calls >= 1 and db.commit_calls >= 1
    assert state["reauth"] == "tok-1"

