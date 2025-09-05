import importlib
import uuid
from typing import Any, List, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient


class _Scalars:
    def __init__(self, rows: List[Any]):
        self._rows = rows
    def all(self):
        return list(self._rows)


class _Result:
    def __init__(self, rows: List[Any]):
        self._rows = rows
    def scalars(self):
        return _Scalars(self._rows)


class FakeDB:
    def __init__(self, rows: List[Any]):
        self._rows = rows
        self.execute_calls: List[Any] = []
    async def execute(self, query, *a, **k):
        self.execute_calls.append(query)
        return _Result(self._rows)


class FakeUser:
    def __init__(self, *, id: Optional[uuid.UUID] = None, role: str = "ADMIN"):
        self.id = id or uuid.uuid4()
        self.role = role


class UserRow:
    def __init__(self, *, email: str, role: str = "ADMIN", id: Optional[uuid.UUID] = None,
                 full_name: Optional[str] = None, is_active: bool = True):
        self.id = id or uuid.uuid4()
        self.email = email
        self.role = role
        self.full_name = full_name
        self.is_active = is_active


def _mk_app(monkeypatch, *, rows: List[Any], caller_role: str = "ADMIN"):
    mod = importlib.import_module("app.api.v1.routers.orgs.admin")

    # Disable rate limiter wrapping
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/orgs/admin")

    db = FakeDB(rows)
    user = FakeUser(role=caller_role)
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    return app, TestClient(app), mod, db, user


def test_list_admins_happy_path(monkeypatch):
    rows = [
        UserRow(email="a1@example.com"),
        UserRow(email="a2@example.com"),
    ]
    app, client, mod, db, user = _mk_app(monkeypatch, rows=rows)

    r = client.get("/api/v1/orgs/admin/admins")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list) and len(data) == 2
    # role is a string containing ADMIN (exact value may be Enum string)
    assert all("ADMIN" in item.get("role", "") for item in data)
    # no-store headers
    assert (r.headers.get("Cache-Control") or "").startswith("no-store")
    assert r.headers.get("Pragma") == "no-cache"


def test_list_admins_forbidden_when_non_admin(monkeypatch):
    app, client, mod, db, user = _mk_app(monkeypatch, rows=[], caller_role="USER")
    r = client.get("/api/v1/orgs/admin/admins")
    assert r.status_code == 403

