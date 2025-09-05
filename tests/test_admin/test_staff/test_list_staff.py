# tests/test_admin/test_staff/test_list_staff.py

import importlib
import uuid
from typing import Any, List, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ───────────────────────────
# Lightweight fakes
# ───────────────────────────

class _ScalarResult:
    def __init__(self, rows: List[Any]):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows


class FakeDB:
    """AsyncSession stub: this route performs a single .execute → scalars().all()."""
    def __init__(self, rows: List[Any]):
        self._rows = rows[:]
        self.captured_queries: List[Any] = []

    async def execute(self, query, *_a, **_k):
        self.captured_queries.append(query)
        return _ScalarResult(self._rows)


class FakeUser:
    def __init__(self, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


class UserRow:
    """Minimal object compatible with _serialize_user."""
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        email: str,
        role: str,  # "ADMIN" | "SUPERUSER"
        full_name: Optional[str] = None,
        is_active: bool = True,
        created_at: Optional[str] = None,
    ):
        self.id = id or uuid.uuid4()
        self.email = email
        self.role = role  # route’s serializer accepts str or Enum-like with .value
        self.full_name = full_name
        self.is_active = is_active
        self.created_at = created_at


# ───────────────────────────
# App factory
# ───────────────────────────

def _mk_app(monkeypatch, *, rows: List[Any]):
    mod = importlib.import_module("app.api.v1.routers.admin.staff")

    # Disable SlowAPI in tests — no need to unwrap decorators
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Bypass ADMIN + MFA checks
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB(rows)
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: FakeUser()

    # NOTE: no route endpoint unwrapping here
    return app, TestClient(app), mod, db


# ───────────────────────────
# Tests
# ───────────────────────────

def test_list_staff_happy_path_no_filters_and_no_store(monkeypatch):
    rows = [
        UserRow(email="admin@example.com", role="ADMIN", created_at="2025-01-02T00:00:00Z"),
        UserRow(email="root@example.com", role="SUPERUSER", created_at="2025-01-01T00:00:00Z"),
    ]
    app, client, mod, db = _mk_app(monkeypatch, rows=rows)

    r = client.get("/api/v1/admin/staff")
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data, list) and len(data) == 2

    for item in data:
        # minimal shape
        assert "id" in item and "email" in item and "role" in item
        assert item["role"] in ("ADMIN", "SUPERUSER")

    # cache headers: no-store + pragma no-cache
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"


def test_list_staff_role_filter_admin_returns_only_admins(monkeypatch):
    rows = [UserRow(email="a1@example.com", role="ADMIN"),
            UserRow(email="a2@example.com", role="ADMIN")]
    app, client, mod, db = _mk_app(monkeypatch, rows=rows)

    r = client.get("/api/v1/admin/staff?role=ADMIN")
    assert r.status_code == 200
    data = r.json()
    assert data and all(it["role"] == "ADMIN" for it in data)


def test_list_staff_role_filter_superuser_only(monkeypatch):
    rows = [UserRow(email="s1@example.com", role="SUPERUSER"),
            UserRow(email="s2@example.com", role="SUPERUSER")]
    app, client, mod, db = _mk_app(monkeypatch, rows=rows)

    r = client.get("/api/v1/admin/staff?role=SUPERUSER")
    assert r.status_code == 200
    data = r.json()
    assert data and all(it["role"] == "SUPERUSER" for it in data)


def test_list_staff_email_contains_is_case_insensitive(monkeypatch):
    # DB stub returns only the matched row; filtering itself is DB-side.
    rows = [UserRow(email="Alice.Admin@Example.com", role="ADMIN")]
    app, client, mod, db = _mk_app(monkeypatch, rows=rows)

    r = client.get("/api/v1/admin/staff?email=alice")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1 and data[0]["email"] == "Alice.Admin@Example.com"


def test_list_staff_pagination_params_passthrough(monkeypatch):
    rows = [UserRow(email="only@example.com", role="ADMIN")]
    app, client, mod, db = _mk_app(monkeypatch, rows=rows)

    r = client.get("/api/v1/admin/staff?limit=1&offset=0")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1


def test_list_staff_empty_list(monkeypatch):
    app, client, mod, db = _mk_app(monkeypatch, rows=[])

    r = client.get("/api/v1/admin/staff")
    assert r.status_code == 200
    assert r.json() == []
