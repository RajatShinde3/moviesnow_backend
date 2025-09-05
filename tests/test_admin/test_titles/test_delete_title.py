# tests/test_admin/test_titles/test_delete_title.py

import importlib
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class FakeDB:
    def __init__(self):
        self.execute_calls: List[Any] = []
        self.commit_calls = 0

    async def execute(self, stmt):
        self.execute_calls.append(stmt)
        # Route doesn't use the result; return anything async-compatible
        return object()

    async def commit(self):
        self.commit_calls += 1


class FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()


class Locks:
    """Records lock usage and returns an async context manager."""
    def __init__(self):
        self.lock_calls: List[Tuple[str, int, int]] = []

    def lock(self, key: str, *, timeout: Optional[int] = None, blocking_timeout: Optional[int] = None):
        self.lock_calls.append((key, timeout, blocking_timeout))

        class _CM:
            async def __aenter__(self_inner):
                return self_inner
            async def __aexit__(self_inner, exc_type, exc, tb):
                return False

        return _CM()


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, audit_raises: bool = False):
    mod = importlib.import_module("app.api.v1.routers.admin.titles")

    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Minimal Title class ref so delete(Title).where(Title.id == ...) is buildable
    TitleCls = type("Title", (), {"id": object()})
    monkeypatch.setattr(mod, "Title", TitleCls, raising=False)

    # Replace sqlalchemy.delete() with a tiny shim supporting .where()
    class _DeleteStmt:
        def __init__(self, entity):
            self.entity = entity
            self.where_called = False
            self.where_args = None

        def where(self, *args, **kwargs):
            self.where_called = True
            self.where_args = (args, kwargs)
            return self

    def _fake_delete(entity):
        return _DeleteStmt(entity)

    monkeypatch.setattr(mod, "delete", _fake_delete, raising=False)

    # Security stubs
    calls = {"ensure_admin": 0, "ensure_mfa": 0}

    async def _ensure_admin(user):  # noqa: ARG001
        calls["ensure_admin"] += 1

    async def _ensure_mfa(request):  # noqa: ARG001
        calls["ensure_mfa"] += 1

    monkeypatch.setattr(mod, "_ensure_admin", _ensure_admin, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ensure_mfa, raising=False)

    # Audit logger
    audit_calls: List[Tuple[str, Dict[str, Any]]] = []

    async def _audit(db, user, action, status, request, meta_data):  # noqa: ARG001
        audit_calls.append((action, meta_data))
        if audit_raises:
            raise RuntimeError("audit down")

    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Redis lock wrapper
    locks = Locks()
    monkeypatch.setattr(mod, "redis_wrapper", locks, raising=False)

    # Build app + overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB()
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, user, calls, locks, audit_calls


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_delete_title_happy_path_executes_delete_commits_no_store_and_audits(monkeypatch):
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch)
    tid = uuid.uuid4()

    resp = client.delete(f"/api/v1/admin/titles/{tid}")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Title deleted"}

    # DB: delete executed and committed
    assert len(db.execute_calls) == 1
    assert db.commit_calls == 1

    # We used a redis lock with the correct key
    assert locks.lock_calls and locks.lock_calls[-1][0] == f"lock:admin_titles:delete:{tid}"

    # Cache headers on success
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Audit captured
    assert audit_calls and audit_calls[-1][0] == "TITLES_DELETE"
    assert audit_calls[-1][1].get("id") == str(tid)

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_delete_title_audit_error_is_swallowed(monkeypatch):
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, audit_raises=True)
    tid = uuid.uuid4()

    resp = client.delete(f"/api/v1/admin/titles/{tid}")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Title deleted"}

    # DB committed despite audit failure
    assert db.commit_calls == 1

    # Cache headers present
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_delete_title_calls_security_checks(monkeypatch):
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch)
    tid = uuid.uuid4()

    resp = client.delete(f"/api/v1/admin/titles/{tid}")
    assert resp.status_code == 200
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_delete_title_uses_custom_delete_stub_and_where(monkeypatch):
    """Sanity-check our delete shim got constructed with Title and had .where() called."""
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch)
    tid = uuid.uuid4()

    resp = client.delete(f"/api/v1/admin/titles/{tid}")
    assert resp.status_code == 200

    # Our fake delete stmt should be the one recorded
    stmt = db.execute_calls[-1]
    # It is an instance of our _DeleteStmt and should have seen .where()
    assert getattr(stmt, "entity", None) is mod.Title
    assert getattr(stmt, "where_called", False) is True
