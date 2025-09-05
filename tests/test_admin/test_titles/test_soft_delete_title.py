# tests/test_admin/test_titles/test_soft_delete_title.py

import importlib
import uuid
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class TitleRow:
    def __init__(self, *, deleted: bool = False):
        self.id = uuid.uuid4()
        self.deleted_at = object() if deleted else None


class FakeDB:
    """Minimal async DB facade tracking select/update + commit usage."""
    def __init__(self, row: Optional[TitleRow]):
        self._row = row
        self.last_stmt = None
        self.select_calls = 0
        self.update_calls: List[Any] = []
        self.commit_calls = 0

    async def execute(self, stmt):
        self.last_stmt = stmt
        kind = getattr(stmt, "_kind", None)

        # SELECT path returns a result with scalar_one_or_none()
        if kind == "select":
            self.select_calls += 1

            class _Res:
                def __init__(self, row): self._row = row
                def scalar_one_or_none(self): return self._row
            return _Res(self._row)

        # UPDATE path just record the stmt and return a dummy object
        if kind == "update":
            self.update_calls.append(stmt)
            return object()

        # Default: record and return dummy
        return object()

    async def commit(self):
        self.commit_calls += 1


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
# SQLA shims used by the route (select/update/func.now)
# ─────────────────────────────────────────────────────────────────────────────

class _SelectStmt:
    _kind = "select"
    def __init__(self, entity): self.entity = entity
    def where(self, *a, **k): return self
    def with_for_update(self): return self

class _UpdateStmt:
    _kind = "update"
    def __init__(self, entity):
        self.entity = entity
        self.where_called = False
        self.where_args = None
        self.values_dict: Dict[str, Any] = {}
    def where(self, *a, **k):
        self.where_called = True
        self.where_args = (a, k)
        return self
    def values(self, **kw):
        self.values_dict.update(kw)
        return self

def _fake_select(entity): return _SelectStmt(entity)
def _fake_update(entity): return _UpdateStmt(entity)

class _Func:
    @staticmethod
    def now():
        return "NOW()"  # placeholder


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    row: Optional[TitleRow],
    audit_raises: bool = False,
):
    mod = importlib.import_module("app.api.v1.routers.admin.titles")

    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Minimal Title class so the route can reference Title.id
    TitleCls = type("Title", (), {"id": object()})
    monkeypatch.setattr(mod, "Title", TitleCls, raising=False)

    # Patch SQLA helpers used by the route
    monkeypatch.setattr(mod, "select", _fake_select, raising=False)
    monkeypatch.setattr(mod, "update", _fake_update, raising=False)
    monkeypatch.setattr(mod, "func", _Func, raising=False)

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

    db = FakeDB(row=row)
    user = SimpleNamespace(id=uuid.uuid4())
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, user, calls, locks, audit_calls


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_soft_delete_happy_path_marks_deleted_commits_audits_and_no_store(monkeypatch):
    row = TitleRow(deleted=False)
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, row=row)

    resp = client.post(f"/api/v1/admin/titles/{row.id}/soft-delete")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Soft-deleted"}

    # One select + one update and a commit
    assert db.select_calls == 1
    assert len(db.update_calls) == 1
    assert db.commit_calls == 1

    # Update statement captured with deleted_at value set
    upd = db.update_calls[-1]
    assert getattr(upd, "where_called", False) is True
    assert "deleted_at" in getattr(upd, "values_dict", {})

    # Lock key correct
    assert locks.lock_calls and locks.lock_calls[-1][0] == f"lock:admin_titles:soft_delete:{row.id}"

    # Cache headers
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Audit captured
    assert audit_calls and audit_calls[-1][0] == "TITLES_DELETE_SOFT"
    assert audit_calls[-1][1].get("id") == str(row.id)

    # Security checks
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_soft_delete_already_deleted_is_idempotent_and_no_store(monkeypatch):
    row = TitleRow(deleted=True)
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, row=row)

    resp = client.post(f"/api/v1/admin/titles/{row.id}/soft-delete")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Already deleted"}

    # No update, no commit when idempotent branch is taken
    assert db.select_calls == 1
    assert db.update_calls == []
    assert db.commit_calls == 0

    # Cache headers still applied
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Security checks
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_soft_delete_404_when_missing_sets_no_store(monkeypatch):
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, row=None)

    tid = uuid.uuid4()
    resp = client.post(f"/api/v1/admin/titles/{tid}/soft-delete")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Title not found"}

    # Headers from HTTPException
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # No update/commit on 404
    assert db.update_calls == []
    assert db.commit_calls == 0

    # Security checks
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_soft_delete_audit_error_is_swallowed(monkeypatch):
    row = TitleRow(deleted=False)
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, row=row, audit_raises=True)

    resp = client.post(f"/api/v1/admin/titles/{row.id}/soft-delete")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Soft-deleted"}

    # DB committed even if audit failed
    assert db.commit_calls == 1

    # Cache headers present
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_soft_delete_calls_security_checks_and_uses_lock(monkeypatch):
    row = TitleRow(deleted=False)
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, row=row)

    resp = client.post(f"/api/v1/admin/titles/{row.id}/soft-delete")
    assert resp.status_code == 200
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
    assert locks.lock_calls and locks.lock_calls[-1][0] == f"lock:admin_titles:soft_delete:{row.id}"
