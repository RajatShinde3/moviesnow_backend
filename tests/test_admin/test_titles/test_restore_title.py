# tests/test_admin/test_titles/test_restore_title.py

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
    def __init__(self, *, deleted: bool = True):
        self.id = uuid.uuid4()
        # deleted=True => has a deleted_at value; deleted=False => active
        self.deleted_at = object() if deleted else None


class FakeDB:
    """Tiny async DB double recording select/update + commit usage."""
    def __init__(self, row: Optional[TitleRow]):
        self._row = row
        self.last_stmt = None
        self.select_calls = 0
        self.update_calls: List[Any] = []
        self.commit_calls = 0

    async def execute(self, stmt):
        self.last_stmt = stmt
        kind = getattr(stmt, "_kind", None)

        if kind == "select":
            self.select_calls += 1

            class _Res:
                def __init__(self, row): self._row = row
                def scalar_one_or_none(self): return self._row
            return _Res(self._row)

        if kind == "update":
            self.update_calls.append(stmt)
            return object()

        return object()

    async def commit(self):
        self.commit_calls += 1


class Locks:
    """Records lock usage; returns a no-op async context manager."""
    def __init__(self):
        self.lock_calls: List[Tuple[str, int, int]] = []

    def lock(self, key: str, *, timeout: Optional[int] = None, blocking_timeout: Optional[int] = None):
        self.lock_calls.append((key, timeout, blocking_timeout))

        class _CM:
            async def __aenter__(self_inner): return self_inner
            async def __aexit__(self_inner, exc_type, exc, tb): return False
        return _CM()


# ─────────────────────────────────────────────────────────────────────────────
# SQLAlchemy-ish shims used by the route (select/update)
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

    # Minimal Title class so the route can reference Title.id in filters
    TitleCls = type("Title", (), {"id": object()})
    monkeypatch.setattr(mod, "Title", TitleCls, raising=False)

    # Patch SQLA helpers used by the route
    monkeypatch.setattr(mod, "select", _fake_select, raising=False)
    monkeypatch.setattr(mod, "update", _fake_update, raising=False)

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

def test_restore_happy_path_clears_deleted_at_commits_audits_and_no_store(monkeypatch):
    row = TitleRow(deleted=True)  # currently soft-deleted
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, row=row)

    resp = client.post(f"/api/v1/admin/titles/{row.id}/restore")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Restored"}

    # One select + one update + one commit
    assert db.select_calls == 1
    assert len(db.update_calls) == 1
    assert db.commit_calls == 1

    # Update statement sets deleted_at to None
    upd = db.update_calls[-1]
    assert getattr(upd, "where_called", False) is True
    assert upd.values_dict.get("deleted_at", "MISSING") is None

    # Lock key used
    assert locks.lock_calls and locks.lock_calls[-1][0] == f"lock:admin_titles:restore:{row.id}"

    # Cache headers present
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Audit captured
    assert audit_calls and audit_calls[-1][0] == "TITLES_RESTORE"
    assert audit_calls[-1][1].get("id") == str(row.id)

    # Security checks were called
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_restore_already_active_is_idempotent_and_no_store(monkeypatch):
    row = TitleRow(deleted=False)  # not deleted
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, row=row)

    resp = client.post(f"/api/v1/admin/titles/{row.id}/restore")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Already active"}

    # No update/commit on idempotent path
    assert db.select_calls == 1
    assert db.update_calls == []
    assert db.commit_calls == 0

    # Cache headers still applied
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Security checks
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_restore_404_when_missing_sets_no_store(monkeypatch):
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, row=None)

    tid = uuid.uuid4()
    resp = client.post(f"/api/v1/admin/titles/{tid}/restore")
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


def test_restore_audit_error_is_swallowed(monkeypatch):
    row = TitleRow(deleted=True)
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, row=row, audit_raises=True)

    resp = client.post(f"/api/v1/admin/titles/{row.id}/restore")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Restored"}

    # DB committed even if audit failed
    assert db.commit_calls == 1

    # Cache headers present
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_restore_calls_security_checks_and_uses_lock(monkeypatch):
    row = TitleRow(deleted=True)
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, row=row)

    resp = client.post(f"/api/v1/admin/titles/{row.id}/restore")
    assert resp.status_code == 200
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
    assert locks.lock_calls and locks.lock_calls[-1][0] == f"lock:admin_titles:restore:{row.id}"
