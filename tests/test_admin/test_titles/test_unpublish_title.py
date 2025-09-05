# tests/test_admin/test_titles/test_unpublish_title.py

import importlib
import uuid
from typing import Optional, Any, Dict, Tuple, List

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class TitleRow:
    def __init__(self, *, is_published: bool = True):
        self.id = uuid.uuid4()
        self.is_published = is_published


class FakeResult:
    def __init__(self, row):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


class FakeDB:
    def __init__(self, *, row: Optional[TitleRow]):
        self._row = row
        self.flush_calls = 0
        self.commit_calls = 0

    async def execute(self, stmt):  # noqa: ARG002 - statement ignored
        return FakeResult(self._row)

    async def flush(self):
        self.flush_calls += 1

    async def commit(self):
        self.commit_calls += 1


class FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()


class Locks:
    """Record lock usage; returns an async context manager."""
    def __init__(self):
        self.lock_calls: List[Tuple[str, int, int]] = []

    def lock(self, key: str, *, timeout: int | None = None, blocking_timeout: int | None = None):
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

def _mk_app(
    monkeypatch,
    *,
    row: Optional[TitleRow],
    audit_raises: bool = False,
):
    mod = importlib.import_module("app.api.v1.routers.admin.titles")

    # Disable rate limiting for tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Minimal Title class reference so attribute access works; we stub select too.
    TitleCls = type("Title", (), {"id": object()})
    monkeypatch.setattr(mod, "Title", TitleCls, raising=False)

    # Replace sqlalchemy.select with a tiny shim supporting .where().with_for_update()
    def _fake_select(_entity):
        class _Stmt:
            def where(self, *args, **kwargs):
                return self
            def with_for_update(self):
                return self
        return _Stmt()
    monkeypatch.setattr(mod, "select", _fake_select, raising=False)

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

    # Build app + DI overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB(row=row)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, user, calls, locks, audit_calls


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_unpublish_title_happy_path_flips_flag_and_no_store_and_audits(monkeypatch):
    row = TitleRow(is_published=True)
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, row=row)

    resp = client.post(f"/api/v1/admin/titles/{row.id}/unpublish")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Unpublished"}

    # Flag flipped + DB writes
    assert row.is_published is False
    assert db.flush_calls == 1
    assert db.commit_calls == 1

    # Lock used with correct key
    assert locks.lock_calls and locks.lock_calls[-1][0] == f"lock:admin_titles:unpublish:{row.id}"

    # Cache headers
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Audit recorded
    assert audit_calls and audit_calls[-1][0] == "TITLES_UNPUBLISH"

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_unpublish_title_idempotent_when_already_unpublished(monkeypatch):
    row = TitleRow(is_published=False)
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, row=row)

    resp = client.post(f"/api/v1/admin/titles/{row.id}/unpublish")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Already unpublished"}

    # No DB writes for idempotent no-op
    assert db.flush_calls == 0
    assert db.commit_calls == 0

    # Lock still acquired
    assert locks.lock_calls and locks.lock_calls[-1][0] == f"lock:admin_titles:unpublish:{row.id}"

    # Cache headers still applied
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # No audit on no-op
    assert audit_calls == []

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_unpublish_title_404_when_missing_sets_no_store(monkeypatch):
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, row=None)
    tid = uuid.uuid4()

    resp = client.post(f"/api/v1/admin/titles/{tid}/unpublish")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Title not found"}

    # No DB writes
    assert db.flush_calls == 0
    assert db.commit_calls == 0

    # Lock acquired with correct key
    assert locks.lock_calls and locks.lock_calls[-1][0] == f"lock:admin_titles:unpublish:{tid}"

    # Error responses should still be no-store
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_unpublish_title_audit_error_is_swallowed(monkeypatch):
    row = TitleRow(is_published=True)
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, row=row, audit_raises=True)

    resp = client.post(f"/api/v1/admin/titles/{row.id}/unpublish")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Unpublished"}

    # DB committed even if audit fails
    assert db.commit_calls == 1

    # Cache headers present
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_unpublish_title_calls_security_checks(monkeypatch):
    row = TitleRow(is_published=True)
    app, client, mod, db, user, calls, locks, audit_calls = _mk_app(monkeypatch, row=row)

    resp = client.post(f"/api/v1/admin/titles/{row.id}/unpublish")
    assert resp.status_code == 200

    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
