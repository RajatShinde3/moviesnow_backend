import importlib
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient

# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class FakeResult:
    def __init__(self, one: Any = None, rows: Optional[List[Any]] = None):
        self._one = one
        self._rows = rows or []

    # For .scalar_one_or_none()
    def scalar_one_or_none(self):
        return self._one

    # For .scalars().all() pattern (not used here, but harmless)
    class _Scalars:
        def __init__(self, rows): self._rows = rows
        def all(self): return list(self._rows)
    def scalars(self):
        return FakeResult._Scalars(self._rows)


class FakeDB:
    """
    Minimal async Session stub:
    - execute(): returns FakeResult; also counts deletes
    - add()/flush()/commit() counters
    """
    def __init__(self, *, title_row: Optional[SimpleNamespace]):
        self._title_row = title_row
        self.add_calls = 0
        self.flush_calls = 0
        self.commit_calls = 0
        self.delete_calls = 0
        self.exec_calls: List[Any] = []
        self.added: List[Any] = []

    async def execute(self, stmt):
        # record the statement for visibility
        self.exec_calls.append(stmt)
        # detect Delete statements without importing sqlalchemy in tests that don't need it
        if stmt.__class__.__name__.lower() == "delete":
            self.delete_calls += 1
            return FakeResult(None)
        # The route does exactly one SELECT(Title) … scalar_one_or_none()
        return FakeResult(self._title_row)

    def add(self, obj: Any):
        self.add_calls += 1
        self.added.append(obj)

    async def flush(self):
        self.flush_calls += 1

    async def commit(self):
        self.commit_calls += 1


class FakeLocks:
    def __init__(self):
        self.lock_calls: List[str] = []

    # returns an async context manager
    def lock(self, key: str, timeout: int, blocking_timeout: int):
        self.lock_calls.append(key)

        class _Ctx:
            async def __aenter__(self_nonlocal): return None
            async def __aexit__(self_nonlocal, exc_type, exc, tb): return False

        return _Ctx()


# Title row stub used by SELECT(Title) → scalar_one_or_none()
def TitleRow(*, deleted_at=None) -> SimpleNamespace:
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        id=uuid.uuid4(),
        deleted_at=deleted_at,
        created_at=now,
        updated_at=now,
    )


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    title_row: Optional[SimpleNamespace],
    audit_raises: bool = False,
):
    mod = importlib.import_module("app.api.v1.routers.admin.titles")

    # Disable rate limits during tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Security stubs (the module imports them as _ensure_*)
    calls = {"ensure_admin": 0, "ensure_mfa": 0}
    async def _ensure_admin(user):  # noqa: ARG001
        calls["ensure_admin"] += 1
    async def _ensure_mfa(request):  # noqa: ARG001
        calls["ensure_mfa"] += 1
    monkeypatch.setattr(mod, "_ensure_admin", _ensure_admin, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ensure_mfa, raising=False)

    # Audit stub
    audit_calls: List[Tuple[str, Dict[str, Any]]] = []
    async def _audit(db, user, action, status, request, meta_data):  # noqa: ARG001
        audit_calls.append((action, meta_data))
        if audit_raises:
            raise RuntimeError("audit down")
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Redis lock stub
    locks = FakeLocks()
    monkeypatch.setattr(mod, "redis_wrapper", locks, raising=False)

    # Build app
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    # DB stub
    db = FakeDB(title_row=title_row)
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: object()

    client = TestClient(app)
    return app, client, mod, db, calls, locks, audit_calls


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _payload_windows(n: int) -> Dict[str, Any]:
    """
    Build a valid minimal payload.
    IMPORTANT: keep only fields that are guaranteed to validate across enums.
    """
    now = datetime.now(timezone.utc)
    windows = []
    for i in range(n):
        ws = now + timedelta(days=i)
        we = ws + timedelta(days=7)
        windows.append({
            "window_start": ws.isoformat(),  # ISO 8601 for pydantic datetime
            "window_end": we.isoformat(),
            # leave territory_mode / distribution / device_classes / rights out
            # to avoid enum mismatches; defaults are used in the API
        })
    return {"windows": windows}


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_put_availability_happy_path_replaces_and_no_store(monkeypatch):
    t = TitleRow()
    app, client, mod, db, calls, locks, audit_calls = _mk_app(monkeypatch, title_row=t)

    body = _payload_windows(3)
    resp = client.put(f"/api/v1/admin/titles/{t.id}/availability", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data == {"message": "Availability updated", "count": 3}

    # DB lifecycle: delete old, add N new, flush & commit
    assert db.delete_calls == 1
    assert db.add_calls == 3
    assert db.flush_calls >= 1
    assert db.commit_calls >= 1

    # Security + lock
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
    assert locks.lock_calls and locks.lock_calls[-1].endswith(f"{t.id}")

    # Cache headers
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Audit captured
    assert audit_calls and audit_calls[-1][0] == "TITLES_AVAILABILITY_SET"


def test_put_availability_404_when_title_missing_sets_no_store(monkeypatch):
    app, client, mod, db, calls, locks, audit_calls = _mk_app(monkeypatch, title_row=None)

    tid = uuid.uuid4()
    resp = client.put(f"/api/v1/admin/titles/{tid}/availability", json=_payload_windows(2))
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Title not found"}

    # Security + lock still invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
    assert locks.lock_calls and locks.lock_calls[-1].endswith(f"{tid}")

    # no-store headers present even on error
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # No DB insert/commit
    assert db.add_calls == 0
    assert db.commit_calls == 0


def test_put_availability_409_when_title_soft_deleted(monkeypatch):
    t = TitleRow(deleted_at=datetime.now(timezone.utc))
    app, client, mod, db, calls, locks, audit_calls = _mk_app(monkeypatch, title_row=t)

    resp = client.put(f"/api/v1/admin/titles/{t.id}/availability", json=_payload_windows(1))
    assert resp.status_code == 409
    assert resp.json() == {"detail": "Title is deleted; restore before changing availability"}

    # No data mutation
    assert db.delete_calls == 0
    assert db.add_calls == 0
    assert db.commit_calls == 0

    # Error responses are no-store
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_put_availability_audit_error_is_swallowed(monkeypatch):
    t = TitleRow()
    app, client, mod, db, calls, locks, audit_calls = _mk_app(monkeypatch, title_row=t, audit_raises=True)

    resp = client.put(f"/api/v1/admin/titles/{t.id}/availability", json=_payload_windows(2))
    assert resp.status_code == 200
    assert resp.json() == {"message": "Availability updated", "count": 2}
    # DB committed even if audit raised
    assert db.commit_calls >= 1


def test_put_availability_empty_set_clears_all(monkeypatch):
    t = TitleRow()
    app, client, mod, db, calls, locks, audit_calls = _mk_app(monkeypatch, title_row=t)

    resp = client.put(f"/api/v1/admin/titles/{t.id}/availability", json={"windows": []})
    assert resp.status_code == 200
    assert resp.json() == {"message": "Availability updated", "count": 0}

    # We still delete existing windows; no inserts
    assert db.delete_calls == 1
    assert db.add_calls == 0
    assert db.commit_calls >= 1

    # Cache headers
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_put_availability_calls_security_checks(monkeypatch):
    t = TitleRow()
    app, client, mod, db, calls, locks, audit_calls = _mk_app(monkeypatch, title_row=t)

    _ = client.put(f"/api/v1/admin/titles/{t.id}/availability", json=_payload_windows(1))
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
