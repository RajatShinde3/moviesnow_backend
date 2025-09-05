# tests/test_admin/test_taxonomy/test_attach_genre.py

import importlib
import uuid
from typing import Any, List, Tuple, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class _Result:
    def __init__(self, value: Any):
        self._value = value
    def scalar_one_or_none(self):
        return self._value

class FakeDB:
    """
    - First two `execute` calls are the existence checks (Title, then Genre).
      We feed values via `exists_sequence` (booleans).
    - The 3rd `execute` is the INSERT into the association table.
    """
    def __init__(self, *, exists_sequence=(True, True), raise_on_insert: bool = False):
        self._exists = list(exists_sequence)
        self.raise_on_insert = raise_on_insert

        self.execute_calls = 0
        self.insert_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0

    async def execute(self, _stmt):
        self.execute_calls += 1
        # 1: Title exists check, 2: Genre exists check
        if self.execute_calls <= 2:
            val = self._exists[self.execute_calls - 1]
            return _Result(object() if val else None)

        # 3+: association INSERT
        self.insert_calls += 1
        if self.raise_on_insert:
            raise RuntimeError("duplicate or constraint violation")
        return _Result(None)

    async def commit(self):
        self.commit_calls += 1

    async def rollback(self):
        self.rollback_calls += 1


class FakeUser:
    def __init__(self, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


# ─────────────────────────────────────────────────────────────────────────────
# App factory (no unwrap needed)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    exists_sequence=(True, True),
    raise_on_insert=False,
    make_audit_raise=False,
):
    mod = importlib.import_module("app.api.v1.routers.admin.taxonomy")

    # Disable rate limiting for tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # The route imports these from app.dependencies.admin at call time,
    # so patch that module directly and also record the calls.
    dep_mod = importlib.import_module("app.dependencies.admin")
    calls = {"ensure_admin": 0, "ensure_mfa": 0}

    async def _ensure_admin(user):  # noqa: ARG001
        calls["ensure_admin"] += 1

    async def _ensure_mfa(request):  # noqa: ARG001
        calls["ensure_mfa"] += 1

    monkeypatch.setattr(dep_mod, "ensure_admin", _ensure_admin, raising=False)
    monkeypatch.setattr(dep_mod, "ensure_mfa", _ensure_mfa, raising=False)

    # Capture audit calls (and optionally raise to ensure errors are swallowed)
    audit_calls: List[Tuple[str, dict]] = []

    async def _audit(db, user, action, status, request, meta_data):  # noqa: ARG001
        audit_calls.append((action, meta_data))
        if make_audit_raise:
            raise RuntimeError("audit boom")

    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Fake redis lock
    class _Lock:
        def __init__(self, key: str, *, timeout: int, blocking_timeout: int):
            self.key = key
        async def __aenter__(self): return None
        async def __aexit__(self, exc_type, exc, tb): return False

    class _Redis:
        def __init__(self):
            self.lock_keys: List[str] = []
        def lock(self, key: str, *, timeout: int, blocking_timeout: int):
            self.lock_keys.append(key)
            return _Lock(key, timeout=timeout, blocking_timeout=blocking_timeout)

    r = _Redis()
    monkeypatch.setattr(mod, "redis_wrapper", r, raising=False)

    # Build app and dependency overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB(exists_sequence=exists_sequence, raise_on_insert=raise_on_insert)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, r, audit_calls, calls


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_attach_genre_happy_path_no_store_and_lock(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch)
    tid = uuid.uuid4()
    gid = uuid.uuid4()

    resp = client.post(f"/api/v1/admin/titles/{tid}/genres/{gid}")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Attached"}

    # DB inserts + commit happens
    assert db.execute_calls >= 3
    assert db.insert_calls >= 1
    assert db.commit_calls >= 1
    assert db.rollback_calls == 0

    # Lock was used with expected key suffix
    assert r.lock_keys and r.lock_keys[-1].endswith(f"{tid}:{gid}")

    # Cache headers (from _json helper)
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"
    # We don't require "Expires" here because _json sets only Cache-Control/Pragma.

    # Audit logged with expected shape
    assert audit_calls, "audit event was not recorded"
    action, meta = audit_calls[-1]
    assert action == "TITLES_GENRE_ATTACH"
    assert meta == {"title_id": str(tid), "genre_id": str(gid)}

    # Security checks were invoked (but patched as no-ops)
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_attach_genre_idempotent_duplicate_rollback_but_200(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(
        monkeypatch,
        exists_sequence=(True, True),
        raise_on_insert=True,           # simulate duplicate/constraint violation
    )
    tid = uuid.uuid4()
    gid = uuid.uuid4()

    resp = client.post(f"/api/v1/admin/titles/{tid}/genres/{gid}")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Attached"}

    # Insert attempted, but rolled back; commit should not happen
    assert db.insert_calls >= 1
    assert db.rollback_calls >= 1
    assert db.commit_calls == 0

    # Lock still used
    assert r.lock_keys and r.lock_keys[-1].endswith(f"{tid}:{gid}")

    # Cache headers still correct
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Audit still attempted
    assert audit_calls and audit_calls[-1][0] == "TITLES_GENRE_ATTACH"


def test_attach_genre_404_when_title_missing(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(
        monkeypatch,
        exists_sequence=(False, True),  # Title missing, Genre would exist
    )
    tid = uuid.uuid4()
    gid = uuid.uuid4()

    resp = client.post(f"/api/v1/admin/titles/{tid}/genres/{gid}")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Title or Genre not found"}

    # No insert/commit/rollback and no lock usage due to early 404
    assert db.insert_calls == 0
    assert db.commit_calls == 0
    assert db.rollback_calls == 0
    assert r.lock_keys == []
    assert audit_calls == []


def test_attach_genre_404_when_genre_missing(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(
        monkeypatch,
        exists_sequence=(True, False),  # Title exists, Genre missing
    )
    tid = uuid.uuid4()
    gid = uuid.uuid4()

    resp = client.post(f"/api/v1/admin/titles/{tid}/genres/{gid}")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Title or Genre not found"}

    # No insert/commit/rollback and no lock usage due to early 404
    assert db.insert_calls == 0
    assert db.commit_calls == 0
    assert db.rollback_calls == 0
    assert r.lock_keys == []
    assert audit_calls == []


def test_attach_genre_audit_error_is_swallowed(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(
        monkeypatch,
        exists_sequence=(True, True),
        make_audit_raise=True,          # audit logger raises error
    )
    tid = uuid.uuid4()
    gid = uuid.uuid4()

    resp = client.post(f"/api/v1/admin/titles/{tid}/genres/{gid}")
    # still succeeds even if audit raises
    assert resp.status_code == 200
    assert resp.json() == {"message": "Attached"}

    # DB insert + commit called
    assert db.insert_calls >= 1
    assert db.commit_calls >= 1

    # Lock was used
    assert r.lock_keys and r.lock_keys[-1].endswith(f"{tid}:{gid}")

    # Cache headers present
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_attach_genre_calls_security_checks(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch)
    tid = uuid.uuid4()
    gid = uuid.uuid4()

    resp = client.post(f"/api/v1/admin/titles/{tid}/genres/{gid}")
    assert resp.status_code == 200

    # Ensure both checks were actually invoked exactly once
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
