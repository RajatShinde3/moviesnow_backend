# tests/test_admin/test_taxonomy/test_patch_credit.py

import importlib
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

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
    Simulates:
      • execute(select(Credit).where(...).with_for_update()) -> returns credit or None
      • flush()/commit() lifecycle
    """
    def __init__(self, *, credit: Optional[SimpleNamespace]):
        self.credit = credit

        self.execute_calls = 0
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0
        self.last_stmt = None

    async def execute(self, stmt, *a, **k):
        self.execute_calls += 1
        self.last_stmt = stmt
        return _Result(self.credit)

    async def flush(self):
        self.flush_calls += 1
        # Simulate DB-side updated_at if present
        if self.credit is not None:
            self.credit.updated_at = datetime.now(timezone.utc)

    async def commit(self):
        self.commit_calls += 1

    async def rollback(self):
        self.rollback_calls += 1


class FakeUser:
    def __init__(self, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


# Minimal credit object with attributes used by _ser_credit
def credit_stub(
    *,
    credit_id: Optional[uuid.UUID] = None,
    title_id: Optional[uuid.UUID] = None,
    person_id: Optional[uuid.UUID] = None,
    kind: str = "cast",
    role: str = "actor",
    character_name: Optional[str] = "Jane Doe",
    billing_order: Optional[int] = 1,
    credited_as: Optional[str] = None,
    is_uncredited: bool = False,
    is_voice: bool = False,
    is_guest: bool = False,
    is_cameo: bool = False,
):
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        id=credit_id or uuid.uuid4(),
        title_id=title_id or uuid.uuid4(),
        person_id=person_id or uuid.uuid4(),
        kind=kind,
        role=role,
        character_name=character_name,
        billing_order=billing_order,
        credited_as=credited_as,
        is_uncredited=is_uncredited,
        is_voice=is_voice,
        is_guest=is_guest,
        is_cameo=is_cameo,
        created_at=now,
        updated_at=now,
    )


# ─────────────────────────────────────────────────────────────────────────────
# App factory (no unwraps; env disables rate limit)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    credit: Optional[SimpleNamespace],
    make_audit_raise: bool = False,
):
    mod = importlib.import_module("app.api.v1.routers.admin.taxonomy")

    # Disable rate limiting for tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Patch security checks to no-ops but count calls
    dep_mod = importlib.import_module("app.dependencies.admin")
    calls = {"ensure_admin": 0, "ensure_mfa": 0}

    async def _ensure_admin(user):  # noqa: ARG001
        calls["ensure_admin"] += 1

    async def _ensure_mfa(request):  # noqa: ARG001
        calls["ensure_mfa"] += 1

    monkeypatch.setattr(dep_mod, "ensure_admin", _ensure_admin, raising=False)
    monkeypatch.setattr(dep_mod, "ensure_mfa", _ensure_mfa, raising=False)

    # Capture audit calls (and optionally raise to ensure errors are swallowed)
    audit_calls: List[Tuple[str, Dict[str, Any]]] = []

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

    # Build app + dependency overrides
    app = FastAPI()
    # NOTE: keep router itself unprefixed; tests add /api/v1/admin here.
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB(credit=credit)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, r, audit_calls, calls


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_patch_credit_happy_path_updates_fields_no_store_and_lock(monkeypatch):
    c = credit_stub(is_uncredited=False, billing_order=1, credited_as=None)
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, credit=c)
    cid = c.id

    patch = {
        "is_uncredited": True,
        "credited_as": "J. Doe",
        "billing_order": 7,
    }
    resp = client.patch(f"/api/v1/admin/credits/{cid}", json=patch)
    assert resp.status_code == 200

    body = resp.json()
    # Fields updated in response
    assert body["is_uncredited"] is True
    assert body["credited_as"] == "J. Doe"
    assert body["billing_order"] == 7

    # Object actually mutated
    assert c.is_uncredited is True
    assert c.credited_as == "J. Doe"
    assert c.billing_order == 7

    # DB lifecycle
    assert db.execute_calls >= 1
    assert db.flush_calls >= 1
    assert db.commit_calls >= 1
    assert db.rollback_calls == 0

    # Lock was used with expected key suffix
    assert r.lock_keys and r.lock_keys[-1].endswith(str(cid))

    # Cache headers (from _json helper)
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Audit logged with expected shape (order of fields not guaranteed)
    assert audit_calls, "audit event was not recorded"
    action, meta = audit_calls[-1]
    assert action == "CREDITS_PATCH"
    assert meta["credit_id"] == str(cid)
    assert set(meta["fields"]) == {"is_uncredited", "credited_as", "billing_order"}

    # Security checks were invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_patch_credit_404_when_credit_missing_still_uses_lock(monkeypatch):
    # No credit in DB
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, credit=None)
    cid = uuid.uuid4()

    resp = client.patch(f"/api/v1/admin/credits/{cid}", json={"is_uncredited": True})
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Credit not found"}

    # Lock attempted even though record missing (lock is acquired before the SELECT)
    assert r.lock_keys and r.lock_keys[-1].endswith(str(cid))

    # No flush/commit/audit on 404
    assert db.flush_calls == 0
    assert db.commit_calls == 0
    assert audit_calls == []

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_patch_credit_400_when_no_changes_provided(monkeypatch):
    c = credit_stub()
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, credit=c)
    cid = c.id

    # Empty JSON → CreditPatchIn validates but exclude_unset => {} → 400
    resp = client.patch(f"/api/v1/admin/credits/{cid}", json={})
    assert resp.status_code == 400
    assert resp.json() == {"detail": "No changes provided"}

    # No DB execution or lock since error raised before lock block
    assert db.execute_calls == 0
    assert r.lock_keys == []
    assert audit_calls == []

    # Security checks still invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_patch_credit_audit_error_is_swallowed(monkeypatch):
    c = credit_stub()
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, credit=c, make_audit_raise=True)
    cid = c.id

    resp = client.patch(f"/api/v1/admin/credits/{cid}", json={"is_cameo": True})
    # still succeeds even if audit raises
    assert resp.status_code == 200

    # DB flush + commit called
    assert db.flush_calls >= 1
    assert db.commit_calls >= 1

    # Lock used + cache headers present
    assert r.lock_keys and r.lock_keys[-1].endswith(str(cid))
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_patch_credit_calls_security_checks(monkeypatch):
    c = credit_stub()
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, credit=c)
    cid = c.id

    resp = client.patch(f"/api/v1/admin/credits/{cid}", json={"is_voice": True})
    assert resp.status_code == 200

    # Ensure both checks were actually invoked exactly once
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
