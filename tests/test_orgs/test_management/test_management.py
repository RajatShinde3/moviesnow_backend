import importlib
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict, Optional, Tuple, List

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ────────────────────────────────────────────────────────────────────────────
# Fakes
# ────────────────────────────────────────────────────────────────────────────

class FakeResult:
    def __init__(self, row):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


class FakeDB:
    def __init__(self, row=None, *, raise_on_execute: Optional[Exception] = None):
        self._row = row
        self.add_calls = 0
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0
        self.exec_calls: List[Any] = []
        self.raise_on_execute = raise_on_execute

    async def execute(self, stmt):
        self.exec_calls.append(stmt)
        if self.raise_on_execute:
            raise self.raise_on_execute
        return FakeResult(self._row)

    async def flush(self):
        self.flush_calls += 1

    async def commit(self):
        self.commit_calls += 1

    async def rollback(self):
        self.rollback_calls += 1


class FakeLockCM:
    def __init__(self, name: str, *, should_timeout=False, calls_store=None):
        self.name = name
        self.should_timeout = should_timeout
        self.calls_store = calls_store

    async def __aenter__(self):
        if self.calls_store is not None:
            self.calls_store.append(("enter", self.name))
        if self.should_timeout:
            raise TimeoutError("simulated lock timeout")
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.calls_store is not None:
            self.calls_store.append(("exit", self.name))
        return False


class FakeRedisIdemAndLocks:
    def __init__(self, *, preset: Optional[Dict[str, Any]] = None, set_raises: bool = False):
        self.preset = preset
        self.set_raises = set_raises
        self.idem_get_calls: List[str] = []
        self.idem_set_calls: List[Tuple[str, Dict[str, Any], int]] = []
        self.lock_calls: List[Tuple[str]] = []
        self.timeout_locks: set[str] = set()

    async def idempotency_get(self, key: str):
        self.idem_get_calls.append(key)
        return self.preset

    async def idempotency_set(self, key: str, value: Dict[str, Any], ttl_seconds: int):
        self.idem_set_calls.append((key, value, ttl_seconds))
        if self.set_raises:
            raise RuntimeError("redis set failure")

    def lock(self, name: str, timeout: int, blocking_timeout: int):
        self.lock_calls.append((name,))
        return FakeLockCM(name, should_timeout=(name in self.timeout_locks), calls_store=self.lock_calls)


# Minimal enum & row stubs where useful inside tests
class _Role:
    USER = "USER"
    ADMIN = "ADMIN"
    SUPERUSER = "SUPERUSER"


class UserRow:
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        role: str = _Role.USER,
        is_active: bool = True,
        deactivated_at: Optional[datetime] = None,
    ):
        self.id = id or uuid.uuid4()
        self.role = role
        self.is_active = is_active
        self.deactivated_at = deactivated_at


# Fake SQLA `select` object so we don't need real SQLA in tests
class _FakeSelect:
    def __init__(self, entity):
        self.entity = entity

    def where(self, *_, **__):
        return self

    def with_for_update(self):
        return self


def _fake_select(entity):
    return _FakeSelect(entity)


# ────────────────────────────────────────────────────────────────────────────
# App factory
# ────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    current_user: Optional[UserRow] = None,
    target_row: Optional[UserRow] = None,
    idem_snapshot: Optional[Dict[str, Any]] = None,
    idem_set_raises: bool = False,
    rate_limit_raises: bool = False,
    db_raises_sqlalchemy: bool = False,
    lock_timeout: bool = False,
):
    """
    Mounts the management router at /api/v1/admin/users with all deps overridden.
    """
    mod = importlib.import_module("app.api.v1.routers.orgs.management")

    # Bypass global limiter in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Patch SQLAlchemy bits used by the endpoints
    monkeypatch.setattr(mod, "select", _fake_select, raising=False)

    # Create an Exception type to simulate sa_exc.SQLAlchemyError
    class _SAErr(Exception): ...
    monkeypatch.setattr(mod, "sa_exc", SimpleNamespace(SQLAlchemyError=_SAErr), raising=False)

    # Redis idempotency + locks
    r = FakeRedisIdemAndLocks(preset=idem_snapshot, set_raises=idem_set_raises)
    if lock_timeout:
        # mark all locks to timeout
        r.timeout_locks = {
            "lock:user_management:role:%s" % (target_row.id if target_row else uuid.uuid4()),
            "lock:user_management:deactivate:%s" % (target_row.id if target_row else uuid.uuid4()),
            "lock:user_management:reactivate:%s" % (target_row.id if target_row else uuid.uuid4()),
        }
    monkeypatch.setattr(mod, "redis_wrapper", r, raising=False)

    # Fake audit
    audit_calls: List[Tuple[str, Dict[str, Any]]] = []
    async def _audit(db, user, action, status, request, meta_data):
        audit_calls.append((action if hasattr(action, "value") else str(action), {"status": status, **(meta_data or {})}))
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Fake enforce_rate_limit
    calls = {"enforce_rate_limit": 0}
    async def _enforce_rate_limit(**kwargs):
        calls["enforce_rate_limit"] += 1
        if rate_limit_raises:
            raise HTTPException(status_code=429, detail=kwargs.get("error_message") or "Too many")
    monkeypatch.setattr(mod, "enforce_rate_limit", _enforce_rate_limit, raising=False)

    # Patch User model just to exist on the module (not used by Fake select)
    class _UserStub: id = object()
    monkeypatch.setattr(mod, "User", _UserStub, raising=False)

    # DB
    db_exc = mod.sa_exc.SQLAlchemyError("db boom") if db_raises_sqlalchemy else None
    db = FakeDB(row=target_row, raise_on_execute=db_exc)

    # Current user & DI overrides
    me = current_user or UserRow(role=_Role.ADMIN)
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin/users")

    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: me

    client = TestClient(app)
    return app, client, mod, db, me, r, audit_calls, calls


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

def _role_payload(role: str) -> Dict[str, Any]:
    return {"role": role}


# ────────────────────────────────────────────────────────────────────────────
# Tests: update_user_role
# ────────────────────────────────────────────────────────────────────────────

def test_update_role_happy_path_as_admin(monkeypatch):
    target = UserRow(role=_Role.USER)
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, target_row=target)
    resp = client.put(f"/api/v1/admin/users/{target.id}/role", json=_role_payload(_Role.ADMIN))
    assert resp.status_code == 200
    assert resp.json()["message"] == "User role updated successfully"

    # DB + lock
    assert db.flush_calls == 1
    assert db.commit_calls == 1
    assert any("lock:user_management:role" in name[0] for name in r.lock_calls)

    # Headers
    assert resp.headers.get("Cache-Control", "").startswith("no-store")
    assert resp.headers.get("Pragma") == "no-cache"

    # Budget called and some audit recorded
    assert calls["enforce_rate_limit"] == 1
    assert any(a[0] == "USER_ROLE_CHANGED" or "USER_ROLE_CHANGED" in a[0] for a in audit)


def test_update_role_idempotency_replay_skips_db(monkeypatch):
    target = UserRow(role=_Role.USER)
    snapshot = {"message": "User role updated successfully"}
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, target_row=target, idem_snapshot=snapshot)

    resp = client.put(
        f"/api/v1/admin/users/{target.id}/role",
        json=_role_payload(_Role.ADMIN),
        headers={"Idempotency-Key": "abc"},
    )
    assert resp.status_code == 200
    assert resp.json() == snapshot

    # No DB write, no idempotency_set after replay
    assert db.commit_calls == 0
    assert r.idem_set_calls == []

    # Cache headers still present
    assert resp.headers.get("Cache-Control", "").startswith("no-store")
    assert resp.headers.get("Pragma") == "no-cache"


def test_update_role_forbidden_when_caller_not_admin_or_superuser(monkeypatch):
    caller = UserRow(role=_Role.USER)
    target = UserRow(role=_Role.USER)
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, current_user=caller, target_row=target)

    resp = client.put(f"/api/v1/admin/users/{target.id}/role", json=_role_payload(_Role.ADMIN))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Insufficient permissions"
    assert db.commit_calls == 0
    assert resp.headers.get("Cache-Control", "").startswith("no-store")
    assert resp.headers.get("Pragma") == "no-cache"


def test_update_role_block_self_change(monkeypatch):
    caller = UserRow(role=_Role.ADMIN)
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, current_user=caller, target_row=None)

    resp = client.put(f"/api/v1/admin/users/{caller.id}/role", json=_role_payload(_Role.USER))
    assert resp.status_code == 400
    assert resp.json()["detail"] == "You cannot change your own role"
    assert resp.headers.get("Cache-Control", "").startswith("no-store")


def test_update_role_only_superuser_can_assign_superuser(monkeypatch):
    caller = UserRow(role=_Role.ADMIN)
    target = UserRow(role=_Role.ADMIN)
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, current_user=caller, target_row=target)

    resp = client.put(f"/api/v1/admin/users/{target.id}/role", json=_role_payload(_Role.SUPERUSER))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Only SUPERUSER can assign SUPERUSER"
    assert db.commit_calls == 0
    assert resp.headers.get("Cache-Control", "").startswith("no-store")


def test_update_role_already_has_role_is_idempotent_and_sets_snapshot(monkeypatch):
    target = UserRow(role=_Role.ADMIN)
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, target_row=target)

    resp = client.put(
        f"/api/v1/admin/users/{target.id}/role",
        json=_role_payload(_Role.ADMIN),
        headers={"Idempotency-Key": "k1"},
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "User already has the requested role"
    # No DB commit for no-op
    assert db.commit_calls == 0
    # Snapshot attempted
    assert r.idem_set_calls and r.idem_set_calls[-1][0].endswith("k1")


def test_update_role_404_when_user_missing(monkeypatch):
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, target_row=None)

    resp = client.put(f"/api/v1/admin/users/{uuid.uuid4()}/role", json=_role_payload(_Role.ADMIN))
    assert resp.status_code == 404
    assert resp.json()["detail"] == "User not found"
    assert resp.headers.get("Cache-Control", "").startswith("no-store")


def test_update_role_forbidden_modify_superuser_by_non_superuser(monkeypatch):
    caller = UserRow(role=_Role.ADMIN)
    target = UserRow(role=_Role.SUPERUSER)
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, current_user=caller, target_row=target)

    resp = client.put(f"/api/v1/admin/users/{target.id}/role", json=_role_payload(_Role.ADMIN))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Only SUPERUSER can modify SUPERUSER"
    assert db.commit_calls == 0


def test_update_role_db_error_500_rolls_back_and_audits(monkeypatch):
    target = UserRow(role=_Role.USER)
    app, client, mod, db, me, r, audit, calls = _mk_app(
        monkeypatch,
        target_row=target,
        db_raises_sqlalchemy=True,
    )
    resp = client.put(f"/api/v1/admin/users/{target.id}/role", json=_role_payload(_Role.ADMIN))
    assert resp.status_code == 500
    assert "Database error while updating role" in resp.text
    assert db.rollback_calls >= 1


def test_update_role_lock_timeout_429(monkeypatch):
    target = UserRow(role=_Role.USER)
    app, client, mod, db, me, r, audit, calls = _mk_app(
        monkeypatch, target_row=target, lock_timeout=True
    )
    resp = client.put(f"/api/v1/admin/users/{target.id}/role", json=_role_payload(_Role.ADMIN))
    assert resp.status_code == 429
    assert "Busy processing a similar request" in resp.text


def test_update_role_per_actor_budget_blocks_and_audits(monkeypatch):
    target = UserRow(role=_Role.USER)
    app, client, mod, db, me, r, audit, calls = _mk_app(
        monkeypatch, target_row=target, rate_limit_raises=True
    )
    resp = client.put(f"/api/v1/admin/users/{target.id}/role", json=_role_payload(_Role.ADMIN))
    assert resp.status_code == 429
    assert calls["enforce_rate_limit"] == 1


# ────────────────────────────────────────────────────────────────────────────
# Tests: deactivate_user
# ────────────────────────────────────────────────────────────────────────────

def test_deactivate_user_happy_path(monkeypatch):
    target = UserRow(role=_Role.USER, is_active=True, deactivated_at=None)
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, target_row=target)

    resp = client.put(f"/api/v1/admin/users/{target.id}/deactivate")
    assert resp.status_code == 200
    assert resp.json()["message"] == "User deactivated successfully"
    assert target.is_active is False
    assert target.deactivated_at is not None
    assert db.commit_calls == 1
    assert resp.headers.get("Cache-Control", "").startswith("no-store")


def test_deactivate_user_forbidden_roles(monkeypatch):
    me = UserRow(role=_Role.USER)
    target = UserRow(role=_Role.USER)
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, current_user=me, target_row=target)

    resp = client.put(f"/api/v1/admin/users/{target.id}/deactivate")
    assert resp.status_code == 403
    assert "Insufficient permissions" in resp.text


def test_deactivate_user_self_blocked(monkeypatch):
    me = UserRow(role=_Role.ADMIN)
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, current_user=me, target_row=None)

    resp = client.put(f"/api/v1/admin/users/{me.id}/deactivate")
    assert resp.status_code == 400
    assert "cannot deactivate your own" in resp.text


def test_deactivate_user_idempotency_replay(monkeypatch):
    target = UserRow(role=_Role.USER)
    snapshot = {"message": "User deactivated successfully"}
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, target_row=target, idem_snapshot=snapshot)

    resp = client.put(f"/api/v1/admin/users/{target.id}/deactivate", headers={"Idempotency-Key": "abc"})
    assert resp.status_code == 200
    assert resp.json() == snapshot
    assert db.commit_calls == 0


def test_deactivate_user_already_inactive_idempotent(monkeypatch):
    target = UserRow(role=_Role.USER, is_active=False, deactivated_at=datetime.now(timezone.utc))
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, target_row=target)

    resp = client.put(f"/api/v1/admin/users/{target.id}/deactivate", headers={"Idempotency-Key": "k2"})
    assert resp.status_code == 200
    assert resp.json()["message"] == "User is already inactive"
    assert r.idem_set_calls and r.idem_set_calls[-1][0].endswith("k2")


def test_deactivate_user_404(monkeypatch):
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, target_row=None)
    resp = client.put(f"/api/v1/admin/users/{uuid.uuid4()}/deactivate")
    assert resp.status_code == 404
    assert resp.headers.get("Cache-Control", "").startswith("no-store")


def test_deactivate_user_lock_timeout(monkeypatch):
    target = UserRow(role=_Role.USER)
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, target_row=target, lock_timeout=True)
    resp = client.put(f"/api/v1/admin/users/{target.id}/deactivate")
    assert resp.status_code == 429


# ────────────────────────────────────────────────────────────────────────────
# Tests: reactivate_user
# ────────────────────────────────────────────────────────────────────────────

def test_reactivate_user_happy_path(monkeypatch):
    target = UserRow(role=_Role.USER, is_active=False, deactivated_at=datetime.now(timezone.utc))
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, target_row=target)

    resp = client.put(f"/api/v1/admin/users/{target.id}/reactivate")
    assert resp.status_code == 200
    assert resp.json()["message"] == "User reactivated successfully"
    assert target.is_active is True
    assert target.deactivated_at is None
    assert db.commit_calls == 1
    assert resp.headers.get("Cache-Control", "").startswith("no-store")


def test_reactivate_user_forbidden_roles(monkeypatch):
    me = UserRow(role=_Role.USER)
    target = UserRow(role=_Role.USER, is_active=False)
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, current_user=me, target_row=target)

    resp = client.put(f"/api/v1/admin/users/{target.id}/reactivate")
    assert resp.status_code == 403


def test_reactivate_user_idempotency_replay(monkeypatch):
    target = UserRow(role=_Role.USER, is_active=False)
    snapshot = {"message": "User reactivated successfully"}
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, target_row=target, idem_snapshot=snapshot)

    resp = client.put(f"/api/v1/admin/users/{target.id}/reactivate", headers={"Idempotency-Key": "abc"})
    assert resp.status_code == 200
    assert resp.json() == snapshot
    assert db.commit_calls == 0


def test_reactivate_user_already_active_idempotent(monkeypatch):
    target = UserRow(role=_Role.USER, is_active=True)
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, target_row=target)

    resp = client.put(f"/api/v1/admin/users/{target.id}/reactivate", headers={"Idempotency-Key": "kk"})
    assert resp.status_code == 200
    assert resp.json()["message"] == "User is already active"
    assert r.idem_set_calls and r.idem_set_calls[-1][0].endswith("kk")


def test_reactivate_user_404(monkeypatch):
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, target_row=None)
    resp = client.put(f"/api/v1/admin/users/{uuid.uuid4()}/reactivate")
    assert resp.status_code == 404
    assert resp.headers.get("Cache-Control", "").startswith("no-store")


def test_reactivate_user_lock_timeout(monkeypatch):
    target = UserRow(role=_Role.USER, is_active=False)
    app, client, mod, db, me, r, audit, calls = _mk_app(monkeypatch, target_row=target, lock_timeout=True)
    resp = client.put(f"/api/v1/admin/users/{target.id}/reactivate")
    assert resp.status_code == 429
