# tests/test_admin/test_taxonomy/test_create_title_credit.py

import importlib
import uuid
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
      • 1st execute(): Title existence check
      • add()/flush()/commit() for Credit insert
    """
    def __init__(self, *, title_exists: bool = True):
        self.title_exists = title_exists

        self.execute_calls = 0
        self.added: List[Any] = []
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0

    async def execute(self, _stmt, *a, **k):
        self.execute_calls += 1
        # Only the title check happens before insert in this route.
        return _Result(object() if self.title_exists else None)

    def add(self, obj: Any):
        self.added.append(obj)

    async def flush(self):
        self.flush_calls += 1
        # Ensure the Credit got an id like the DB would do
        if self.added:
            c = self.added[-1]
            if getattr(c, "id", None) in (None, ""):
                setattr(c, "id", uuid.uuid4())

    async def commit(self):
        self.commit_calls += 1

    async def rollback(self):
        self.rollback_calls += 1


class FakeUser:
    def __init__(self, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


class FakeRedis:
    def __init__(self, *, snapshot: Optional[Dict[str, Any]] = None, raise_on_set: bool = False):
        self.snapshot = snapshot
        self.raise_on_set = raise_on_set
        self.get_keys: List[str] = []
        self.set_calls: List[Tuple[str, Dict[str, Any], int]] = []  # (key, value, ttl_seconds)

    async def idempotency_get(self, key: str):
        self.get_keys.append(key)
        return self.snapshot

    async def idempotency_set(self, key: str, value: Dict[str, Any], ttl_seconds: int = 600):
        if self.raise_on_set:
            raise RuntimeError("idempotency_set boom")
        self.set_calls.append((key, value, ttl_seconds))


# ─────────────────────────────────────────────────────────────────────────────
# App factory (no unwraps; env disables rate limit)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    title_exists: bool = True,
    idempotency_snapshot: Optional[Dict[str, Any]] = None,
    raise_on_idem_set: bool = False,
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

    # Fake Redis idempotency
    r = FakeRedis(snapshot=idempotency_snapshot, raise_on_set=raise_on_idem_set)
    monkeypatch.setattr(mod, "redis_wrapper", r, raising=False)

    # Build app + dependency overrides
    app = FastAPI()
    # NOTE: tests include router with /api/v1/admin; make sure your router has no prefix internally.
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB(title_exists=title_exists)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, r, audit_calls, calls


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _payload_for(person_id: uuid.UUID) -> Dict[str, Any]:
    return {
        "person_id": str(person_id),
        "kind": "cast",
        "role": "actor",
        "character_name": "Jane Doe",
        "billing_order": 1,
        "credited_as": "J. Doe",
        "is_uncredited": False,
        "is_voice": False,
        "is_guest": False,
        "is_cameo": False,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_create_credit_happy_path_no_store_and_audit_and_set_snapshot(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch)
    tid = uuid.uuid4()
    pid = uuid.uuid4()
    idem = "abc123"

    resp = client.post(
        f"/api/v1/admin/titles/{tid}/credits",
        json=_payload_for(pid),
        headers={"Idempotency-Key": idem},
    )
    assert resp.status_code == 200
    body = resp.json()
    # Basic shape
    assert body["person_id"] == str(pid)
    assert body["kind"] == "cast"
    assert body["role"] == "actor"
    assert "id" in body and body["id"]

    # DB lifecycle happened
    assert len(db.added) == 1
    assert db.flush_calls >= 1
    assert db.commit_calls >= 1
    assert db.rollback_calls == 0

    # Idempotency snapshot set with TTL 600 and key includes the parts
    assert r.set_calls, "idempotency_set was not called"
    key, snap, ttl = r.set_calls[-1]
    assert ttl == 600
    assert key.endswith(idem)
    # Sanity: the key embeds title/person/kind/role (route behavior)
    assert str(tid) in key and str(pid) in key and "cast" in key and "actor" in key

    # Cache headers
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Audit logged
    assert audit_calls and audit_calls[-1][0] == "CREDITS_CREATE"

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_create_credit_idempotency_replay_short_circuits_everything(monkeypatch):
    # Pre-seed Redis snapshot → route should return it and skip DB/audit/set
    seeded = {
        "id": str(uuid.uuid4()),
        "person_id": str(uuid.uuid4()),
        "kind": "cast",
        "role": "actor",
        "character_name": "Replay",
        "billing_order": 7,
        "credited_as": None,
        "is_uncredited": False,
        "is_voice": False,
        "is_guest": False,
        "is_cameo": False,
    }
    app, client, mod, db, r, audit_calls, calls = _mk_app(
        monkeypatch, idempotency_snapshot=seeded
    )
    tid = uuid.uuid4()
    pid = uuid.uuid4()
    idem = "idem-replay-1"

    resp = client.post(
        f"/api/v1/admin/titles/{tid}/credits",
        json=_payload_for(pid),
        headers={"Idempotency-Key": idem},
    )
    assert resp.status_code == 200
    assert resp.json() == seeded

    # No DB writes/audit/snapshot set on replay
    assert len(db.added) == 0
    assert db.commit_calls == 0
    assert not audit_calls
    assert not r.set_calls

    # Cache headers still enforced
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_create_credit_idempotency_set_error_is_swallowed(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(
        monkeypatch, raise_on_idem_set=True
    )
    tid = uuid.uuid4()
    pid = uuid.uuid4()
    idem = "snap-fails"

    resp = client.post(
        f"/api/v1/admin/titles/{tid}/credits",
        json=_payload_for(pid),
        headers={"Idempotency-Key": idem},
    )
    assert resp.status_code == 200
    # DB commit still happened even though snapshot set failed
    assert db.commit_calls >= 1

    # Cache headers present
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_create_credit_works_without_idempotency_header(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch)
    tid = uuid.uuid4()
    pid = uuid.uuid4()

    resp = client.post(f"/api/v1/admin/titles/{tid}/credits", json=_payload_for(pid))
    assert resp.status_code == 200
    body = resp.json()
    assert body["person_id"] == str(pid)

    # No idempotency set without header
    assert not r.set_calls
    # DB & audit ok
    assert db.commit_calls >= 1
    assert audit_calls and audit_calls[-1][0] == "CREDITS_CREATE"

    # Cache headers present
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_create_credit_404_when_title_missing(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, title_exists=False)
    tid = uuid.uuid4()
    pid = uuid.uuid4()

    resp = client.post(f"/api/v1/admin/titles/{tid}/credits", json=_payload_for(pid))
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Title not found"}

    # No DB writes/audit/idempotency when title not found
    assert len(db.added) == 0
    assert db.commit_calls == 0
    assert not audit_calls
    assert not r.set_calls


def test_create_credit_audit_error_is_swallowed(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, make_audit_raise=True)
    tid = uuid.uuid4()
    pid = uuid.uuid4()

    resp = client.post(f"/api/v1/admin/titles/{tid}/credits", json=_payload_for(pid))
    # still succeeds even if audit raises
    assert resp.status_code == 200
    assert db.commit_calls >= 1
    # Cache headers present
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_create_credit_calls_security_checks(monkeypatch):
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch)
    tid = uuid.uuid4()
    pid = uuid.uuid4()
    resp = client.post(f"/api/v1/admin/titles/{tid}/credits", json=_payload_for(pid))
    assert resp.status_code == 200
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
