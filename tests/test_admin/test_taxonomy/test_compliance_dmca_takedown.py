# tests/test_admin/test_taxonomy/test_compliance_dmca_takedown.py

import importlib
import uuid
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
      • execute(select(Title).with_for_update()) -> returns title (or None)
      • add() for ContentAdvisory row
      • flush()/commit()
    """
    def __init__(self, *, title_obj: Optional[SimpleNamespace]):
        self.title_obj = title_obj

        self.execute_calls = 0
        self.added: List[Any] = []
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0
        self.last_stmt = None

    async def execute(self, stmt, *a, **k):
        self.execute_calls += 1
        self.last_stmt = stmt
        # Only one SELECT ... FOR UPDATE occurs
        return _Result(self.title_obj)

    def add(self, obj: Any):
        self.added.append(obj)

    async def flush(self):
        self.flush_calls += 1

    async def commit(self):
        self.commit_calls += 1

    async def rollback(self):
        self.rollback_calls += 1


class FakeUser:
    def __init__(self, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


def _title_stub(is_published: Optional[bool] = True) -> SimpleNamespace:
    # include is_published attribute (route checks hasattr before toggling)
    return SimpleNamespace(id=uuid.uuid4(), is_published=is_published)


# ─────────────────────────────────────────────────────────────────────────────
# App factory (no unwraps; env disables rate limit)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    title_obj: Optional[SimpleNamespace],
    make_audit_raise: bool = False,
    patch_model: bool = False,  # set True if you want to avoid ORM warnings by stubbing ContentAdvisory
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

    # Fake redis lock that records keys
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

    # Optionally stub ContentAdvisory to minimize ORM noise (not required)
    if patch_model:
        class _AdvisoryStub:
            def __init__(self, **kwargs):
                for k, v in kwargs.items():
                    setattr(self, k, v)
        monkeypatch.setattr(mod, "ContentAdvisory", _AdvisoryStub, raising=False)

    # Build app + dependency overrides
    app = FastAPI()
    # NOTE: router itself should not include /api/v1/admin to avoid double-prefix.
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB(title_obj=title_obj)
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, r, audit_calls, calls


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _payload(
    *,
    reason: Optional[str] = "piracy",
    source_url: Optional[str] = "https://example.com/report",
    unpublish: bool = False,
) -> Dict[str, Any]:
    return {"reason": reason, "source_url": source_url, "unpublish": unpublish}


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_dmca_happy_path_no_unpublish(monkeypatch):
    t = _title_stub(is_published=True)
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, title_obj=t)
    tid = t.id

    resp = client.post(
        f"/api/v1/admin/titles/{tid}/dmca",
        json=_payload(reason="piracy", source_url="https://src.example/dmca", unpublish=False),
    )
    assert resp.status_code == 200
    assert resp.json() == {"message": "Takedown applied"}

    # DB lifecycle: one SELECT + one INSERT + flush + commit
    assert db.execute_calls == 1
    assert len(db.added) == 1
    assert db.flush_calls >= 1
    assert db.commit_calls >= 1

    # Advisory object shape
    adv = db.added[0]
    assert getattr(adv, "title_id") == tid
    assert getattr(adv, "language") == "en"
    assert getattr(adv, "is_active") is True
    assert getattr(adv, "source") == "dmca_admin"
    assert getattr(adv, "notes") == "piracy"
    # tags should include dmca=True and the source_url we sent
    tags = getattr(adv, "tags")
    assert isinstance(tags, dict) and tags.get("dmca") is True and tags.get("source_url") == "https://src.example/dmca"
    # enums (taken from module)
    assert getattr(adv, "kind") == mod.AdvisoryKind.OTHER
    assert getattr(adv, "severity") == mod.AdvisorySeverity.SEVERE

    # Title not unpublished on unpublish=False
    assert t.is_published is True

    # Lock key & cache headers
    assert r.lock_keys and r.lock_keys[-1].endswith(str(tid))
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Audit logged with expected meta
    assert audit_calls and audit_calls[-1][0] == "COMPLIANCE_DMCA"
    assert audit_calls[-1][1] == {"title_id": str(tid)}

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_dmca_unpublish_true_and_default_reason(monkeypatch):
    t = _title_stub(is_published=True)
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, title_obj=t)
    tid = t.id

    # No explicit reason/source_url -> defaults; unpublish=True toggles flag
    resp = client.post(
        f"/api/v1/admin/titles/{tid}/dmca",
        json=_payload(reason=None, source_url=None, unpublish=True),
    )
    assert resp.status_code == 200
    assert t.is_published is False  # toggled off

    adv = db.added[0]
    assert getattr(adv, "notes") == "DMCA takedown"
    tags = getattr(adv, "tags")
    assert isinstance(tags, dict) and tags.get("dmca") is True and "source_url" not in tags


def test_dmca_404_when_title_missing_lock_used(monkeypatch):
    # Title not found → 404
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, title_obj=None)
    tid = uuid.uuid4()

    resp = client.post(
        f"/api/v1/admin/titles/{tid}/dmca",
        json=_payload(),
    )
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Title not found"}

    # No inserts/commit; lock still recorded (acquired before SELECT)
    assert len(db.added) == 0
    assert db.commit_calls == 0
    assert r.lock_keys and r.lock_keys[-1].endswith(str(tid))
    assert not audit_calls

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_dmca_audit_error_is_swallowed(monkeypatch):
    t = _title_stub(is_published=True)
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, title_obj=t, make_audit_raise=True)
    tid = t.id

    resp = client.post(
        f"/api/v1/admin/titles/{tid}/dmca",
        json=_payload(),
    )
    # still succeeds even if audit raises
    assert resp.status_code == 200
    assert db.commit_calls >= 1

    # Lock & cache headers present
    assert r.lock_keys and r.lock_keys[-1].endswith(str(tid))
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_dmca_calls_security_checks(monkeypatch):
    t = _title_stub(is_published=True)
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, title_obj=t)
    tid = t.id

    resp = client.post(f"/api/v1/admin/titles/{tid}/dmca", json=_payload())
    assert resp.status_code == 200

    # Ensure both checks were actually invoked exactly once
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
