# tests/test_admin/test_taxonomy/test_compliance_block_title.py

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
      • execute(update(Certification)...).values(...) per region
      • add() for each new Certification row
      • flush()/commit()
    """
    def __init__(self, *, title_obj: Optional[SimpleNamespace]):
        self.title_obj = title_obj

        self.execute_calls = 0
        self.update_calls = 0
        self.added: List[Any] = []
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0
        self.last_stmt = None

    async def execute(self, stmt, *a, **k):
        self.execute_calls += 1
        self.last_stmt = stmt
        # 1st execute is the SELECT ... FOR UPDATE on Title
        if self.execute_calls == 1:
            return _Result(self.title_obj)
        else:
            # Subsequent executes are UPDATEs on Certification (set previous current=false)
            self.update_calls += 1
            return _Result(None)

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


# ─────────────────────────────────────────────────────────────────────────────
# App factory (no unwraps; env disables rate limit)
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    title_obj: Optional[SimpleNamespace],
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
    regions: List[str],
    system: str = "MPAA",
    rating_code: Optional[str] = "PG-13",
    min_age: Optional[int] = None,
    notes: Optional[str] = None,
    unpublish: bool = False,
) -> Dict[str, Any]:
    return {
        "regions": regions,
        "system": system,
        "rating_code": rating_code,
        "min_age": min_age,
        "notes": notes,
        "unpublish": unpublish,
    }


def _title_stub(is_published: Optional[bool] = True) -> SimpleNamespace:
    # include is_published attribute (route checks hasattr before toggling)
    return SimpleNamespace(id=uuid.uuid4(), is_published=is_published)


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_block_happy_path_multiple_regions_no_unpublish(monkeypatch):
    t = _title_stub(is_published=True)
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, title_obj=t)
    tid = t.id
    regions = ["us", "in"]

    resp = client.post(
        f"/api/v1/admin/titles/{tid}/block",
        json=_payload(regions=regions, system="MPAA", rating_code="PG-13", unpublish=False),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"message": "Compliance block applied", "regions": ["US", "IN"], "unpublish": False}

    # DB lifecycle: one SELECT + two UPDATEs + two INSERTs + flush + commit
    assert db.execute_calls >= 1
    assert db.update_calls == 2
    assert len(db.added) == 2
    assert db.flush_calls >= 1
    assert db.commit_calls >= 1

    # Newly added Certification objects reflect inputs (region/system/rating_code)
    for c in db.added:
        assert getattr(c, "region", "").isupper()
        assert getattr(c, "system") == "MPAA"
        assert getattr(c, "rating_code") == "PG-13"
        assert getattr(c, "is_current") is True
        assert getattr(c, "source") == "admin_block"

    # Title not unpublished on unpublish=False
    assert t.is_published is True

    # Lock key & cache headers
    assert r.lock_keys and r.lock_keys[-1].endswith(str(tid))
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Audit logged with expected meta
    assert audit_calls and audit_calls[-1][0] == "COMPLIANCE_BLOCK"
    assert audit_calls[-1][1] == {"title_id": str(tid), "regions": ["US", "IN"], "unpublish": False}

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_block_unpublish_toggles_flag(monkeypatch):
    t = _title_stub(is_published=True)
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, title_obj=t)
    tid = t.id

    resp = client.post(
        f"/api/v1/admin/titles/{tid}/block",
        json=_payload(regions=["us"], system="MPAA", rating_code="R", unpublish=True),
    )
    assert resp.status_code == 200
    assert resp.json()["unpublish"] is True
    # Title flag toggled off
    assert t.is_published is False

    # Lock & cache headers
    assert r.lock_keys and r.lock_keys[-1].endswith(str(tid))
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_block_regions_normalization_and_rating_fallback(monkeypatch):
    t = _title_stub(is_published=True)
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, title_obj=t)
    tid = t.id

    # No rating_code → fallback to str(min_age); mixed/spacey regions → normalize to upper+trim
    resp = client.post(
        f"/api/v1/admin/titles/{tid}/block",
        json=_payload(regions=["Us", " in "], system="TV", rating_code=None, min_age=16, notes="Guidance", unpublish=False),
    )
    assert resp.status_code == 200
    assert resp.json()["regions"] == ["US", "IN"]

    # Inserts reflect fallback and notes
    assert len(db.added) == 2
    for c in db.added:
        assert getattr(c, "rating_code") == "16"
        assert getattr(c, "age_min") == 16
        assert getattr(c, "meaning") == "Guidance"
        assert getattr(c, "system") == "TV"


def test_block_invalid_regions_empty_400_and_lock_used(monkeypatch):
    t = _title_stub(is_published=True)
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, title_obj=t)
    tid = t.id

    resp = client.post(
        f"/api/v1/admin/titles/{tid}/block",
        json=_payload(regions=[], system="MPAA", rating_code="PG"),
    )
    assert resp.status_code == 400
    assert resp.json() == {"detail": "regions must be ISO-3166-1 alpha-2"}

    # No inserts/commit; lock still recorded
    assert len(db.added) == 0
    assert db.commit_calls == 0
    assert r.lock_keys and r.lock_keys[-1].endswith(str(tid))
    assert not audit_calls  # no audit on 400


def test_block_invalid_regions_bad_code_400_and_lock_used(monkeypatch):
    t = _title_stub(is_published=True)
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, title_obj=t)
    tid = t.id

    resp = client.post(
        f"/api/v1/admin/titles/{tid}/block",
        json=_payload(regions=["USA"], system="MPAA", rating_code="PG"),
    )
    assert resp.status_code == 400
    assert resp.json() == {"detail": "regions must be ISO-3166-1 alpha-2"}

    # No inserts/commit; lock still recorded
    assert len(db.added) == 0
    assert db.commit_calls == 0
    assert r.lock_keys and r.lock_keys[-1].endswith(str(tid))
    assert not audit_calls


def test_block_404_when_title_missing_lock_used(monkeypatch):
    # Title not found → 404
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, title_obj=None)
    tid = uuid.uuid4()

    resp = client.post(
        f"/api/v1/admin/titles/{tid}/block",
        json=_payload(regions=["US"], system="MPAA", rating_code="PG"),
    )
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Title not found"}

    # No inserts/commit; lock still recorded (acquired before SELECT)
    assert len(db.added) == 0
    assert db.commit_calls == 0
    assert r.lock_keys and r.lock_keys[-1].endswith(str(tid))
    assert not audit_calls


def test_block_audit_error_is_swallowed(monkeypatch):
    t = _title_stub(is_published=True)
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, title_obj=t, make_audit_raise=True)
    tid = t.id

    resp = client.post(
        f"/api/v1/admin/titles/{tid}/block",
        json=_payload(regions=["US"], system="MPAA", rating_code="PG"),
    )
    # still succeeds even if audit raises
    assert resp.status_code == 200
    assert db.commit_calls >= 1

    # Lock & cache headers present
    assert r.lock_keys and r.lock_keys[-1].endswith(str(tid))
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_block_calls_security_checks(monkeypatch):
    t = _title_stub(is_published=True)
    app, client, mod, db, r, audit_calls, calls = _mk_app(monkeypatch, title_obj=t)
    tid = t.id

    resp = client.post(
        f"/api/v1/admin/titles/{tid}/block",
        json=_payload(regions=["US"], system="MPAA", rating_code="PG"),
    )
    assert resp.status_code == 200

    # Ensure both checks were actually invoked exactly once
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
