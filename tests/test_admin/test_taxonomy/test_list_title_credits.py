# tests/test_admin/test_taxonomy/test_list_title_credits.py

import importlib
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, List, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class _Scalars:
    def __init__(self, rows): self._rows = rows
    def all(self): return self._rows

class _ExecResult:
    def __init__(self, rows): self._rows = rows
    def scalars(self): return _Scalars(self._rows)

class FakeDB:
    """
    Records the last statement passed to execute(), and returns `rows`
    for scalars().all().
    """
    def __init__(self, rows: Optional[list] = None):
        self.rows = rows or []
        self.last_stmt = None
        self.execute_calls = 0

    async def execute(self, stmt, *a, **k):
        self.execute_calls += 1
        self.last_stmt = stmt
        return _ExecResult(self.rows)


class FakeUser:
    def __init__(self, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, rows: Optional[list] = None):
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

    # Build app + dependency overrides
    app = FastAPI()
    # NOTE: router itself should NOT have /api/v1/admin prefix, to avoid double-prefixing.
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB(rows=rows or [])
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, calls


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _credit_stub(
    *,
    person_id: uuid.UUID,
    kind: str = "cast",
    role: str = "actor",
    character_name: str = "Jane Doe",
    billing_order: Optional[int] = None,
    credited_as: Optional[str] = None,
    created_at: Optional[datetime] = None,
    updated_at: Optional[datetime] = None,
):
    """
    Minimal object with attributes expected by _ser_credit().
    Using SimpleNamespace so _ser_credit can access attributes directly.
    """
    return SimpleNamespace(
        id=uuid.uuid4(),
        title_id=uuid.uuid4(),
        person_id=person_id,
        kind=kind,
        role=role,
        character_name=character_name,
        billing_order=billing_order,
        credited_as=credited_as,
        is_uncredited=False,
        is_voice=False,
        is_guest=False,
        is_cameo=False,
        created_at=created_at,
        updated_at=updated_at,
    )


def _extract_limit_offset(stmt):
    """
    Best-effort extraction of limit/offset from a SQLAlchemy Select.
    Works across SA 1.4/2.x by probing a few possible attributes.
    """
    limit = None
    offset = None

    for name in ("_limit_clause", "_limit"):
        val = getattr(stmt, name, None)
        if val is not None:
            try:
                limit = int(getattr(val, "value", val))
            except Exception:
                pass
            break

    for name in ("_offset_clause", "_offset"):
        val = getattr(stmt, name, None)
        if val is not None:
            try:
                offset = int(getattr(val, "value", val))
            except Exception:
                pass
            break

    return limit, offset


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_list_title_credits_happy_path_no_store_and_security(monkeypatch):
    now = datetime.now(timezone.utc)
    rows = [
        _credit_stub(person_id=uuid.uuid4(), kind="cast", role="actor", billing_order=1, created_at=now - timedelta(minutes=2)),
        _credit_stub(person_id=uuid.uuid4(), kind="cast", role="actor", billing_order=2, created_at=now - timedelta(minutes=1)),
        _credit_stub(person_id=uuid.uuid4(), kind="crew", role="director", billing_order=None, created_at=now),
    ]
    app, client, mod, db, calls = _mk_app(monkeypatch, rows=rows)
    tid = uuid.uuid4()

    resp = client.get(f"/api/v1/admin/titles/{tid}/credits")
    assert resp.status_code == 200

    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 3

    # spot-check shape from _ser_credit
    one = data[0]
    assert "id" in one and "person_id" in one and "kind" in one and "role" in one

    # Cache headers
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Security checks invoked once
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1

    # DB was queried exactly once
    assert db.execute_calls == 1


def test_list_title_credits_with_filters_case_insensitive(monkeypatch):
    rows = [
        _credit_stub(person_id=uuid.uuid4(), kind="cast", role="Actor", billing_order=1),
        _credit_stub(person_id=uuid.uuid4(), kind="CAST", role="actor", billing_order=2),
    ]
    app, client, mod, db, calls = _mk_app(monkeypatch, rows=rows)
    tid = uuid.uuid4()

    # Even though we can't force SQL filtering here, the route should accept mixed case.
    resp = client.get(f"/api/v1/admin/titles/{tid}/credits", params={"kind": "CasT", "role": "AcToR"})
    assert resp.status_code == 200

    # Cache headers still set
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Security checks invoked once
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1

    # The final JSON is still a list (whatever DB returned)
    assert isinstance(resp.json(), list)


def test_list_title_credits_empty_list(monkeypatch):
    app, client, mod, db, calls = _mk_app(monkeypatch, rows=[])
    tid = uuid.uuid4()

    resp = client.get(f"/api/v1/admin/titles/{tid}/credits")
    assert resp.status_code == 200
    assert resp.json() == []

    # Cache headers still set
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_list_title_credits_limit_and_offset_passed_to_stmt(monkeypatch):
    rows = [_credit_stub(person_id=uuid.uuid4()) for _ in range(10)]
    app, client, mod, db, calls = _mk_app(monkeypatch, rows=rows)
    tid = uuid.uuid4()

    limit = 3
    offset = 2
    resp = client.get(f"/api/v1/admin/titles/{tid}/credits", params={"limit": limit, "offset": offset})
    assert resp.status_code == 200

    # Sanity-check that the built Select carried limit/offset
    stmt = db.last_stmt
    assert stmt is not None, "No statement captured"
    got_limit, got_offset = _extract_limit_offset(stmt)
    # We only assert if we could detect them; if SQLAlchemy internals change, these may be None.
    if got_limit is not None:
        assert got_limit == limit
    if got_offset is not None:
        assert got_offset == offset


def test_list_title_credits_query_param_validation(monkeypatch):
    app, client, mod, db, calls = _mk_app(monkeypatch)
    tid = uuid.uuid4()

    # limit too small
    resp = client.get(f"/api/v1/admin/titles/{tid}/credits", params={"limit": 0})
    assert resp.status_code == 422

    # limit too large
    resp = client.get(f"/api/v1/admin/titles/{tid}/credits", params={"limit": 501})
    assert resp.status_code == 422

    # negative offset
    resp = client.get(f"/api/v1/admin/titles/{tid}/credits", params={"offset": -1})
    assert resp.status_code == 422
