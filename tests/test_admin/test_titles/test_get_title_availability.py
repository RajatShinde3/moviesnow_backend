# tests/test_admin/test_titles/test_get_title_availability.py

import importlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class TitleRow:
    def __init__(self, *, id_: Optional[uuid.UUID] = None):
        self.id = id_ or uuid.uuid4()

class AvailabilityRow:
    def __init__(self, *, title_id: uuid.UUID, window_start: datetime, window_end: datetime):
        self.id = uuid.uuid4()
        self.title_id = title_id
        self.window_start = window_start
        self.window_end = window_end


class FakeDB:
    """Tiny async DB double for select calls."""
    def __init__(self, *, title_row: Optional[TitleRow], avail_rows: List[AvailabilityRow]):
        self.title_row = title_row
        self.avail_rows = list(avail_rows)

        self.exec_calls: List[Tuple[str, Any]] = []
        self.select_title_calls = 0
        self.select_avails_calls = 0

    async def execute(self, stmt):
        self.exec_calls.append((getattr(stmt, "_kind", "unknown"), stmt))
        kind = getattr(stmt, "_kind", None)
        entity = getattr(stmt, "entity", None)

        if kind == "select" and getattr(entity, "__name__", "") == "Title":
            self.select_title_calls += 1

            class _Res:
                def __init__(self, row): self._row = row
                def scalar_one_or_none(self): return self._row
            return _Res(self.title_row)

        if kind == "select" and getattr(entity, "__name__", "") == "Availability":
            self.select_avails_calls += 1

            # route orders by window_start ASC; we mimic that here
            ordered = sorted(self.avail_rows, key=lambda a: a.window_start)

            class _Res:
                def __init__(self, rows): self._rows = rows
                class _Scalars:
                    def __init__(self, rows): self._rows = rows
                    def all(self): return list(self._rows)
                def scalars(self): return self._Scalars(self._rows)
            return _Res(ordered)

        return object()


# ─────────────────────────────────────────────────────────────────────────────
# SQLAlchemy-ish shims (select + columns)
# ─────────────────────────────────────────────────────────────────────────────

class _SelectStmt:
    _kind = "select"
    def __init__(self, entity):
        self.entity = entity
    def where(self, *a, **k): return self
    def order_by(self, *a, **k): return self

def _fake_select(entity): return _SelectStmt(entity)

class _Col:
    """Bare-bones column-like shim to support .asc()."""
    def asc(self): return self


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    title_row: Optional[TitleRow],
    avail_rows: List[AvailabilityRow],
):
    mod = importlib.import_module("app.api.v1.routers.admin.titles")

    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Minimal Title & Availability types that the route references in filters
    TitleCls = type("Title", (), {"id": object()})
    AvailabilityCls = type("Availability", (), {
        "title_id": object(),
        "window_start": _Col(),  # only used for .asc()
    })
    monkeypatch.setattr(mod, "Title", TitleCls, raising=False)
    monkeypatch.setattr(mod, "Availability", AvailabilityCls, raising=False)

    # SQLA select shim
    monkeypatch.setattr(mod, "select", _fake_select, raising=False)

    # Security stubs
    calls = {"ensure_admin": 0, "ensure_mfa": 0}
    async def _ensure_admin(user):  # noqa: ARG001
        calls["ensure_admin"] += 1
    async def _ensure_mfa(request):  # noqa: ARG001
        calls["ensure_mfa"] += 1
    monkeypatch.setattr(mod, "_ensure_admin", _ensure_admin, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ensure_mfa, raising=False)

    # Patch serializer to a predictable shape (id + window_start only)
    def _ser(a):  # a is AvailabilityRow
        return {"id": str(a.id), "window_start": a.window_start}
    monkeypatch.setattr(mod, "_ser_availability", _ser, raising=False)

    # Build app & DI overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB(title_row=title_row, avail_rows=avail_rows)
    user = object()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, db, calls


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _windows_for(title_id):
    now = datetime.now(timezone.utc)
    return [
        AvailabilityRow(title_id=title_id, window_start=now + timedelta(days=2), window_end=now + timedelta(days=4)),
        AvailabilityRow(title_id=title_id, window_start=now + timedelta(days=1), window_end=now + timedelta(days=3)),
        AvailabilityRow(title_id=title_id, window_start=now + timedelta(days=5), window_end=now + timedelta(days=6)),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_availability_happy_path_sorted_and_no_store(monkeypatch):
    t = TitleRow()
    rows = _windows_for(t.id)
    app, client, mod, db, calls = _mk_app(monkeypatch, title_row=t, avail_rows=rows)

    resp = client.get(f"/api/v1/admin/titles/{t.id}/availability")
    assert resp.status_code == 200

    # Sorted ascending by window_start
    data = resp.json()
    expected = [
        {"id": str(a.id), "window_start": a.window_start.isoformat()}
        for a in sorted(rows, key=lambda a: a.window_start)
    ]
    assert data == expected

    # Cache headers present
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # DB calls: one for Title, one for windows
    assert db.select_title_calls == 1
    assert db.select_avails_calls == 1

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_availability_404_when_title_missing_sets_no_store(monkeypatch):
    # No title present -> 404
    app, client, mod, db, calls = _mk_app(monkeypatch, title_row=None, avail_rows=[])

    tid = uuid.uuid4()
    resp = client.get(f"/api/v1/admin/titles/{tid}/availability")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Title not found"}

    # Headers propagated from HTTPException
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Only title lookup attempted
    assert db.select_title_calls == 1
    assert db.select_avails_calls == 0

    # Security checks invoked
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_availability_empty_array_ok_and_no_store(monkeypatch):
    t = TitleRow()
    app, client, mod, db, calls = _mk_app(monkeypatch, title_row=t, avail_rows=[])

    resp = client.get(f"/api/v1/admin/titles/{t.id}/availability")
    assert resp.status_code == 200
    assert resp.json() == []  # empty list when no windows

    # Cache headers present
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"

    # Security checks
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1


def test_availability_calls_security_checks(monkeypatch):
    t = TitleRow()
    rows = _windows_for(t.id)
    app, client, mod, db, calls = _mk_app(monkeypatch, title_row=t, avail_rows=rows)

    _ = client.get(f"/api/v1/admin/titles/{t.id}/availability")
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
