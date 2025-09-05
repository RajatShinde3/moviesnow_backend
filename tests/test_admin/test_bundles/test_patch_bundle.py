# tests/test_admin/test_bundles/test_patch_bundle.py

import importlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes / doubles
# ─────────────────────────────────────────────────────────────────────────────

class _ScalarResult:
    def __init__(self, val_or_list):
        self._val_or_list = val_or_list

    def scalar_one_or_none(self):
        # Our route uses scalar_one_or_none for a single row
        if isinstance(self._val_or_list, (list, tuple)):
            return self._val_or_list[0] if self._val_or_list else None
        return self._val_or_list


class FakeDB:
    """AsyncSession-ish fake with programmable execute() results and call tracking."""
    def __init__(self, results: List[Any]):
        self._results = list(results)
        self.queries: List[Any] = []
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0

    async def execute(self, query, *_a, **_k):
        self.queries.append(query)
        if self._results:
            return _ScalarResult(self._results.pop(0))
        return _ScalarResult(None)

    def add(self, obj):  # not used in this route
        pass

    async def flush(self):
        self.flush_calls += 1

    async def commit(self):
        self.commit_calls += 1

    async def rollback(self):
        self.rollback_calls += 1


class FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()


class BundleRow:
    """Mimics the ORM Bundle row the route mutates."""
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        title_id: Optional[uuid.UUID] = None,
        label: Optional[str] = None,
        created_at: Optional[datetime] = None,
        expires_at: Optional[datetime] = None,
        storage_key: str = "bundles/x.zip",
    ):
        self.id = id or uuid.uuid4()
        self.title_id = title_id or uuid.uuid4()
        self.label = label
        self.created_at = created_at
        self.expires_at = expires_at
        self.storage_key = storage_key


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    db_result: Any,
    bundle_for_get: Optional[BundleRow] = None,
):
    """Mount the router with dependencies patched for testing."""
    mod = importlib.import_module("app.api.v1.routers.admin.bundles")

    # Bypass rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Fixed 'now' for deterministic comparisons
    fixed_now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    if hasattr(mod, "_now_utc"):
        monkeypatch.setattr(mod, "_now_utc", lambda: fixed_now, raising=False)

    # Bypass ADMIN + MFA
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Audit logger (can be overridden per-test)
    async def _audit(*_a, **_k): return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Return projection via admin_get_bundle (the route uses this for response)
    seen_get_args: Dict[str, Any] = {}
    async def _admin_get_bundle(bundle_id, request, response, db, current_user):
        seen_get_args["bundle_id"] = str(bundle_id)
        seen_get_args["has_request"] = request is not None
        seen_get_args["has_response"] = response is not None
        b = bundle_for_get  # reflect the mutated object
        return {
            "id": str(b.id),
            "title_id": str(b.title_id),
            "label": b.label,
            "expires_at": b.expires_at.isoformat() if b.expires_at else None,
            "storage_key": b.storage_key,
        }
    monkeypatch.setattr(mod, "admin_get_bundle", _admin_get_bundle, raising=False)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB([db_result])
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap SlowAPI decorator (endpoint only; don't touch route.app)
    path = "/api/v1/admin/bundles/{bundle_id}"
    for route in app.routes:
        if getattr(route, "path", None) == path and "PATCH" in getattr(route, "methods", set()):
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn
            break

    client = TestClient(app)
    return app, client, mod, db, user, {"fixed_now": fixed_now, "seen_get_args": seen_get_args}


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_patch_bundle_happy_path_updates_and_returns_fresh_projection(monkeypatch):
    created_at = datetime(2024, 12, 31, 12, 0, 0, tzinfo=timezone.utc)
    b = BundleRow(created_at=created_at, label=None, expires_at=None)
    app, client, mod, db, user, st = _mk_app(monkeypatch, db_result=b, bundle_for_get=b)

    new_exp = st["fixed_now"] + timedelta(days=7)
    r = client.patch(
        f"/api/v1/admin/bundles/{b.id}",
        json={"label": "New Label", "expires_at": new_exp.isoformat()},
    )
    assert r.status_code == 200, r.text
    body = r.json()

    # DB mutations
    assert b.label == "New Label"
    assert b.expires_at == new_exp
    assert db.flush_calls == 1
    assert db.commit_calls == 1

    # Cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # Response comes from admin_get_bundle (fresh projection)
    assert body["id"] == str(b.id)
    assert body["label"] == "New Label"
    assert body["expires_at"] == new_exp.isoformat()

    # Ensure admin_get_bundle was called with same bundle_id & request/response
    assert st["seen_get_args"]["bundle_id"] == str(b.id)
    assert st["seen_get_args"]["has_request"] is True
    assert st["seen_get_args"]["has_response"] is True


def test_patch_bundle_404_when_not_found(monkeypatch):
    app, client, mod, db, user, st = _mk_app(monkeypatch, db_result=None, bundle_for_get=None)
    missing_id = uuid.uuid4()

    r = client.patch(f"/api/v1/admin/bundles/{missing_id}", json={"label": "X"})
    assert r.status_code == 404
    assert "Bundle not found" in r.text
    assert db.commit_calls == 0


def test_patch_bundle_empty_string_label_clears_label(monkeypatch):
    created_at = datetime(2024, 12, 31, 12, 0, 0, tzinfo=timezone.utc)
    b = BundleRow(created_at=created_at, label="Old", expires_at=None)
    app, client, mod, db, user, st = _mk_app(monkeypatch, db_result=b, bundle_for_get=b)

    r = client.patch(f"/api/v1/admin/bundles/{b.id}", json={"label": ""})
    assert r.status_code == 200, r.text
    body = r.json()

    assert b.label is None
    assert body["label"] is None
    assert db.flush_calls == 1
    assert db.commit_calls == 1


def test_patch_bundle_expires_at_must_be_after_created_at(monkeypatch):
    created_at = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)  # same as fixed_now
    b = BundleRow(created_at=created_at, label=None, expires_at=None)
    app, client, mod, db, user, st = _mk_app(monkeypatch, db_result=b, bundle_for_get=b)

    # expires_at equal to created_at → 400
    r = client.patch(f"/api/v1/admin/bundles/{b.id}", json={"expires_at": created_at.isoformat()})
    assert r.status_code == 400
    assert "expires_at must be after created_at" in r.text
    assert db.commit_calls == 0


def test_patch_bundle_audit_error_is_swallowed(monkeypatch):
    created_at = datetime(2024, 12, 31, 12, 0, 0, tzinfo=timezone.utc)
    b = BundleRow(created_at=created_at, label="A", expires_at=None)
    app, client, mod, db, user, st = _mk_app(monkeypatch, db_result=b, bundle_for_get=b)

    async def _boom(*_a, **_k): raise RuntimeError("audit down")
    monkeypatch.setattr(importlib.import_module("app.api.v1.routers.admin.bundles"), "log_audit_event", _boom, raising=False)

    r = client.patch(f"/api/v1/admin/bundles/{b.id}", json={"label": "B"})
    assert r.status_code == 200, r.text
    # update still applied and committed
    assert b.label == "B"
    assert db.commit_calls == 1
