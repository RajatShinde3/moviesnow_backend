# tests/test_admin/test_bundles/test_delete_bundle.py

import importlib
import uuid
from typing import Any, Dict, List, Optional, Tuple

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes / doubles
# ─────────────────────────────────────────────────────────────────────────────

class _ScalarResult:
    def __init__(self, val):
        self._val = val
    def scalar_one_or_none(self):
        return self._val


class FakeDB:
    """AsyncSession-ish fake capturing execute/commit calls."""
    def __init__(self, results: List[Any]):
        self._results = list(results)
        self.queries: List[Any] = []
        self.commit_calls = 0
    async def execute(self, query, *_a, **_k):
        self.queries.append(query)
        if self._results:
            return _ScalarResult(self._results.pop(0))
        return _ScalarResult(None)
    async def commit(self):
        self.commit_calls += 1


class FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()


class BundleRow:
    """Minimal object to mimic ORM Bundle row."""
    def __init__(self, *, id: Optional[uuid.UUID] = None, storage_key: str = "bundles/x.zip"):
        self.id = id or uuid.uuid4()
        self.storage_key = storage_key


class FakeS3:
    def __init__(self, *, raise_on_delete: bool = False):
        self.raise_on_delete = raise_on_delete
        self.delete_calls: List[str] = []
    def delete(self, key: str):
        self.delete_calls.append(key)
        if self.raise_on_delete:
            raise RuntimeError("storage down")


class _AsyncLockCtx:
    def __init__(self, key, capture: List[str]):
        self.key = key
        self.capture = capture
    async def __aenter__(self):
        self.capture.append(self.key)
    async def __aexit__(self, exc_type, exc, tb):
        return False


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, db_result: Any, s3: Optional[FakeS3] = None):
    mod = importlib.import_module("app.api.v1.routers.admin.bundles")

    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Bypass ADMIN + MFA
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Audit logger (default no-op; override in specific tests)
    async def _audit(*_a, **_k): return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # S3
    fs3 = s3 or FakeS3()
    monkeypatch.setattr(mod, "_s3", lambda: fs3, raising=False)

    # Redis lock
    lock_keys: List[str] = []
    def _lock(key: str, timeout=10, blocking_timeout=3):
        return _AsyncLockCtx(key, lock_keys)
    monkeypatch.setattr(mod.redis_wrapper, "lock", _lock, raising=False)

    # Build app
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    db = FakeDB([db_result])
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap SlowAPI (only swap endpoint; don't touch route.app)
    path = "/api/v1/admin/bundles/{bundle_id}"
    for route in app.routes:
        if getattr(route, "path", None) == path and "DELETE" in getattr(route, "methods", set()):
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn
            break

    client = TestClient(app)
    return app, client, mod, db, fs3, {"lock_keys": lock_keys}


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_delete_bundle_happy_path_deletes_row_calls_s3_and_sets_no_store(monkeypatch):
    b_id = uuid.uuid4()
    row = BundleRow(id=b_id, storage_key=f"bundles/{b_id}/S01.zip")
    app, client, mod, db, s3, st = _mk_app(monkeypatch, db_result=row, s3=FakeS3())

    r = client.delete(f"/api/v1/admin/bundles/{b_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body == {"status": "DELETED", "bundle_id": str(b_id)}

    # cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # DB: select + delete, and commit
    assert len(db.queries) >= 2
    assert db.commit_calls == 1

    # Lock key captured
    assert st["lock_keys"] and st["lock_keys"][0].endswith(f"{b_id}")

    # S3 delete called once with the bundle's key
    assert s3.delete_calls == [row.storage_key]


def test_delete_bundle_404_when_not_found(monkeypatch):
    missing = uuid.uuid4()
    app, client, mod, db, s3, st = _mk_app(monkeypatch, db_result=None, s3=FakeS3())

    r = client.delete(f"/api/v1/admin/bundles/{missing}")
    assert r.status_code == 404
    assert "Bundle not found" in r.text

    # no commit, no s3, no lock
    assert db.commit_calls == 0
    assert s3.delete_calls == []
    assert st["lock_keys"] == []


def test_delete_bundle_s3_error_is_ignored(monkeypatch):
    b_id = uuid.uuid4()
    row = BundleRow(id=b_id, storage_key=f"bundles/{b_id}/oops.zip")
    app, client, mod, db, s3, st = _mk_app(monkeypatch, db_result=row, s3=FakeS3(raise_on_delete=True))

    r = client.delete(f"/api/v1/admin/bundles/{b_id}")
    assert r.status_code == 200
    # Commit still happens
    assert db.commit_calls == 1
    # S3 delete attempted once even though it raises
    assert s3.delete_calls == [row.storage_key]


def test_delete_bundle_audit_error_is_swallowed(monkeypatch):
    b_id = uuid.uuid4()
    row = BundleRow(id=b_id)
    app, client, mod, db, s3, st = _mk_app(monkeypatch, db_result=row, s3=FakeS3())

    async def _boom(*_a, **_k): raise RuntimeError("audit down")
    monkeypatch.setattr(mod, "log_audit_event", _boom, raising=False)

    r = client.delete(f"/api/v1/admin/bundles/{b_id}")
    assert r.status_code == 200
    assert db.commit_calls == 1
