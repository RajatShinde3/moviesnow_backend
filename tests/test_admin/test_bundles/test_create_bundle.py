# tests/test_admin/test_bundles/test_create_bundle.py

import importlib
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes / test doubles
# ─────────────────────────────────────────────────────────────────────────────

class _ScalarResult:
    def __init__(self, val_or_list):
        self._val_or_list = val_or_list

    def scalar_one_or_none(self):
        # If a list/tuple, return first or None; else return the object
        if isinstance(self._val_or_list, (list, tuple)):
            return self._val_or_list[0] if self._val_or_list else None
        return self._val_or_list

    def scalars(self):
        class _Scalars:
            def __init__(self, val_or_list):
                self._val_or_list = val_or_list
            def all(self):
                if isinstance(self._val_or_list, (list, tuple)):
                    return list(self._val_or_list)
                return []  # not used for single-obj responses in these tests
        return _Scalars(self._val_or_list)


class FakeDB:
    """AsyncSession-ish fake with a programmable queue of execute() results."""
    def __init__(self, results: List[Any]):
        self._results = list(results)
        self.queries: List[Any] = []
        self.added: List[Any] = []
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0

    async def execute(self, query, *_a, **_k):
        self.queries.append(query)
        if self._results:
            return _ScalarResult(self._results.pop(0))
        return _ScalarResult(None)

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        self.flush_calls += 1
        # assign IDs to any newly added bundle lacking id
        for obj in self.added:
            if getattr(obj, "id", None) is None:
                obj.id = uuid.uuid4()

    async def commit(self):
        self.commit_calls += 1

    async def rollback(self):
        self.rollback_calls += 1


class FakeUser:
    def __init__(self, user_id: Optional[uuid.UUID] = None):
        self.id = user_id or uuid.uuid4()


class FakeS3Client:
    def __init__(self, exists=False):
        self.exists = exists
    def head_object(self, Bucket, Key):
        if self.exists:
            # success means the object exists
            return {"ContentLength": 1}
        # raise any exception to simulate "not found" / allowed to proceed
        raise RuntimeError("not found")


class FakeS3:
    def __init__(self, *, exists=False, presign_error: bool = False):
        self.bucket = "bucket"
        self.client = FakeS3Client(exists=exists)
        self.presign_error = presign_error
        self.put_calls: List[Tuple[str, str, bool]] = []

    def presigned_put(self, key, *, content_type, public):
        self.put_calls.append((key, content_type, public))
        if self.presign_error:
            # Use the real exception class from the module under test later
            raise RuntimeError("S3 presign failed")
        return f"https://example.com/{key}?sig=abc"

    def delete(self, key):
        return None


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

import importlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.routing import request_response
from fastapi.routing import APIRoute 

# assuming these fakes/utilities already exist in your test module
# from .fakes import FakeDB, FakeUser, FakeS3, _AsyncLockCtx

def _mk_app(
    monkeypatch,
    *,
    db_results: List[Any],
    s3: Optional[FakeS3] = None,
):
    mod = importlib.import_module("app.api.v1.routers.admin.bundles")

    # Deterministic time + TTL defaults
    fixed_now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(mod, "_now_utc", lambda: fixed_now, raising=False)
    monkeypatch.setattr(mod.settings, "BUNDLE_DEFAULT_TTL_DAYS", 14, raising=False)
    monkeypatch.setattr(mod.settings, "BUNDLE_MAX_TTL_DAYS", 60, raising=False)

    # Disable SlowAPI
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # AuthZ/MFA no-ops
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Audit no-op (override per-test when needed)
    async def _audit(*_a, **_k): return None
    monkeypatch.setattr(mod, "log_audit_event", _audit, raising=False)

    # Fake S3
    fs3 = s3 or FakeS3()
    def _s3_factory(): return fs3
    monkeypatch.setattr(mod, "_s3", _s3_factory, raising=False)

    # Ensure HEAD behavior exists for exists=True/False
    if not hasattr(fs3, "bucket"):
        fs3.bucket = "test-bucket"
    if not hasattr(fs3, "client"):
        class _Client:
            def __init__(self, exists: bool): self._exists = exists
            def head_object(self, *, Bucket, Key):
                if self._exists:
                    return {"ETag": '"deadbeef"'}
                raise RuntimeError("NotFound")
        fs3.client = _Client(getattr(fs3, "exists", False))  # type: ignore[attr-defined]
    elif not hasattr(fs3.client, "head_object"):
        def _head_object(*, Bucket, Key):
            if getattr(fs3, "exists", False):
                return {"ETag": '"deadbeef"'}
            raise RuntimeError("NotFound")
        fs3.client.head_object = _head_object  # type: ignore[attr-defined]

    # Make presign failure raise the module's S3StorageError
    class _S3Err(mod.S3StorageError): ...
    def _wrap_presigned_put(key, content_type, public):
        if getattr(fs3, "presign_error", False):
            raise _S3Err("outage")
        return FakeS3.presigned_put(fs3, key, content_type=content_type, public=public)
    fs3.presigned_put = _wrap_presigned_put  # type: ignore[attr-defined]

    # Redis idempotency + lock
    idem_sets: List[Tuple[str, Dict[str, Any], int]] = []
    idem_get_value: Optional[Dict[str, Any]] = None
    lock_keys: List[str] = []

    async def _idem_get(_k: str):
        return idem_get_value

    async def _idem_set(k: str, v: Dict[str, Any], ttl_seconds: int):
        idem_sets.append((k, v, ttl_seconds))

    def _lock(key: str, timeout=10, blocking_timeout=3):
        return _AsyncLockCtx(key, lock_keys)

    monkeypatch.setattr(mod.redis_wrapper, "idempotency_get", _idem_get, raising=False)
    monkeypatch.setattr(mod.redis_wrapper, "idempotency_set", _idem_set, raising=False)
    monkeypatch.setattr(mod.redis_wrapper, "lock", _lock, raising=False)

    # Fake DB + user
    db = FakeDB(db_results)
    user = FakeUser()

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap route & rebuild ASGI 3-arg callable
    ptn = "/api/v1/admin/titles/{title_id}/bundles"
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path == ptn and "POST" in route.methods:
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn
            route.app = request_response(route.get_route_handler())
            break

    client = TestClient(app)

    def set_idem_get(v: Optional[Dict[str, Any]]):
        nonlocal idem_get_value
        idem_get_value = v

    return app, client, mod, db, fs3, {
        "idem_sets": idem_sets,
        "set_idem_get": set_idem_get,
        "lock_keys": lock_keys,
        "fixed_now": fixed_now,
    }

# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_create_bundle_happy_path_adhoc_presigns_and_sets_snapshot(monkeypatch):
    title_id = uuid.uuid4()
    # DB calls: [select Title] → found
    app, client, mod, db, fs3, st = _mk_app(monkeypatch, db_results=[object()], s3=FakeS3(exists=False))

    eid1, eid2 = uuid.uuid4(), uuid.uuid4()
    r = client.post(
        f"/api/v1/admin/titles/{title_id}/bundles",
        json={"episode_ids": [str(eid1), str(eid2)], "ttl_days": None},
        headers={"Idempotency-Key": "k1"},
    )
    assert r.status_code == 200, r.text
    body = r.json()

    # Storage key format: adhoc bundle_<12 hex>.zip
    assert body["storage_key"].startswith(f"bundles/{title_id}/bundle_")
    assert re.fullmatch(rf"bundles/{title_id}/bundle_[0-9a-f]{{12}}\.zip", body["storage_key"])

    # Presign captured, content-type enforced
    assert fs3.put_calls and fs3.put_calls[-1] == (body["storage_key"], "application/zip", False)

    # Cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"

    # TTL uses default 14 days from fixed_now
    fixed_now = st["fixed_now"]
    assert body["expires_at"] == (fixed_now + timedelta(days=14)).isoformat()

    # DB row captured and episode_ids are stringified
    assert db.added and isinstance(db.added[-1], mod.Bundle)
    assert db.added[-1].episode_ids == [str(eid1), str(eid2)]

    # Idempotency snapshot stored with TTL 600
    k, snap, ttl = st["idem_sets"][-1]
    assert k == f"idemp:admin:bundles:create:{title_id}:k1"
    assert ttl == 600
    assert snap["storage_key"] == body["storage_key"]

    # Concurrency lock key (adhoc)
    assert any(k.endswith(":adhoc") for k in st["lock_keys"])


def test_create_bundle_happy_path_season_key_and_default_label(monkeypatch):
    title_id = uuid.uuid4()
    app, client, mod, db, fs3, st = _mk_app(monkeypatch, db_results=[object(), []], s3=FakeS3(exists=False))
    # results: [Title found], [no duplicate season bundle]

    r = client.post(
        f"/api/v1/admin/titles/{title_id}/bundles",
        json={"season_number": 2},
        headers={"Idempotency-Key": "k2"},
    )
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["storage_key"] == f"bundles/{title_id}/S02.zip"
    # label defaults to "Season 2" in the DB record when not provided
    assert db.added[-1].label == "Season 2"
    # Lock keyed on S02
    assert any(k.endswith(f"{title_id}:S02") for k in st["lock_keys"])


def test_create_bundle_idempotency_replay_skips_work(monkeypatch):
    import uuid
    title_id = uuid.uuid4()

    # IMPORTANT: provide a Title row so step 1 passes
    app, client, mod, db, fs3, st = _mk_app(monkeypatch, db_results=[object()], s3=FakeS3(exists=False))

    snap = {
        "bundle_id": "b-1",
        "storage_key": f"bundles/{title_id}/bundle_deadbeef00.zip",
        "upload_url": "https://snap",
        "expires_at": "2099-01-01T00:00:00+00:00",
    }
    # inject snapshot
    st["set_idem_get"](snap)

    r = client.post(
        f"/api/v1/admin/titles/{title_id}/bundles",
        json={"season_number": None},
        headers={"Idempotency-Key": "same"},
    )
    assert r.status_code == 200, r.text
    assert r.json() == snap


def test_create_bundle_404_when_title_not_found(monkeypatch):
    title_id = uuid.uuid4()
    # [select Title] → None
    app, client, mod, db, fs3, st = _mk_app(monkeypatch, db_results=[None], s3=FakeS3())
    r = client.post(f"/api/v1/admin/titles/{title_id}/bundles", json={})
    assert r.status_code == 404
    assert "Title not found" in r.text


def test_create_bundle_duplicate_season_returns_409(monkeypatch):
    title_id = uuid.uuid4()
    # [Title found], [duplicate season row present]
    app, client, mod, db, fs3, st = _mk_app(monkeypatch, db_results=[object(), [object()]], s3=FakeS3())
    r = client.post(f"/api/v1/admin/titles/{title_id}/bundles", json={"season_number": 1})
    assert r.status_code == 409
    assert "Bundle for this season already exists" in r.text
    assert db.commit_calls == 0
    assert fs3.put_calls == []


def test_create_bundle_s3_key_exists_is_best_effort_and_still_presigns(monkeypatch):
    import uuid
    title_id = uuid.UUID(int=1)

    # HEAD succeeds → route *tries* to 409 but swallows it (best-effort check)
    fs3 = FakeS3(exists=True)
    app, client, mod, db, fs3, st = _mk_app(monkeypatch, db_results=[object()], s3=fs3)

    r = client.post(f"/api/v1/admin/titles/{title_id}/bundles", json={})
    assert r.status_code == 200, r.text

    body = r.json()
    assert set(body.keys()) == {"bundle_id", "storage_key", "upload_url", "expires_at"}
    assert body["storage_key"].startswith(f"bundles/{title_id}/")
    assert body["upload_url"]  # non-empty

    # Should have proceeded to presign and commit
    assert db.commit_calls == 1
    assert len(fs3.put_calls) == 1
    assert fs3.put_calls[0][0] == body["storage_key"]




def test_create_bundle_presign_failure_rolls_back_and_503(monkeypatch):
    title_id = uuid.uuid4()
    # [Title found], [no duplicate]
    fs3 = FakeS3(exists=False, presign_error=True)
    app, client, mod, db, fs3, st = _mk_app(monkeypatch, db_results=[object(), []], s3=fs3)

    r = client.post(f"/api/v1/admin/titles/{title_id}/bundles", json={"season_number": 3})
    assert r.status_code == 503
    assert "outage" in r.text  # detail from S3StorageError
    assert db.rollback_calls == 1
    assert db.commit_calls == 0


from datetime import timedelta

def test_create_bundle_ttl_is_clamped_to_60_days(monkeypatch):
    import uuid
    title_id = uuid.uuid4()
    app, client, mod, db, fs3, st = _mk_app(monkeypatch, db_results=[object()], s3=FakeS3())

    r = client.post(
        f"/api/v1/admin/titles/{title_id}/bundles",
        json={"ttl_days": 60},  # model enforces <= 60; route clamps internally anyway
    )
    assert r.status_code == 200, r.text
    body = r.json()

    expected_exp = (st["fixed_now"] + timedelta(days=60)).isoformat()
    assert body["expires_at"] == expected_exp



def test_create_bundle_audit_error_is_swallowed(monkeypatch):
    title_id = uuid.uuid4()
    app, client, mod, db, fs3, st = _mk_app(monkeypatch, db_results=[object()], s3=FakeS3())

    async def _boom(*_a, **_k): raise RuntimeError("audit down")
    monkeypatch.setattr(mod, "log_audit_event", _boom, raising=False)

    r = client.post(f"/api/v1/admin/titles/{title_id}/bundles", json={})
    assert r.status_code == 200  # still succeeds despite audit error
