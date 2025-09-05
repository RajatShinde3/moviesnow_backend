# tests/test_admin/test_bundles/test_create_movie_extras_zip.py

import importlib
import uuid
from typing import Any, List, Optional, Tuple

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes / doubles
# ─────────────────────────────────────────────────────────────────────────────

class _ScalarResult:
    def __init__(self, val): self._val = val
    def scalar_one_or_none(self): return self._val

class FakeDB:
    """AsyncSession-ish stub (route only passes it to _ensure_title)."""
    def __init__(self, results: List[Any] | None = None):
        self._results = list(results or [])
        self.queries: List[Any] = []
    async def execute(self, query, *_a, **_k):
        self.queries.append(query)
        if self._results:
            return _ScalarResult(self._results.pop(0))
        return _ScalarResult(None)

class FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()

class FakeS3:
    def __init__(self, *, raise_on_presign: bool = False, storage_error_cls=None):
        self.raise_on_presign = raise_on_presign
        self.storage_error_cls = storage_error_cls or RuntimeError
        self.put_calls: List[Tuple[str, str, bool]] = []
    def presigned_put(self, key: str, *, content_type: str, public: bool) -> str:
        self.put_calls.append((key, content_type, public))
        if self.raise_on_presign:
            raise self.storage_error_cls("outage")
        return f"https://example.com/{key}?sig=abc"


# ─────────────────────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    ensure_title_404: bool = False,
    s3: Optional[FakeS3] = None,
):
    mod = importlib.import_module("app.api.v1.routers.admin.bundles")

    # Disable rate limiting in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Bypass ADMIN + MFA
    async def _ok(*_a, **_k): return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # _ensure_title behavior
    if ensure_title_404:
        async def _not_found(db, title_id):
            raise HTTPException(status_code=404, detail="Title not found")
        monkeypatch.setattr(mod, "_ensure_title", _not_found, raising=False)
    else:
        async def _ensure_title_passthru(db, title_id):
            _ = await db.execute(object())  # consume one DB result
            return object()
        monkeypatch.setattr(mod, "_ensure_title", _ensure_title_passthru, raising=False)

    # S3: ensure we raise the module's S3StorageError type when needed
    fs3 = s3 or FakeS3(raise_on_presign=False, storage_error_cls=mod.S3StorageError)
    monkeypatch.setattr(mod, "_s3", lambda: fs3, raising=False)

    # Build app + overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    db = FakeDB([object()])  # consumed by _ensure_title_passthru
    user = FakeUser()
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: user

    # Unwrap SlowAPI (only swap the endpoint; don't touch route.app)
    path = "/api/v1/admin/titles/{title_id}/movie-extras"
    for route in app.routes:
        if getattr(route, "path", None) == path and "POST" in getattr(route, "methods", set()):
            fn = route.endpoint
            while hasattr(fn, "__wrapped__"):
                fn = fn.__wrapped__
            route.endpoint = fn
            break

    client = TestClient(app)
    return app, client, mod, db, fs3


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_movie_extras_happy_path_presigns_and_sets_no_store(monkeypatch):
    title_id = uuid.uuid4()
    fs3 = FakeS3(raise_on_presign=False)
    app, client, mod, db, fs3 = _mk_app(monkeypatch, s3=fs3)

    r = client.post(
        f"/api/v1/admin/titles/{title_id}/movie-extras",
        json={"label": "optional"},  # payload shape doesn't affect key
    )
    assert r.status_code == 200, r.text
    body = r.json()

    expected_key = f"downloads/{title_id}/extras/movie_extras.zip"
    assert body["storage_key"] == expected_key
    assert body["upload_url"].startswith("https://example.com/") and expected_key in body["upload_url"]

    # presign captured with correct args
    assert fs3.put_calls and fs3.put_calls[-1] == (expected_key, "application/zip", False)

    # cache headers
    cc = (r.headers.get("cache-control") or "").lower()
    assert "no-store" in cc
    assert (r.headers.get("pragma") or "").lower() == "no-cache"


def test_movie_extras_title_not_found_returns_404(monkeypatch):
    title_id = uuid.uuid4()
    app, client, mod, db, fs3 = _mk_app(monkeypatch, ensure_title_404=True, s3=FakeS3())
    r = client.post(
        f"/api/v1/admin/titles/{title_id}/movie-extras",
        json={},
    )
    assert r.status_code == 404
    assert "Title not found" in r.text
    # no S3 call when title is missing
    assert fs3.put_calls == []


def test_movie_extras_presign_failure_maps_to_503(monkeypatch):
    title_id = uuid.uuid4()
    app, client, mod, db, fs3 = _mk_app(
        monkeypatch,
        s3=FakeS3(raise_on_presign=True, storage_error_cls=importlib.import_module("app.api.v1.routers.admin.bundles").S3StorageError),
    )
    r = client.post(
        f"/api/v1/admin/titles/{title_id}/movie-extras",
        json={},
    )
    assert r.status_code == 503
    assert "outage" in r.text  # detail from S3StorageError
