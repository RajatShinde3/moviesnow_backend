# tests/test_public/test_bundles/test_list_bundles.py

import importlib
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────

class _Result:
    def __init__(self, rows):
        self._rows = rows

    # Simulate SQLAlchemy Result.scalars().all()
    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class FakeDB:
    def __init__(self, rows):
        self.rows = rows
        self.execute_calls = []

    async def execute(self, stmt):
        self.execute_calls.append(stmt)
        return _Result(self.rows)


class BundleObj:
    """Minimal record to match the route's shaped fields."""
    def __init__(
        self,
        *,
        id,
        title_id,
        season_number,
        storage_key,
        size_bytes,
        sha256,
        expires_at,
        label,
    ):
        self.id = id
        self.title_id = title_id
        self.season_number = season_number
        self.storage_key = storage_key
        self.size_bytes = size_bytes
        self.sha256 = sha256
        self.expires_at = expires_at
        self.label = label


# ─────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, rows, *, ttl_env=None, enforce_key=None, hashed=False):
    """
    Build a tiny app with the public bundles router:
      - override DB dependency with our FakeDB
      - stub rate_limit dependency to a no-op (avoid token bucket noise)
      - optionally enforce a public API key via env
      - optionally set PUBLIC_BUNDLES_TTL_SEC
    """
    mod = importlib.import_module("app.api.v1.routers.public.bundles")

    # No-op the per-route rate limiter dependency
    async def _no_rate_limit(request=None, response=None, **_):
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # Public API key enforcement toggles
    if enforce_key is None:
        monkeypatch.delenv("PUBLIC_API_KEY", raising=False)
        monkeypatch.delenv("PUBLIC_API_KEY_SHA256", raising=False)
    else:
        if hashed:
            import hashlib
            monkeypatch.setenv(
                "PUBLIC_API_KEY_SHA256",
                hashlib.sha256(enforce_key.encode("utf-8")).hexdigest(),
            )
            monkeypatch.delenv("PUBLIC_API_KEY", raising=False)
        else:
            monkeypatch.setenv("PUBLIC_API_KEY", enforce_key)
            monkeypatch.delenv("PUBLIC_API_KEY_SHA256", raising=False)

    # TTL override
    if ttl_env is None:
        monkeypatch.delenv("PUBLIC_BUNDLES_TTL_SEC", raising=False)
    else:
        monkeypatch.setenv("PUBLIC_BUNDLES_TTL_SEC", str(ttl_env))

    # Build app + overrides
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")

    db = FakeDB(rows)
    app.dependency_overrides[mod.get_async_db] = lambda: db

    client = TestClient(app)
    return app, client, mod, db


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _mk_rows(title_id: uuid.UUID):
    now = datetime.now(timezone.utc)
    return [
        # Season 1 — active (no expiry)
        BundleObj(
            id=uuid.uuid4(),
            title_id=title_id,
            season_number=1,
            storage_key=f"bundles/{title_id}/S01.zip",
            size_bytes=111,
            sha256="a"*64,
            expires_at=None,
            label="S1",
        ),
        # Season 2 — expired (filtered out)
        BundleObj(
            id=uuid.uuid4(),
            title_id=title_id,
            season_number=2,
            storage_key=f"bundles/{title_id}/S02.zip",
            size_bytes=222,
            sha256="b"*64,
            expires_at=now - timedelta(days=1),
            label="S2",
        ),
        # Season 3 — active (future expiry)
        BundleObj(
            id=uuid.uuid4(),
            title_id=title_id,
            season_number=3,
            storage_key=f"bundles/{title_id}/S03.zip",
            size_bytes=333,
            sha256="c"*64,
            expires_at=now + timedelta(days=1),
            label="S3",
        ),
    ]


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_list_bundles_happy_path_filters_expired_shapes_items_sets_cache_and_etag(monkeypatch):
    tid = uuid.uuid4()
    rows = _mk_rows(tid)
    app, client, mod, db = _mk_app(monkeypatch, rows, ttl_env=120)

    headers_in = {
        "x-request-id": "req-123",
        "traceparent": "00-abc-xyz-01",
    }
    resp = client.get(f"/api/v1/titles/{tid}/bundles", headers=headers_in)
    assert resp.status_code == 200

    data = resp.json()
    # Expired S2 filtered out → only S1 and S3 remain
    assert isinstance(data, list) and len(data) == 2
    # Check shape and fields (spot-check)
    assert {k for k in data[0].keys()} == {
        "id",
        "title_id",
        "season_number",
        "storage_key",
        "size_bytes",
        "sha256",
        "expires_at",
        "label",
    }
    assert data[0]["season_number"] == 1
    assert data[0]["title_id"] == str(tid)

    # CDN-friendly cache headers & ttl=120
    assert resp.headers.get("Cache-Control") == "public, max-age=120, s-maxage=120, stale-while-revalidate=60"
    # ETag present (weak, but we only assert presence/format lightly)
    etag = resp.headers.get("ETag")
    assert etag and etag.startswith('W/"') and etag.endswith('"')

    # Correlation headers echoed
    assert resp.headers.get("x-request-id") == "req-123"
    assert resp.headers.get("traceparent") == "00-abc-xyz-01"

    # Fake DB was exercised
    assert len(db.execute_calls) == 1


def test_list_bundles_conditional_get_returns_304_with_headers(monkeypatch):
    tid = uuid.uuid4()
    rows = _mk_rows(tid)
    app, client, mod, _db = _mk_app(monkeypatch, rows, ttl_env=90)

    # First call to get ETag
    r1 = client.get(f"/api/v1/titles/{tid}/bundles")
    etag = r1.headers["ETag"]

    # Second call with If-None-Match → 304 and empty JSON body
    r2 = client.get(f"/api/v1/titles/{tid}/bundles", headers={"If-None-Match": etag, "x-request-id": "abc"})
    assert r2.status_code == 304
    assert r2.json() == {}  # route deliberately returns {} on 304
    # Same ETag and cache headers mirrored
    assert r2.headers.get("ETag") == etag
    assert r2.headers.get("Cache-Control") == "public, max-age=90, s-maxage=90, stale-while-revalidate=60"
    # Correlation header echoed too
    assert r2.headers.get("x-request-id") == "abc"


def test_list_bundles_ttl_default_and_invalid_env_fallback(monkeypatch):
    tid = uuid.uuid4()
    rows = _mk_rows(tid)

    # Default (no env) → 600
    app, client, mod, _ = _mk_app(monkeypatch, rows, ttl_env=None)
    r = client.get(f"/api/v1/titles/{tid}/bundles")
    assert r.headers.get("Cache-Control") == "public, max-age=600, s-maxage=600, stale-while-revalidate=60"

    # Invalid env → falls back to 600
    app2, client2, mod2, _ = _mk_app(monkeypatch, rows, ttl_env="abc")
    r2 = client2.get(f"/api/v1/titles/{tid}/bundles")
    assert r2.headers.get("Cache-Control") == "public, max-age=600, s-maxage=600, stale-while-revalidate=60"


def test_list_bundles_optional_public_api_key_enforcement_plain(monkeypatch):
    tid = uuid.uuid4()
    rows = _mk_rows(tid)
    key = "sekret123"
    app, client, mod, _ = _mk_app(monkeypatch, rows, ttl_env=60, enforce_key=key)

    # Missing key → 401
    r1 = client.get(f"/api/v1/titles/{tid}/bundles")
    assert r1.status_code == 401

    # Correct key via header → 200
    r2 = client.get(f"/api/v1/titles/{tid}/bundles", headers={"X-API-Key": key})
    assert r2.status_code == 200


def test_list_bundles_optional_public_api_key_enforcement_hashed(monkeypatch):
    tid = uuid.uuid4()
    rows = _mk_rows(tid)
    key = "sekret456"
    app, client, mod, _ = _mk_app(monkeypatch, rows, ttl_env=60, enforce_key=key, hashed=True)

    # Missing key → 401
    r1 = client.get(f"/api/v1/titles/{tid}/bundles")
    assert r1.status_code == 401

    # Providing raw key still passes (server hashes & compares)
    r2 = client.get(f"/api/v1/titles/{tid}/bundles", headers={"X-API-Key": key})
    assert r2.status_code == 200


def test_list_bundles_empty_list_still_sets_cache_and_etag(monkeypatch):
    tid = uuid.uuid4()
    rows = []  # no bundles
    app, client, mod, _ = _mk_app(monkeypatch, rows, ttl_env=45)
    r = client.get(f"/api/v1/titles/{tid}/bundles")
    assert r.status_code == 200
    assert r.json() == []
    assert r.headers.get("ETag")  # still present
    assert r.headers.get("Cache-Control") == "public, max-age=45, s-maxage=45, stale-while-revalidate=60"
