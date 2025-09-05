# tests/test_public/test_bundles/test_bundle_manifest.py

import importlib
import os
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────

class FakeS3:
    """
    Minimal S3 fake that mimics the interface used by the route:
      - has .bucket
      - has .client.head_object(...)
      - has .presigned_get(key, expires_in=..., response_content_type=...)
    """
    def __init__(self, *, exists=True, presign_ok=True, url="https://example.test/presigned"):
        self.bucket = "unit-test-bucket"
        self.client = self  # simple: head_object lives here
        self.exists = exists
        self.presign_ok = presign_ok
        self.url = url
        self.last_head_object = None
        self.last_presign_args = None

    # Called as: s3.client.head_object(Bucket=s3.bucket, Key=manifest_key)
    def head_object(self, *, Bucket, Key):
        self.last_head_object = {"Bucket": Bucket, "Key": Key}
        if not self.exists:
            # Will be replaced in tests with module's S3StorageError
            raise self._storage_error("NoSuchKey")

    # Called as: s3.presigned_get(key, expires_in=300, response_content_type="application/json")
    def presigned_get(self, key, *, expires_in, response_content_type):
        self.last_presign_args = {
            "key": key,
            "expires_in": expires_in,
            "response_content_type": response_content_type,
        }
        if not self.presign_ok:
            raise RuntimeError("presign failed")
        return self.url

    # Placeholder; tests will monkeypatch this attribute to the module's exception type
    def _storage_error(self, msg):
        return RuntimeError(msg)


# ─────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, s3: FakeS3, enforce_key=None, hashed=False):
    """
    Build a tiny FastAPI app that mounts the public bundles router and
    replaces rate_limit + S3Client for deterministic tests.
    """
    # Import the router module under test
    mod = importlib.import_module("app.api.v1.routers.public.bundles")

    # Disable per-route limiter
    async def _no_rate_limit(request=None, response=None, **_):
        # Mirror headers the real limiter would set (optional but harmless)
        if response is not None:
            response.headers.setdefault("X-RateLimit-Limit", "0")
            response.headers.setdefault("X-RateLimit-Remaining", "0")
            response.headers.setdefault("X-RateLimit-Window", "60")
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # Configure (optional) API key enforcement
    if enforce_key is None:
        monkeypatch.delenv("PUBLIC_API_KEY", raising=False)
        monkeypatch.delenv("PUBLIC_API_KEY_SHA256", raising=False)
    else:
        if hashed:
            import hashlib
            monkeypatch.setenv("PUBLIC_API_KEY_SHA256", hashlib.sha256(enforce_key.encode("utf-8")).hexdigest())
            monkeypatch.delenv("PUBLIC_API_KEY", raising=False)
        else:
            monkeypatch.setenv("PUBLIC_API_KEY", enforce_key)
            monkeypatch.delenv("PUBLIC_API_KEY_SHA256", raising=False)

    # Wire FakeS3 in place of S3Client
    # Also ensure our fake raises the module's S3StorageError when needed
    s3._storage_error = lambda msg: mod.S3StorageError(msg)
    monkeypatch.setattr(mod, "S3Client", lambda: s3, raising=True)

    # Build FastAPI app and include the router
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")
    client = TestClient(app)
    return app, client, mod, s3


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_manifest_happy_path_no_store_headers_and_correlation(monkeypatch):
    title_id = uuid.uuid4()
    season = 3

    s3 = FakeS3(exists=True, presign_ok=True, url="https://cdn.example/manifest?sig=abc")
    app, client, mod, s3 = _mk_app(monkeypatch, s3=s3)

    headers_in = {"x-request-id": "req-789", "traceparent": "00-111-222-01"}
    r = client.get(f"/api/v1/titles/{title_id}/bundles/{season}/manifest", headers=headers_in)
    assert r.status_code == 200
    body = r.json()
    assert body == {"url": "https://cdn.example/manifest?sig=abc"}

    # S3 HEAD was called with normalized manifest key (S{season:02}_manifest.json)
    expected_key_suffix = f"S{season:02}_manifest.json"
    assert s3.last_head_object is not None
    assert s3.last_head_object["Bucket"] == s3.bucket
    assert s3.last_head_object["Key"].endswith(expected_key_suffix)

    # Presign called with correct args
    assert s3.last_presign_args == {
        "key": s3.last_head_object["Key"],
        "expires_in": 300,
        "response_content_type": "application/json",
    }

    # Cache is no-store for sensitive presigned URLs
    assert r.headers.get("Cache-Control") == "no-store"
    assert r.headers.get("Pragma") == "no-cache"
    assert r.headers.get("Expires") == "0"

    # Correlation headers echoed
    assert r.headers.get("x-request-id") == "req-789"
    assert r.headers.get("traceparent") == "00-111-222-01"


def test_manifest_404_when_head_object_indicates_missing(monkeypatch):
    title_id = uuid.uuid4()
    s3 = FakeS3(exists=False, presign_ok=True)
    app, client, mod, s3 = _mk_app(monkeypatch, s3=s3)

    r = client.get(f"/api/v1/titles/{title_id}/bundles/1/manifest")
    assert r.status_code == 404
    assert r.json()["detail"] == "Manifest not found"


def test_manifest_404_on_unknown_storage_exception(monkeypatch):
    title_id = uuid.uuid4()

    class ExplodingS3(FakeS3):
        def head_object(self, *, Bucket, Key):
            # Simulate a non-S3StorageError exception path
            raise ValueError("permission denied")

    s3 = ExplodingS3()
    app, client, mod, _ = _mk_app(monkeypatch, s3=s3)

    r = client.get(f"/api/v1/titles/{title_id}/bundles/2/manifest")
    assert r.status_code == 404
    assert r.json()["detail"] == "Manifest not found"


def test_manifest_503_on_presign_failure(monkeypatch):
    title_id = uuid.uuid4()
    s3 = FakeS3(exists=True, presign_ok=False)
    app, client, mod, s3 = _mk_app(monkeypatch, s3=s3)

    r = client.get(f"/api/v1/titles/{title_id}/bundles/5/manifest")
    assert r.status_code == 503
    assert r.json()["detail"] == "Could not sign manifest URL"


def test_manifest_enforces_public_api_key_plain(monkeypatch):
    title_id = uuid.uuid4()
    key = "sekret-key"
    s3 = FakeS3()
    app, client, mod, s3 = _mk_app(monkeypatch, s3=s3, enforce_key=key, hashed=False)

    # Missing key → 401
    r1 = client.get(f"/api/v1/titles/{title_id}/bundles/1/manifest")
    assert r1.status_code == 401

    # Header works
    r2 = client.get(f"/api/v1/titles/{title_id}/bundles/1/manifest", headers={"X-API-Key": key})
    assert r2.status_code == 200

    # Query param works
    r3 = client.get(f"/api/v1/titles/{title_id}/bundles/1/manifest?api_key={key}")
    assert r3.status_code == 200


def test_manifest_enforces_public_api_key_hashed(monkeypatch):
    title_id = uuid.uuid4()
    key = "another-secret"
    s3 = FakeS3()
    app, client, mod, s3 = _mk_app(monkeypatch, s3=s3, enforce_key=key, hashed=True)

    r1 = client.get(f"/api/v1/titles/{title_id}/bundles/1/manifest")
    assert r1.status_code == 401

    r2 = client.get(f"/api/v1/titles/{title_id}/bundles/1/manifest", headers={"X-API-Key": key})
    assert r2.status_code == 200


def test_manifest_season_bounds_validation(monkeypatch):
    title_id = uuid.uuid4()
    s3 = FakeS3()
    app, client, mod, s3 = _mk_app(monkeypatch, s3=s3)

    # season < 1 → 422
    r1 = client.get(f"/api/v1/titles/{title_id}/bundles/0/manifest")
    assert r1.status_code == 422

    # season > 999 → 422
    r2 = client.get(f"/api/v1/titles/{title_id}/bundles/1000/manifest")
    assert r2.status_code == 422
