# tests/test_public/test_downloads/test_list_downloads.py

import importlib
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, ttl_env=None, enforce_key=None, hashed=False):
    """
    Mount the public downloads router at /api/v1 and override:
      - rate_limit -> no-op
      - PUBLIC_DOWNLOADS_CACHE_TTL -> ttl_env
      - optional PUBLIC_API_KEY / PUBLIC_API_KEY_SHA256
    """
    mod = importlib.import_module("app.api.v1.routers.public.downloads")

    # no-op rate limiter
    async def _no_rate_limit(*_, **__):
        return None

    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # TTL env
    if ttl_env is None:
        monkeypatch.delenv("PUBLIC_DOWNLOADS_CACHE_TTL", raising=False)
    else:
        monkeypatch.setenv("PUBLIC_DOWNLOADS_CACHE_TTL", str(ttl_env))

    # API key envs
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

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")
    client = TestClient(app)
    return app, client, mod


def _url(title_id):
    return f"/api/v1/titles/{title_id}/downloads"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_list_downloads_happy_path_payload_and_cached_headers(monkeypatch):
    tid = uuid4()
    _app, client, _ = _mk_app(monkeypatch, ttl_env=45)

    headers_in = {"x-request-id": "req-123", "traceparent": "00-abc-xyz-01"}
    r = client.get(_url(tid), headers=headers_in)
    assert r.status_code == 200

    body = r.json()
    # Payload shape & content
    assert set(body.keys()) == {"title_id", "policy", "title", "episodes", "alternatives"}
    assert body["title_id"] == str(tid)
    assert body["policy"] == "bundles_only"
    assert body["title"] == []
    assert body["episodes"] == []
    assert body["alternatives"]["bundle_list"] == f"/titles/{tid}/bundles"
    assert body["alternatives"]["delivery_single"] == "/delivery/download-url"
    assert body["alternatives"]["delivery_batch"] == "/delivery/batch-download-urls"

    # Cached headers: strong ETag, Cache-Control, Vary, correlation echo
    etag = r.headers.get("ETag")
    assert etag and etag.startswith('"') and not etag.startswith('W/')
    assert r.headers.get("Cache-Control") == "public, max-age=45, s-maxage=45, stale-while-revalidate=30"
    assert r.headers.get("Vary") == "Accept, If-None-Match"
    assert r.headers.get("x-request-id") == "req-123"
    assert r.headers.get("traceparent") == "00-abc-xyz-01"


def test_list_downloads_conditional_get_304(monkeypatch):
    tid = uuid4()
    _app, client, _ = _mk_app(monkeypatch, ttl_env=30)

    r1 = client.get(_url(tid))
    etag = r1.headers["ETag"]

    r2 = client.get(_url(tid), headers={"If-None-Match": etag, "x-request-id": "etag-hit"})
    assert r2.status_code == 304
    # JSONResponse(content=None) → "null"
    assert r2.text.strip() == "null"
    assert r2.headers.get("ETag") == etag
    assert r2.headers.get("Cache-Control") == "public, max-age=30, s-maxage=30, stale-while-revalidate=30"
    assert r2.headers.get("Vary") == "Accept, If-None-Match"
    assert r2.headers.get("x-request-id") == "etag-hit"


def test_list_downloads_conditional_get_star(monkeypatch):
    tid = uuid4()
    _app, client, _ = _mk_app(monkeypatch, ttl_env=33)

    r = client.get(_url(tid), headers={"If-None-Match": "*"})
    assert r.status_code == 304
    assert r.text.strip() == "null"
    assert r.headers.get("Cache-Control") == "public, max-age=33, s-maxage=33, stale-while-revalidate=30"


def test_list_downloads_ttl_default_and_invalid_env(monkeypatch):
    tid1 = uuid4()
    # Default (no env) → 60
    _app1, client1, _ = _mk_app(monkeypatch, ttl_env=None)
    r1 = client1.get(_url(tid1))
    assert r1.headers.get("Cache-Control") == "public, max-age=60, s-maxage=60, stale-while-revalidate=30"

    # Invalid env value → fallback to 60
    tid2 = uuid4()
    _app2, client2, _ = _mk_app(monkeypatch, ttl_env="not-an-int")
    r2 = client2.get(_url(tid2))
    assert r2.headers.get("Cache-Control") == "public, max-age=60, s-maxage=60, stale-while-revalidate=30"


def test_list_downloads_enforces_public_api_key_plain(monkeypatch):
    key = "sekret123"
    tid = uuid4()
    _app, client, _ = _mk_app(monkeypatch, ttl_env=60, enforce_key=key, hashed=False)

    r1 = client.get(_url(tid))
    assert r1.status_code == 401

    r2 = client.get(_url(tid), headers={"X-API-Key": key})
    assert r2.status_code == 200

    r3 = client.get(_url(tid) + f"?api_key={key}")
    assert r3.status_code == 200


def test_list_downloads_enforces_public_api_key_hashed(monkeypatch):
    key = "super-secret"
    tid = uuid4()
    _app, client, _ = _mk_app(monkeypatch, ttl_env=60, enforce_key=key, hashed=True)

    r1 = client.get(_url(tid))
    assert r1.status_code == 401

    r2 = client.get(_url(tid), headers={"X-API-Key": key})
    assert r2.status_code == 200


def test_list_downloads_path_param_validation_422_for_non_uuid(monkeypatch):
    _app, client, _ = _mk_app(monkeypatch, ttl_env=60)
    r = client.get("/api/v1/titles/not-a-uuid/downloads")
    assert r.status_code == 422
