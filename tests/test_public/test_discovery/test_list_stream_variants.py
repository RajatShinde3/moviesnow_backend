# tests/test_public/test_discovery/test_list_stream_variants.py

import importlib
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes & helpers
# ─────────────────────────────────────────────────────────────

class FakeRepo:
    def __init__(self, *, variants=None, raise_exc=False):
        self.variants = variants or []
        self.raise_exc = raise_exc
        self.last_tid = None

    def get_stream_variants(self, tid):
        self.last_tid = tid
        if self.raise_exc:
            raise RuntimeError("boom")
        return self.variants


def _mk_app(
    monkeypatch,
    *,
    repo,
    ttl_env,
    enforce_key=None,
    hashed=False,
    sanitize_passthrough=True,
):
    """
    Build a tiny app mounting the public discovery router and replacing:
      - rate_limit with no-op
      - get_titles_repository with our repo (can be any object)
      - PUBLIC_ITEM_CACHE_TTL_SECONDS with ttl_env
      - optional API key enforcement (plain or SHA256 env)
      - optional sanitize passthrough (or we can override it later in tests)
    """
    mod = importlib.import_module("app.api.v1.routers.public.discovery")

    # No-op limiter
    async def _no_rate_limit(*_, **__):
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # TTL env
    if ttl_env is None:
        monkeypatch.delenv("PUBLIC_ITEM_CACHE_TTL_SECONDS", raising=False)
    else:
        monkeypatch.setenv("PUBLIC_ITEM_CACHE_TTL_SECONDS", str(ttl_env))

    # API key envs
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

    # Repo provider
    monkeypatch.setattr(mod, "get_titles_repository", lambda: repo, raising=True)

    # Sanitize passthrough by default (tests can override to assert it was used)
    if sanitize_passthrough:
        monkeypatch.setattr(mod, "sanitize_title_id", lambda x: x, raising=True)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")
    client = TestClient(app)
    return app, client, mod


def _url(tid):
    return f"/api/v1/titles/{tid}/streams"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_stream_variants_happy_path_cached_etag_and_headers(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.public.discovery")
    variants = [
        # already-dicts are accepted
        {"quality": mod.QualityEnum.q1080p, "bitrate_kbps": 4500, "codec": "h264", "container": "mp4", "drm": False},
        {"quality": "720p", "bitrate_kbps": 2500, "codec": "h264", "container": "mp4", "drm": False},
    ]
    repo = FakeRepo(variants=variants)
    _app, client, _ = _mk_app(monkeypatch, repo=repo, ttl_env=40)

    headers_in = {"x-request-id": "req-123", "traceparent": "00-abc-xyz-01"}
    r = client.get(_url("toy-story"), headers=headers_in)

    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list) and len(body) == 2
    assert body[0]["quality"] == "1080p"
    assert body[1]["quality"] == "720p"

    # Cached responses: strong ETag, CDN cache, vary, and correlation headers
    etag = r.headers.get("ETag")
    assert etag and etag.startswith('"') and not etag.startswith('W/')
    assert r.headers.get("Cache-Control") == (
        "public, max-age=40, s-maxage=40, stale-while-revalidate=60, stale-if-error=300"
    )
    assert r.headers.get("Vary") == "Accept, If-None-Match"
    assert r.headers.get("x-request-id") == "req-123"
    assert r.headers.get("traceparent") == "00-abc-xyz-01"
    # sanitize passthrough by default → repo saw raw id
    assert repo.last_tid == "toy-story"


def test_stream_variants_conditional_get_304(monkeypatch):
    repo = FakeRepo(variants=[{"quality": "auto"}])
    _app, client, _ = _mk_app(monkeypatch, repo=repo, ttl_env=30)

    r1 = client.get(_url("tt123"))
    etag = r1.headers["ETag"]

    r2 = client.get(_url("tt123"), headers={"If-None-Match": etag, "x-request-id": "etag-hit"})
    assert r2.status_code == 304
    # cache_json_response(content=None) → "null"
    assert r2.text.strip() == "null"
    assert r2.headers.get("ETag") == etag
    assert r2.headers.get("Cache-Control") == (
        "public, max-age=30, s-maxage=30, stale-while-revalidate=60, stale-if-error=300"
    )
    assert r2.headers.get("Vary") == "Accept, If-None-Match"
    assert r2.headers.get("x-request-id") == "etag-hit"


def test_stream_variants_conditional_get_star(monkeypatch):
    repo = FakeRepo(variants=[{"quality": "auto"}])
    _app, client, _ = _mk_app(monkeypatch, repo=repo, ttl_env=35)

    r = client.get(_url("any"), headers={"If-None-Match": "*"})
    assert r.status_code == 304
    assert r.text.strip() == "null"


def test_stream_variants_no_cache_when_ttl_zero(monkeypatch):
    repo = FakeRepo(variants=[{"quality": "480p", "bitrate_kbps": 800}])
    _app, client, _ = _mk_app(monkeypatch, repo=repo, ttl_env=0)

    r = client.get(_url("slug"))
    assert r.status_code == 200
    assert r.json()[0]["quality"] == "480p"

    # No caching headers / etag expected when ttl=0
    assert r.headers.get("ETag") is None
    assert r.headers.get("Vary") is None
    cc = r.headers.get("Cache-Control")
    assert (cc is None) or ("max-age" not in cc)


def test_stream_variants_accepts_existing_model_instances(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.public.discovery")
    inst = mod.StreamVariant(quality=mod.QualityEnum.q2160p, bitrate_kbps=12000, codec="h265", container="mp4", drm=True)
    repo = FakeRepo(variants=[inst])
    _app, client, _ = _mk_app(monkeypatch, repo=repo, ttl_env=0)

    r = client.get(_url("slug"))
    assert r.status_code == 200
    body = r.json()
    assert body == [{"quality": "2160p", "bitrate_kbps": 12000, "codec": "h265", "container": "mp4", "drm": True}]


def test_stream_variants_repo_exception_returns_500(monkeypatch):
    repo = FakeRepo(raise_exc=True)
    _app, client, mod = _mk_app(monkeypatch, repo=repo, ttl_env=0)
    r = client.get(_url("oops"))
    assert r.status_code == 500
    assert r.json()["detail"] == "Failed to fetch stream variants"


def test_stream_variants_missing_method_returns_empty_list_but_cached(monkeypatch):
    # Provide an object without get_stream_variants → route returns []
    repo = object()
    _app, client, _ = _mk_app(monkeypatch, repo=repo, ttl_env=25)

    r = client.get(_url("anything"))
    assert r.status_code == 200
    assert r.json() == []
    # still cached with ttl=25
    assert r.headers.get("ETag")
    assert "max-age=25" in r.headers.get("Cache-Control", "")


def test_stream_variants_enforces_public_api_key_plain(monkeypatch):
    key = "sekret123"
    repo = FakeRepo(variants=[{"quality": "auto"}])
    _app, client, _ = _mk_app(monkeypatch, repo=repo, ttl_env=0, enforce_key=key, hashed=False)

    r1 = client.get(_url("tt"))
    assert r1.status_code == 401

    r2 = client.get(_url("tt"), headers={"X-API-Key": key})
    assert r2.status_code == 200

    r3 = client.get(_url("tt") + f"?api_key={key}")
    assert r3.status_code == 200


def test_stream_variants_enforces_public_api_key_hashed(monkeypatch):
    key = "super-secret"
    repo = FakeRepo(variants=[{"quality": "auto"}])
    _app, client, _ = _mk_app(monkeypatch, repo=repo, ttl_env=0, enforce_key=key, hashed=True)

    r1 = client.get(_url("tt"))
    assert r1.status_code == 401

    r2 = client.get(_url("tt"), headers={"X-API-Key": key})
    assert r2.status_code == 200


def test_stream_variants_applies_sanitize_title_id(monkeypatch):
    repo = FakeRepo(variants=[{"quality": "720p"}])
    _app, client, mod = _mk_app(monkeypatch, repo=repo, ttl_env=0, sanitize_passthrough=False)

    # Force sanitize to return a sentinel value; assert repo saw it
    monkeypatch.setattr(mod, "sanitize_title_id", lambda raw: "SANITIZED", raising=True)

    r = client.get(_url("WeIRD-slug_123"))
    assert r.status_code == 200
    assert repo.last_tid == "SANITIZED"
