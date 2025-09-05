# tests/test_public/test_discovery/test_get_title.py

import importlib
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes & helpers
# ─────────────────────────────────────────────────────────────

class FakeRepo:
    def __init__(self, *, item=None, raise_exc=False):
        self.item = item
        self.raise_exc = raise_exc
        self.last_get_title_arg = None

    def get_title(self, tid):
        self.last_get_title_arg = tid
        if self.raise_exc:
            raise RuntimeError("boom")
        return self.item


class DummyDetail:
    """Lightweight stand-in for TitleDetail used only inside the route."""
    def __init__(self, **data):
        self._data = data

    def dict(self):
        return dict(self._data)


def _mk_app(
    monkeypatch,
    *,
    repo: FakeRepo,
    ttl_env=60,
    enforce_key=None,
    hashed=False,
    sanitize_passthrough=True,
):
    """
    Build a tiny app that mounts the public discovery router and replaces:
      - rate_limit with no-op
      - TitleDetail with DummyDetail (so we don't depend on schema internals)
      - get_titles_repository with our FakeRepo
      - PUBLIC_ITEM_CACHE_TTL_SECONDS env for caching behavior
      - optional public API key enforcement (plain or SHA256)
      - optional sanitize_title_id behavior
    """
    mod = importlib.import_module("app.api.v1.routers.public.discovery")

    # No-op per-route limiter
    async def _no_rate_limit(*_, **__):
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # Use our dummy TitleDetail so route's isinstance + .dict() work.
    monkeypatch.setattr(mod, "TitleDetail", DummyDetail, raising=True)

    # TTL env (positive to trigger cache_json_response code path)
    if ttl_env is None:
        monkeypatch.delenv("PUBLIC_ITEM_CACHE_TTL_SECONDS", raising=False)
    else:
        monkeypatch.setenv("PUBLIC_ITEM_CACHE_TTL_SECONDS", str(ttl_env))

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

    # Repo provider
    monkeypatch.setattr(mod, "get_titles_repository", lambda: repo, raising=True)

    # Sanitize behavior
    if sanitize_passthrough:
        monkeypatch.setattr(mod, "sanitize_title_id", lambda x: x, raising=True)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")
    client = TestClient(app)
    return app, client, mod, repo


def _url(tid):
    return f"/api/v1/titles/{tid}"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_get_title_happy_path_cached_with_strong_etag_and_headers(monkeypatch):
    repo = FakeRepo(item=DummyDetail(id="tt1234", name="Toy Story"))
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=45)

    headers_in = {"x-request-id": "req-123", "traceparent": "00-abc-xyz-01"}
    r = client.get(_url("toy-story"), headers=headers_in)

    assert r.status_code == 200
    assert r.json() == {"id": "tt1234", "name": "Toy Story"}

    # Strong ETag + CDN-friendly cache
    etag = r.headers.get("ETag")
    assert etag and etag.startswith('"') and not etag.startswith('W/')
    assert r.headers.get("Cache-Control") == (
        "public, max-age=45, s-maxage=45, stale-while-revalidate=60, stale-if-error=300"
    )
    assert r.headers.get("Vary") == "Accept, If-None-Match"

    # Correlation headers echoed
    assert r.headers.get("x-request-id") == "req-123"
    assert r.headers.get("traceparent") == "00-abc-xyz-01"


def test_get_title_conditional_get_returns_304(monkeypatch):
    repo = FakeRepo(item=DummyDetail(id="tt1234", name="Toy Story"))
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=30)

    first = client.get(_url("tt1234"))
    etag = first.headers["ETag"]

    second = client.get(_url("tt1234"), headers={"If-None-Match": etag, "x-request-id": "etag-hit"})
    assert second.status_code == 304
    # cache_json_response returns JSONResponse(content=None) → "null"
    assert second.text.strip() == "null"
    assert second.headers.get("ETag") == etag
    assert second.headers.get("Cache-Control") == (
        "public, max-age=30, s-maxage=30, stale-while-revalidate=60, stale-if-error=300"
    )
    assert second.headers.get("Vary") == "Accept, If-None-Match"
    assert second.headers.get("x-request-id") == "etag-hit"


def test_get_title_404_when_repo_returns_none(monkeypatch):
    repo = FakeRepo(item=None)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=60)

    r = client.get(_url("missing-slug"))
    assert r.status_code == 404
    assert r.json()["detail"] == "Title not found"


def test_get_title_500_on_repo_exception(monkeypatch):
    repo = FakeRepo(raise_exc=True)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=60)

    r = client.get(_url("any"))
    assert r.status_code == 500
    assert r.json()["detail"] == "Failed to fetch title"


def test_get_title_enforces_public_api_key_plain(monkeypatch):
    key = "sekret123"
    repo = FakeRepo(item=DummyDetail(id="tt", name="X"))
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=60, enforce_key=key, hashed=False)

    r1 = client.get(_url("tt"))
    assert r1.status_code == 401

    r2 = client.get(_url("tt"), headers={"X-API-Key": key})
    assert r2.status_code == 200

    r3 = client.get(_url("tt") + f"?api_key={key}")
    assert r3.status_code == 200


def test_get_title_enforces_public_api_key_hashed(monkeypatch):
    key = "supersecret"
    repo = FakeRepo(item=DummyDetail(id="tt", name="Y"))
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=60, enforce_key=key, hashed=True)

    r1 = client.get(_url("tt"))
    assert r1.status_code == 401

    r2 = client.get(_url("tt"), headers={"X-API-Key": key})
    assert r2.status_code == 200


def test_get_title_sanitize_title_id_is_applied_and_forwarded(monkeypatch):
    repo = FakeRepo(item=DummyDetail(id="ttsan", name="Sanitized"))
    _app, client, mod, repo = _mk_app(monkeypatch, repo=repo, ttl_env=60, sanitize_passthrough=False)

    # Force sanitize_title_id to return a sentinel so we can assert forwarding
    monkeypatch.setattr(mod, "sanitize_title_id", lambda raw: "SANITIZED", raising=True)

    r = client.get(_url("WeIRD-slug_123"))
    assert r.status_code == 200
    assert repo.last_get_title_arg == "SANITIZED"
