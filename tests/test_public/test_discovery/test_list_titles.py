# tests/test_public/test_discovery/test_list_titles.py

import importlib
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Minimal hot-cache for deterministic tests
# ─────────────────────────────────────────────────────────────

class DummyCache:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def set(self, key, value, ttl):
        # ignore ttl in tests
        self.store[key] = value


# ─────────────────────────────────────────────────────────────
# Fake repository
# ─────────────────────────────────────────────────────────────

class FakeTitlesRepo:
    def __init__(self, *, items=None, total=0, facets=None, raise_exc=False):
        self.items = items or []
        self.total = total
        self.facets = facets or {}
        self.raise_exc = raise_exc
        self.last_args = None

    def search_titles(self, *, q, filters, sort, order, page, page_size):
        self.last_args = {
            "q": q,
            "filters": filters,
            "sort": sort,
            "order": order,
            "page": page,
            "page_size": page_size,
        }
        if self.raise_exc:
            raise RuntimeError("boom")
        return self.items, self.total, self.facets


# ─────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    repo: FakeTitlesRepo,
    ttl_env=None,
    enforce_key=None,
    hashed=False,
):
    """
    Build a tiny app with the public discovery router mounted at /api/v1.
    - Replace rate_limit with no-op
    - Wire in FakeTitlesRepo via get_titles_repository
    - Override in-proc TTL cache with DummyCache
    - Optionally enforce a public API key (plain or SHA256)
    - Optionally set PUBLIC_CACHE_TTL_SECONDS
    """
    mod = importlib.import_module("app.api.v1.routers.public.discovery")

    # Disable per-route limiter
    async def _no_rate_limit(*_, **__):
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # Ensure a fresh, simple cache per test
    monkeypatch.setattr(mod, "_resp_cache", DummyCache(), raising=True)

    # TTL env
    if ttl_env is None:
        monkeypatch.delenv("PUBLIC_CACHE_TTL_SECONDS", raising=False)
    else:
        monkeypatch.setenv("PUBLIC_CACHE_TTL_SECONDS", str(ttl_env))

    # API key enforcement toggles
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

    # Provide the fake repo
    monkeypatch.setattr(mod, "get_titles_repository", lambda: repo, raising=True)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")
    client = TestClient(app)
    return app, client, mod, repo


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _url(base="/api/v1/titles", **params):
    if not params:
        return base
    from urllib.parse import urlencode
    return f"{base}?{urlencode(params, doseq=True)}"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_list_titles_happy_path_etag_cache_and_pagination_headers(monkeypatch):
    # total=120 with page_size=24 → 5 pages; we request page 2
    repo = FakeTitlesRepo(items=[], total=120, facets={"genres": {"Action": 10}})
    _app, client, _mod, _repo = _mk_app(monkeypatch, repo=repo, ttl_env=45)

    headers_in = {"x-request-id": "req-123", "traceparent": "00-abc-xyz-01"}
    r = client.get(_url(page=2, page_size=24, sort="popularity", order="desc"), headers=headers_in)

    assert r.status_code == 200
    body = r.json()
    # Payload shape
    assert set(body.keys()) == {"items", "page", "page_size", "total", "facets"}
    assert body["items"] == []
    assert body["page"] == 2
    assert body["page_size"] == 24
    assert body["total"] == 120
    assert isinstance(body["facets"], dict)

    # Strong ETag, CDN-friendly caching, Vary present
    cc = r.headers.get("Cache-Control")
    assert cc == "public, max-age=45, s-maxage=45, stale-while-revalidate=60, stale-if-error=300"
    etag = r.headers.get("ETag")
    assert etag and etag.startswith('"') and not etag.startswith('W/')
    assert r.headers.get("Vary") == "Accept, If-None-Match"

    # Pagination headers
    assert r.headers.get("X-Total-Count") == "120"
    link = r.headers.get("Link")
    # should include first, prev (1), next (3), last (5)
    assert 'rel="first"' in link and "page=1" in link
    assert 'rel="prev"' in link and "page=1" in link
    assert 'rel="next"' in link and "page=3" in link
    assert 'rel="last"' in link and "page=5" in link

    # Correlation headers echoed
    assert r.headers.get("x-request-id") == "req-123"
    assert r.headers.get("traceparent") == "00-abc-xyz-01"


def test_list_titles_conditional_get_304_and_vary(monkeypatch):
    repo = FakeTitlesRepo(items=[], total=50, facets={})
    _app, client, _mod, _repo = _mk_app(monkeypatch, repo=repo, ttl_env=30)

    r1 = client.get(_url(page=1, page_size=10))
    etag = r1.headers["ETag"]

    r2 = client.get(_url(page=1, page_size=10), headers={"If-None-Match": etag, "x-request-id": "rid"})
    assert r2.status_code == 304
    # JSONResponse(content=None) serializes to null
    assert r2.text.strip() == "null"
    assert r2.headers.get("ETag") == etag
    assert r2.headers.get("Cache-Control") == "public, max-age=30, s-maxage=30, stale-while-revalidate=60, stale-if-error=300"
    assert r2.headers.get("Vary") == "Accept, If-None-Match"
    assert r2.headers.get("x-request-id") == "rid"


def test_list_titles_conditional_get_star_matches_all(monkeypatch):
    repo = FakeTitlesRepo(items=[], total=0, facets={})
    _app, client, _mod, _repo = _mk_app(monkeypatch, repo=repo, ttl_env=30)

    r = client.get(_url(), headers={"If-None-Match": "*"})
    assert r.status_code == 304
    assert r.text.strip() == "null"


def test_list_titles_hot_cache_served_without_repo_call(monkeypatch):
    repo = FakeTitlesRepo(items=[], total=10, facets={})
    _app, client, mod, _repo = _mk_app(monkeypatch, repo=repo, ttl_env=33)

    # Prime cache
    first = client.get(_url(page=1, page_size=10))
    assert first.status_code == 200

    # Now make repo unusable; hot cache path should short-circuit
    def _explode():
        raise AssertionError("repo should not be called when hot cache is present")
    monkeypatch.setattr(mod, "get_titles_repository", _explode, raising=True)

    again = client.get(_url(page=1, page_size=10), headers={"x-request-id": "cached"})
    assert again.status_code == 200
    assert again.headers.get("x-request-id") == "cached"
    # Still cached headers present
    assert "max-age=33" in again.headers.get("Cache-Control", "")


def test_list_titles_sanitizes_sort_and_order_and_forwards_filters(monkeypatch):
    repo = FakeTitlesRepo(items=[], total=0, facets={})
    _app, client, _mod, repo = _mk_app(monkeypatch, repo=repo, ttl_env=30)

    params = [
        ("q", "toy story"),
        ("sort", "not-a-valid-sort"),
        ("order", "sideways"),
        ("page", "3"),
        ("page_size", "24"),
        ("genres", "Action"),
        ("genres", "Comedy"),
        ("year_gte", "1999"),
        ("year_lte", "2005"),
        ("rating_gte", "7.1"),
        ("rating_lte", "9.5"),
        ("cast", "Tom Hanks"),
        ("cast", "Meryl Streep"),
    ]
    r = client.get("/api/v1/titles", params=params)
    assert r.status_code == 200

    # Repo called once
    assert repo.last_args is not None
    la = repo.last_args

    # Sanitized sort/order
    assert la["sort"] == "popularity"
    assert la["order"] == "desc"

    # Forwarded q and filters
    assert la["q"] == "toy story"
    assert la["page"] == 3 and la["page_size"] == 24
    assert la["filters"] == {
        "genres": ["Action", "Comedy"],
        "year_gte": 1999,
        "year_lte": 2005,
        "rating_gte": 7.1,
        "rating_lte": 9.5,
        "cast": ["Tom Hanks", "Meryl Streep"],
    }


def test_list_titles_repo_exception_returns_500(monkeypatch):
    repo = FakeTitlesRepo(raise_exc=True)
    _app, client, _mod, _repo = _mk_app(monkeypatch, repo=repo, ttl_env=30)

    r = client.get(_url())
    assert r.status_code == 500
    assert r.json()["detail"] == "Search failed"


def test_list_titles_ttl_default_and_invalid_env(monkeypatch):
    # Default 30
    repo1 = FakeTitlesRepo()
    _app1, client1, _mod1, _ = _mk_app(monkeypatch, repo=repo1, ttl_env=None)
    r1 = client1.get(_url())
    assert r1.headers.get("Cache-Control") == "public, max-age=30, s-maxage=30, stale-while-revalidate=60, stale-if-error=300"

    # Invalid env value → fallback to 30
    repo2 = FakeTitlesRepo()
    _app2, client2, _mod2, _ = _mk_app(monkeypatch, repo=repo2, ttl_env="not-an-int")
    r2 = client2.get(_url())
    assert r2.headers.get("Cache-Control") == "public, max-age=30, s-maxage=30, stale-while-revalidate=60, stale-if-error=300"


def test_list_titles_enforces_public_api_key_plain(monkeypatch):
    repo = FakeTitlesRepo()
    key = "sekret123"
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=30, enforce_key=key, hashed=False)

    r1 = client.get(_url())
    assert r1.status_code == 401

    r2 = client.get(_url(), headers={"X-API-Key": key})
    assert r2.status_code == 200

    r3 = client.get(_url(api_key=key))
    assert r3.status_code == 200


def test_list_titles_enforces_public_api_key_hashed(monkeypatch):
    repo = FakeTitlesRepo()
    key = "shhh-its-a-secret"
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=30, enforce_key=key, hashed=True)

    r1 = client.get(_url())
    assert r1.status_code == 401

    r2 = client.get(_url(), headers={"X-API-Key": key})
    assert r2.status_code == 200


def test_list_titles_query_validation_422(monkeypatch):
    repo = FakeTitlesRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=30)

    assert client.get(_url(page=0)).status_code == 422      # page >= 1
    assert client.get(_url(page_size=0)).status_code == 422 # page_size >= 1
    assert client.get(_url(page_size=101)).status_code == 422 # page_size <= 100
