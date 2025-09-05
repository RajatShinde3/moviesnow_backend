# tests/test_public/test_discovery/test_search.py

import importlib
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes & helpers
# ─────────────────────────────────────────────────────────────

class FakeRepo:
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


class DummySummary:
    """Stand-in for TitleSummary used by the route when shaping items."""
    def __init__(self, **data):
        self._data = dict(data)


class DummyPaginated:
    """Stand-in for PaginatedTitles; returns a serializable dict on .dict()."""
    def __init__(self, *, items, page, page_size, total, facets):
        self._payload = {
            "items": [it._data if isinstance(it, DummySummary) else it for it in items],
            "page": page,
            "page_size": page_size,
            "total": int(total or 0),
            "facets": facets or {},
        }

    def dict(self):
        return dict(self._payload)


def _mk_app(
    monkeypatch,
    *,
    repo: FakeRepo,
    ttl_env=None,
    enforce_key=None,
    hashed=False,
):
    """
    Build a tiny FastAPI app that mounts the public discovery router and replaces:
      - rate_limit -> no-op
      - TitleSummary -> DummySummary
      - PaginatedTitles -> DummyPaginated
      - get_titles_repository -> FakeRepo
      - PUBLIC_CACHE_TTL_SECONDS -> ttl_env
      - optional public API key enforcement (plain or SHA256)
    """
    mod = importlib.import_module("app.api.v1.routers.public.discovery")

    # No-op rate limiter
    async def _no_rate_limit(*_, **__):
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # Dummy models so tests don't depend on real schemas
    monkeypatch.setattr(mod, "TitleSummary", DummySummary, raising=True)
    monkeypatch.setattr(mod, "PaginatedTitles", DummyPaginated, raising=True)

    # TTL env
    if ttl_env is None:
        monkeypatch.delenv("PUBLIC_CACHE_TTL_SECONDS", raising=False)
    else:
        monkeypatch.setenv("PUBLIC_CACHE_TTL_SECONDS", str(ttl_env))

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

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")
    client = TestClient(app)
    return app, client, mod, repo


def _url(**params):
    base = "/api/v1/search"
    if not params:
        return base
    from urllib.parse import urlencode
    return f"{base}?{urlencode(params, doseq=True)}"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_search_happy_path_etag_cache_and_pagination_headers(monkeypatch):
    repo = FakeRepo(items=[], total=120, facets={"genres": {"Action": 10}})
    _app, client, _mod, _repo = _mk_app(monkeypatch, repo=repo, ttl_env=45)

    headers_in = {"x-request-id": "req-123", "traceparent": "00-abc-xyz-01"}
    r = client.get(_url(q="matrix", page=2, page_size=24), headers=headers_in)

    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {"items", "page", "page_size", "total", "facets"}
    assert body["page"] == 2 and body["page_size"] == 24 and body["total"] == 120

    # Strong ETag + CDN cache + Vary
    etag = r.headers.get("ETag")
    assert etag and etag.startswith('"') and not etag.startswith('W/')
    assert r.headers.get("Cache-Control") == (
        "public, max-age=45, s-maxage=45, stale-while-revalidate=60, stale-if-error=300"
    )
    assert r.headers.get("Vary") == "Accept, If-None-Match"

    # Pagination headers (RFC 5988)
    link = r.headers.get("Link")
    assert r.headers.get("X-Total-Count") == "120"
    assert 'rel="first"' in link and "page=1" in link
    assert 'rel="prev"' in link and "page=1" in link
    assert 'rel="next"' in link and "page=3" in link
    assert 'rel="last"' in link and "page=5" in link

    # Correlation echo
    assert r.headers.get("x-request-id") == "req-123"
    assert r.headers.get("traceparent") == "00-abc-xyz-01"


def test_search_repo_called_with_defaults(monkeypatch):
    repo = FakeRepo(items=[], total=0, facets={})
    _app, client, _mod, repo = _mk_app(monkeypatch, repo=repo, ttl_env=30)

    r = client.get(_url(q="toy story", page=3, page_size=10))
    assert r.status_code == 200

    la = repo.last_args
    assert la["q"] == "toy story"
    assert la["filters"] == {}
    assert la["sort"] == "popularity"
    assert la["order"] == "desc"
    assert la["page"] == 3 and la["page_size"] == 10


def test_search_conditional_get_304(monkeypatch):
    repo = FakeRepo(items=[], total=50, facets={})
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=30)

    r1 = client.get(_url(q="x"))
    etag = r1.headers["ETag"]

    r2 = client.get(_url(q="x"), headers={"If-None-Match": etag, "x-request-id": "etag-hit"})
    assert r2.status_code == 304
    assert r2.text.strip() == "null"
    assert r2.headers.get("ETag") == etag
    assert r2.headers.get("Cache-Control") == (
        "public, max-age=30, s-maxage=30, stale-while-revalidate=60, stale-if-error=300"
    )
    assert r2.headers.get("Vary") == "Accept, If-None-Match"
    assert r2.headers.get("x-request-id") == "etag-hit"


def test_search_conditional_get_star(monkeypatch):
    repo = FakeRepo(items=[], total=0, facets={})
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=35)

    r = client.get(_url(q="x"), headers={"If-None-Match": "*"})
    assert r.status_code == 304
    assert r.text.strip() == "null"


def test_search_ttl_default_and_invalid_env(monkeypatch):
    # Default 30
    repo1 = FakeRepo()
    _app1, client1, _mod1, _ = _mk_app(monkeypatch, repo=repo1, ttl_env=None)
    r1 = client1.get(_url(q="x"))
    assert r1.headers.get("Cache-Control") == (
        "public, max-age=30, s-maxage=30, stale-while-revalidate=60, stale-if-error=300"
    )

    # Invalid env -> fallback to 30
    repo2 = FakeRepo()
    _app2, client2, _mod2, _ = _mk_app(monkeypatch, repo=repo2, ttl_env="not-an-int")
    r2 = client2.get(_url(q="x"))
    assert r2.headers.get("Cache-Control") == (
        "public, max-age=30, s-maxage=30, stale-while-revalidate=60, stale-if-error=300"
    )


def test_search_enforces_public_api_key_plain(monkeypatch):
    key = "sekret123"
    repo = FakeRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=30, enforce_key=key, hashed=False)

    r1 = client.get(_url(q="x"))
    assert r1.status_code == 401

    r2 = client.get(_url(q="x"), headers={"X-API-Key": key})
    assert r2.status_code == 200

    r3 = client.get(_url(q="x", api_key=key))
    assert r3.status_code == 200


def test_search_enforces_public_api_key_hashed(monkeypatch):
    key = "super-secret"
    repo = FakeRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=30, enforce_key=key, hashed=True)

    r1 = client.get(_url(q="x"))
    assert r1.status_code == 401

    r2 = client.get(_url(q="x"), headers={"X-API-Key": key})
    assert r2.status_code == 200


def test_search_repo_exception_returns_500(monkeypatch):
    repo = FakeRepo(raise_exc=True)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=30)

    r = client.get(_url(q="x"))
    assert r.status_code == 500
    assert r.json()["detail"] == "Search failed"


def test_search_validation_422(monkeypatch):
    repo = FakeRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=30)

    # q is required and min_length=1
    assert client.get(_url()).status_code == 422
    assert client.get(_url(q="")).status_code == 422

    # page/page_size bounds
    assert client.get(_url(q="x", page=0)).status_code == 422
    assert client.get(_url(q="x", page_size=0)).status_code == 422
    assert client.get(_url(q="x", page_size=101)).status_code == 422


def test_search_items_are_shaped_via_TitleSummary_and_paginated(monkeypatch):
    # Provide a dict item; route should wrap it via TitleSummary (**), then DummyPaginated.dict()
    repo = FakeRepo(items=[{"id": "tt1", "name": "Toy Story"}], total=1, facets={"genres": {"Animation": 1}})
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, ttl_env=30)

    r = client.get(_url(q="toy"))
    assert r.status_code == 200
    body = r.json()
    assert body["items"] == [{"id": "tt1", "name": "Toy Story"}]
    assert body["total"] == 1
    assert body["facets"] == {"genres": {"Animation": 1}}
