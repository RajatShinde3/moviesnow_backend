# tests/test_user/test_list_reviews.py

import importlib
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes & dummies
# ─────────────────────────────────────────────────────────────

class FakeUserRepo:
    def __init__(self, *, items=None, total=0, raise_exc=False):
        self.items = list(items or [])
        self.total = int(total)
        self.raise_exc = raise_exc
        self.calls = 0
        self.last_args = {}

    def list_reviews(self, *, title_id, user_id, page, page_size):
        self.calls += 1
        self.last_args = {
            "title_id": title_id,
            "user_id": user_id,
            "page": page,
            "page_size": page_size,
        }
        if self.raise_exc:
            raise RuntimeError("boom")
        return list(self.items), int(self.total)


class DummyReview:
    """Schema-agnostic stand-in for Review(**i)."""
    def __init__(self, **data):
        self._data = dict(data)


class DummyPaginatedReviews:
    """Schema-agnostic stand-in for PaginatedReviews(...)."""
    def __init__(self, *, items, page, page_size, total):
        self._payload = {
            "items": [it._data if isinstance(it, DummyReview) else it for it in items],
            "page": page,
            "page_size": page_size,
            "total": total,
        }

    def dict(self):
        return dict(self._payload)


# ─────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    repo: FakeUserRepo,
    user_ctx=None,
    enforce_key=None,
    hashed=False,
    sanitize_passthrough=True,
    record_log=False,
):
    """
    Mount the /me router and override:
      - rate_limit -> no-op
      - get_user_repository -> FakeUserRepo
      - get_current_user -> returns user_ctx (or default)
      - Review / PaginatedReviews -> dummies (schema-agnostic)
      - sanitize_title_id -> passthrough (tests may override)
      - _log_user_action -> recorder (optional)
      - PUBLIC_API_KEY / PUBLIC_API_KEY_SHA256 (optional)
    """
    mod = importlib.import_module("app.api.v1.routers.user.me")

    # no-op rate limiter
    async def _no_rate_limit(*_, **__): return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # repo & models
    monkeypatch.setattr(mod, "get_user_repository", lambda: repo, raising=True)
    monkeypatch.setattr(mod, "Review", DummyReview, raising=True)
    monkeypatch.setattr(mod, "PaginatedReviews", DummyPaginatedReviews, raising=True)

    # auth
    if user_ctx is None:
        user_ctx = {"id": "u-123", "email": "user@example.com"}
    async def _fake_current_user(): return user_ctx
    monkeypatch.setattr(mod, "get_current_user", _fake_current_user, raising=True)

    # sanitize
    if sanitize_passthrough:
        monkeypatch.setattr(mod, "sanitize_title_id", lambda x: x, raising=True)

    # log recorder
    log_calls = []
    if record_log:
        def _recorder(request, user_id, action, **meta):
            log_calls.append({"user_id": user_id, "action": action, "meta": meta})
        monkeypatch.setattr(mod, "_log_user_action", _recorder, raising=True)

    # API key enforcement env
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

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")
    client = TestClient(app)
    return app, client, mod, log_calls


def _url(**params):
    base = "/api/v1/reviews"
    if not params:
        return base
    from urllib.parse import urlencode
    return f"{base}?{urlencode(params)}"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_list_reviews_by_title_happy_path_no_store_and_pagination_headers(monkeypatch):
    items = [
        {"id": "r1", "title_id": "tt123", "user_id": "u-111", "content": "Nice"},
        {"id": "r2", "title_id": "tt123", "user_id": "u-222", "content": "Great"},
    ]
    repo = FakeUserRepo(items=items, total=55)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, record_log=True)

    headers_in = {"x-request-id": "req-abc"}
    r = client.get(_url(title_id="tt123", page=2, page_size=20), headers=headers_in)
    assert r.status_code == 200

    body = r.json()
    assert body["page"] == 2 and body["page_size"] == 20 and body["total"] == 55
    assert [i["id"] for i in body["items"]] == ["r1", "r2"]

    # repo called correctly: by title, not by user
    assert repo.calls == 1
    assert repo.last_args["title_id"] == "tt123"
    assert repo.last_args["user_id"] is None
    assert repo.last_args["page"] == 2 and repo.last_args["page_size"] == 20

    # pagination headers
    assert r.headers.get("X-Total-Count") == "55"
    link = r.headers.get("Link", "")
    assert 'rel="first"' in link and "page=1" in link
    assert 'rel="prev"' in link and "page=1" in link
    assert 'rel="next"' in link and "page=3" in link
    assert 'rel="last"' in link and "page=3" in link

    # no-store cache headers
    assert r.headers.get("Cache-Control") == "no-store"
    assert r.headers.get("Pragma") == "no-cache"
    assert r.headers.get("Expires") == "0"


def test_list_reviews_by_current_user_when_no_title_param(monkeypatch):
    items = [{"id": "r1", "title_id": "ttX", "user_id": "u-123", "content": "Mine"}]
    repo = FakeUserRepo(items=items, total=1)
    _app, client, _mod, log_calls = _mk_app(monkeypatch, repo=repo, record_log=True)

    r = client.get(_url(page=1, page_size=10))
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1 and body["items"][0]["user_id"] == "u-123"

    # repo called for current user
    assert repo.last_args["title_id"] is None
    assert repo.last_args["user_id"] == "u-123"

    # logging metadata: by_title False, title_id None
    assert any(
        c["action"] == "REVIEWS_LIST" and c["meta"].get("by_title") is False and c["meta"].get("title_id") is None
        for c in log_calls
    )


def test_list_reviews_applies_sanitize_to_query_title_id(monkeypatch):
    repo = FakeUserRepo(items=[], total=0)
    _app, client, mod, log_calls = _mk_app(monkeypatch, repo=repo, sanitize_passthrough=False, record_log=True)
    monkeypatch.setattr(mod, "sanitize_title_id", lambda raw: "SANITIZED", raising=True)

    r = client.get(_url(title_id="  Weird  ", page=1, page_size=10))
    assert r.status_code == 200
    assert repo.last_args["title_id"] == "SANITIZED"
    assert any(c["meta"].get("title_id") == "SANITIZED" and c["meta"].get("by_title") is True for c in log_calls)


def test_list_reviews_validation_422(monkeypatch):
    repo = FakeUserRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)
    assert client.get(_url(page=0)).status_code == 422
    assert client.get(_url(page_size=0)).status_code == 422
    assert client.get(_url(page_size=101)).status_code == 422


def test_list_reviews_auth_dependency_unauthorized(monkeypatch):
    repo = FakeUserRepo()
    _app, client, mod, _ = _mk_app(monkeypatch, repo=repo)

    async def _raise_unauth():
        raise HTTPException(status_code=401, detail="Unauthorized")
    monkeypatch.setattr(mod, "get_current_user", _raise_unauth, raising=True)

    r = client.get(_url())
    assert r.status_code == 401
    assert repo.calls == 0


def test_list_reviews_repo_exception_yields_500(monkeypatch):
    repo = FakeUserRepo(raise_exc=True)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)
    r = client.get(_url(page=1, page_size=20))
    assert r.status_code == 500


def test_list_reviews_api_key_enforcement_plain(monkeypatch):
    key = "sekret123"
    repo = FakeUserRepo(items=[])
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=False)

    r1 = client.get(_url())
    assert r1.status_code == 401

    r2 = client.get(_url(), headers={"X-API-Key": key})
    assert r2.status_code == 200

    r3 = client.get(_url() + f"?api_key={key}")
    assert r3.status_code == 200


def test_list_reviews_api_key_enforcement_hashed(monkeypatch):
    key = "super-secret"
    repo = FakeUserRepo(items=[])
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=True)

    r1 = client.get(_url())
    assert r1.status_code == 401

    r2 = client.get(_url(), headers={"X-API-Key": key})
    assert r2.status_code == 200
