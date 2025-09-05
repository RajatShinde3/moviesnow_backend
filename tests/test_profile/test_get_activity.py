# tests/test_user/test_get_activity.py

import importlib
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────

class FakeUserRepo:
    def __init__(self, *, items=None, total=0, raise_exc=False):
        self.items = items or []
        self.total = total
        self.raise_exc = raise_exc
        self.calls = 0
        self.last_user_id = None
        self.last_page = None
        self.last_page_size = None

    def get_activity(self, user_id: str, page: int, page_size: int):
        self.calls += 1
        self.last_user_id = user_id
        self.last_page = page
        self.last_page_size = page_size
        if self.raise_exc:
            raise RuntimeError("boom")
        return self.items, self.total


class DummyActivityEntry:
    """Stand-in for ActivityEntry (accept any fields)."""
    def __init__(self, **data):
        self._data = dict(data)


class DummyPaginatedActivity:
    """Stand-in for PaginatedActivity producing a serializable dict."""
    def __init__(self, *, items, page, page_size, total):
        self._payload = {
            "items": [it._data if isinstance(it, DummyActivityEntry) else it for it in items],
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
    record_log=False,
):
    """
    Mount the /me router and override:
      - rate_limit -> no-op
      - get_user_repository -> FakeUserRepo
      - get_current_user -> returns user_ctx (or default)
      - _log_user_action -> recorder (optional)
      - ActivityEntry / PaginatedActivity -> dummies (schema-agnostic tests)
      - PUBLIC_API_KEY / PUBLIC_API_KEY_SHA256 (optional)
    """
    mod = importlib.import_module("app.api.v1.routers.user.me")

    # No-op rate limiter
    async def _no_rate_limit(*_, **__): return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # Repo + models
    monkeypatch.setattr(mod, "get_user_repository", lambda: repo, raising=True)
    monkeypatch.setattr(mod, "ActivityEntry", DummyActivityEntry, raising=True)
    monkeypatch.setattr(mod, "PaginatedActivity", DummyPaginatedActivity, raising=True)

    # Auth dependency
    if user_ctx is None:
        user_ctx = {"id": "u-123", "email": "user@example.com"}
    async def _fake_current_user(): return user_ctx
    monkeypatch.setattr(mod, "get_current_user", _fake_current_user, raising=True)

    # Optional log recorder
    log_calls = []
    if record_log:
        def _recorder(request, user_id, action, **meta):
            log_calls.append({"user_id": user_id, "action": action, "meta": meta})
        monkeypatch.setattr(mod, "_log_user_action", _recorder, raising=True)

    # API key enforcement
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
    base = "/api/v1/activity"
    if not params:
        return base
    from urllib.parse import urlencode
    return f"{base}?{urlencode(params)}"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_activity_happy_path_no_store_and_pagination_headers(monkeypatch):
    # total=55 with page_size=20 → 3 pages; request page 2
    items = [
        {"type": "LOGIN", "at": "2025-08-01T10:00:00Z"},
        {"type": "PROFILE_PATCH", "at": "2025-08-02T11:00:00Z"},
    ]
    repo = FakeUserRepo(items=items, total=55)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, record_log=True)

    headers_in = {"x-request-id": "req-abc", "traceparent": "00-foo-bar-01"}
    r = client.get(_url(page=2, page_size=20), headers=headers_in)
    assert r.status_code == 200

    body = r.json()
    assert set(body.keys()) == {"items", "page", "page_size", "total"}
    assert body["page"] == 2 and body["page_size"] == 20 and body["total"] == 55
    assert len(body["items"]) == 2 and body["items"][0]["type"] == "LOGIN"

    # Repo call correctness
    assert repo.calls == 1 and repo.last_user_id == "u-123"
    assert repo.last_page == 2 and repo.last_page_size == 20

    # Pagination headers
    assert r.headers.get("X-Total-Count") == "55"
    link = r.headers.get("Link", "")
    # Should include first (1), prev (1), next (3), last (3)
    assert 'rel="first"' in link and "page=1" in link
    assert 'rel="prev"' in link and "page=1" in link
    assert 'rel="next"' in link and "page=3" in link
    assert 'rel="last"' in link and "page=3" in link

    # no-store cache headers
    assert r.headers.get("Cache-Control") == "no-store"
    assert r.headers.get("Pragma") == "no-cache"
    assert r.headers.get("Expires") == "0"


def test_activity_logs_action(monkeypatch):
    repo = FakeUserRepo(items=[], total=0)
    _app, client, _mod, log_calls = _mk_app(monkeypatch, repo=repo, record_log=True)

    r = client.get(_url(page=1, page_size=10))
    assert r.status_code == 200
    assert any(
        call["action"] == "ACTIVITY_LIST"
        and call["user_id"] == "u-123"
        and call["meta"].get("page") == 1
        and call["meta"].get("page_size") == 10
        for call in log_calls
    )


def test_activity_validation_422(monkeypatch):
    repo = FakeUserRepo(items=[], total=0)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    assert client.get(_url(page=0)).status_code == 422
    assert client.get(_url(page_size=0)).status_code == 422
    assert client.get(_url(page_size=101)).status_code == 422


def test_activity_auth_dependency_unauthorized(monkeypatch):
    repo = FakeUserRepo(items=[], total=0)
    _app, client, mod, _ = _mk_app(monkeypatch, repo=repo)

    async def _raise_unauth():
        raise HTTPException(status_code=401, detail="Unauthorized")
    monkeypatch.setattr(mod, "get_current_user", _raise_unauth, raising=True)

    r = client.get(_url())
    assert r.status_code == 401


def test_activity_repo_exception_yields_500(monkeypatch):
    repo = FakeUserRepo(raise_exc=True)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    r = client.get(_url(page=1, page_size=10))
    assert r.status_code == 500


def test_activity_api_key_enforcement_plain(monkeypatch):
    key = "sekret123"
    repo = FakeUserRepo(items=[], total=0)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=False)

    r1 = client.get(_url())
    assert r1.status_code == 401

    r2 = client.get(_url(), headers={"X-API-Key": key})
    assert r2.status_code == 200


def test_activity_api_key_enforcement_hashed(monkeypatch):
    key = "super-secret"
    repo = FakeUserRepo(items=[], total=0)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=True)

    r1 = client.get(_url())
    assert r1.status_code == 401

    r2 = client.get(_url(), headers={"X-API-Key": key})
    assert r2.status_code == 200
