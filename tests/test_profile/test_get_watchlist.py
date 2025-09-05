# tests/test_user/test_get_watchlist.py

import importlib
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────

class FakeUserRepo:
    def __init__(self, *, items=None, raise_exc=False):
        self.items = list(items or [])
        self.raise_exc = raise_exc
        self.calls = 0
        self.last_user_id = None

    def get_watchlist(self, user_id: str):
        self.calls += 1
        self.last_user_id = user_id
        if self.raise_exc:
            raise RuntimeError("boom")
        return list(self.items)


class DummyWatchlist:
    """Schema-agnostic stand-in for Watchlist(items=[...])."""
    def __init__(self, *, items):
        self.items = list(items)

    def dict(self):
        return {"items": list(self.items)}


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
      - Watchlist -> DummyWatchlist
      - _log_user_action -> recorder (optional)
      - PUBLIC_API_KEY / PUBLIC_API_KEY_SHA256 (optional)
    """
    mod = importlib.import_module("app.api.v1.routers.user.me")

    # No-op rate limiter
    async def _no_rate_limit(*_, **__): return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # Repo + model
    monkeypatch.setattr(mod, "get_user_repository", lambda: repo, raising=True)
    monkeypatch.setattr(mod, "Watchlist", DummyWatchlist, raising=True)

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


def _url():
    return "/api/v1/watchlist"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_watchlist_happy_path_no_store_and_logging(monkeypatch):
    repo = FakeUserRepo(items=["tt1", "tt2"])
    _app, client, _mod, log_calls = _mk_app(monkeypatch, repo=repo, record_log=True)

    r = client.get(_url())
    assert r.status_code == 200
    body = r.json()
    assert body == {"items": ["tt1", "tt2"]}

    # repo call & user id
    assert repo.calls == 1 and repo.last_user_id == "u-123"

    # logging
    assert any(
        c["action"] == "WATCHLIST_GET"
        and c["user_id"] == "u-123"
        and c["meta"].get("count") == 2
        for c in log_calls
    )

    # no-store headers
    assert r.headers.get("Cache-Control") == "no-store"
    assert r.headers.get("Pragma") == "no-cache"
    assert r.headers.get("Expires") == "0"


def test_watchlist_order_is_preserved(monkeypatch):
    repo = FakeUserRepo(items=["b", "a", "c"])
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    r = client.get(_url())
    assert r.status_code == 200
    assert r.json()["items"] == ["b", "a", "c"]


def test_watchlist_empty_list(monkeypatch):
    repo = FakeUserRepo(items=[])
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    r = client.get(_url())
    assert r.status_code == 200
    assert r.json() == {"items": []}


def test_watchlist_auth_dependency_unauthorized(monkeypatch):
    repo = FakeUserRepo(items=["tt1"])
    _app, client, mod, _ = _mk_app(monkeypatch, repo=repo)

    async def _raise_unauth():
        raise HTTPException(status_code=401, detail="Unauthorized")
    monkeypatch.setattr(mod, "get_current_user", _raise_unauth, raising=True)

    r = client.get(_url())
    assert r.status_code == 401
    assert repo.calls == 0


def test_watchlist_repo_exception_yields_500(monkeypatch):
    repo = FakeUserRepo(raise_exc=True)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    r = client.get(_url())
    assert r.status_code == 500


def test_watchlist_api_key_enforcement_plain(monkeypatch):
    key = "sekret123"
    repo = FakeUserRepo(items=["tt1"])
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=False)

    r1 = client.get(_url())
    assert r1.status_code == 401

    r2 = client.get(_url(), headers={"X-API-Key": key})
    assert r2.status_code == 200 and r2.json() == {"items": ["tt1"]}

    r3 = client.get(_url() + f"?api_key={key}")
    assert r3.status_code == 200 and r3.json() == {"items": ["tt1"]}


def test_watchlist_api_key_enforcement_hashed(monkeypatch):
    key = "super-secret"
    repo = FakeUserRepo(items=["tt1"])
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=True)

    r1 = client.get(_url())
    assert r1.status_code == 401

    r2 = client.get(_url(), headers={"X-API-Key": key})
    assert r2.status_code == 200 and r2.json() == {"items": ["tt1"]}
