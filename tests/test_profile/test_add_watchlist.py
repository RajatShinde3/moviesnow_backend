# tests/test_user/test_add_watchlist.py

import importlib
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────

class FakeUserRepo:
    def __init__(self, *, raise_exc=False):
        self.raise_exc = raise_exc
        self.calls = 0
        self.last_user_id = None
        self.last_tid = None

    def add_watchlist(self, user_id: str, title_id: str):
        self.calls += 1
        self.last_user_id = user_id
        self.last_tid = title_id
        if self.raise_exc:
            raise RuntimeError("boom")


class FakeTitlesRepo:
    def __init__(self, *, raise_on_probe=False):
        self.raise_on_probe = raise_on_probe
        self.calls = 0
        self.last_tid = None

    def get_title(self, tid: str):
        self.calls += 1
        self.last_tid = tid
        if self.raise_on_probe:
            raise RuntimeError("probe failed")
        return {"id": tid}


# ─────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    user_repo: FakeUserRepo,
    titles_repo=None,
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
      - get_titles_repository -> titles_repo (object providing get_title, or anything)
      - get_current_user -> returns user_ctx (or default)
      - sanitize_title_id -> passthrough (tests override as needed)
      - _log_user_action -> recorder (optional)
      - PUBLIC_API_KEY / PUBLIC_API_KEY_SHA256 (optional)
    """
    mod = importlib.import_module("app.api.v1.routers.user.me")

    # No-op rate limiter
    async def _no_rate_limit(*_, **__):
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # Repos
    monkeypatch.setattr(mod, "get_user_repository", lambda: user_repo, raising=True)
    if titles_repo is None:
        titles_repo = FakeTitlesRepo()
    monkeypatch.setattr(mod, "get_titles_repository", lambda: titles_repo, raising=True)

    # Auth
    if user_ctx is None:
        user_ctx = {"id": "u-123", "email": "user@example.com"}
    async def _fake_current_user():
        return user_ctx
    monkeypatch.setattr(mod, "get_current_user", _fake_current_user, raising=True)

    # sanitize passthrough (tests may override)
    if sanitize_passthrough:
        monkeypatch.setattr(mod, "sanitize_title_id", lambda x: x, raising=True)

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
    return app, client, mod, titles_repo, log_calls


def _url(tid: str):
    return f"/api/v1/watchlist/{tid}"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_add_watchlist_happy_path_adds_and_logs(monkeypatch):
    user_repo = FakeUserRepo()
    _app, client, _mod, titles_repo, log_calls = _mk_app(
        monkeypatch, user_repo=user_repo, record_log=True
    )

    r = client.post(_url("tt123"))
    assert r.status_code == 204
    assert r.text == ""  # no body

    # repo called with authed user and same tid; probe performed
    assert user_repo.calls == 1
    assert user_repo.last_user_id == "u-123"
    assert user_repo.last_tid == "tt123"
    assert titles_repo.calls == 1 and titles_repo.last_tid == "tt123"

    # logged
    assert any(
        c["action"] == "WATCHLIST_ADD"
        and c["user_id"] == "u-123"
        and c["meta"].get("title_id") == "tt123"
        for c in log_calls
    )


def test_add_watchlist_applies_sanitize_and_forwards_to_repos_and_logger(monkeypatch):
    user_repo = FakeUserRepo()
    _app, client, mod, titles_repo, log_calls = _mk_app(
        monkeypatch, user_repo=user_repo, sanitize_passthrough=False, record_log=True
    )
    # sanitize to a sentinel
    monkeypatch.setattr(mod, "sanitize_title_id", lambda raw: "SANITIZED", raising=True)

    r = client.post(_url("WeIRD-slug_123"))
    assert r.status_code == 204

    assert user_repo.last_tid == "SANITIZED"
    assert titles_repo.last_tid == "SANITIZED"
    assert any(c["meta"].get("title_id") == "SANITIZED" for c in log_calls)


def test_add_watchlist_probe_errors_are_swallowed(monkeypatch):
    user_repo = FakeUserRepo()
    titles_repo = FakeTitlesRepo(raise_on_probe=True)
    _app, client, _mod, _titles_repo, _ = _mk_app(
        monkeypatch, user_repo=user_repo, titles_repo=titles_repo
    )

    r = client.post(_url("ttX"))
    assert r.status_code == 204
    # even though probe raised, we still persisted
    assert user_repo.calls == 1 and user_repo.last_tid == "ttX"
    assert titles_repo.calls == 1  # probe attempted


def test_add_watchlist_missing_get_title_method_is_ignored(monkeypatch):
    user_repo = FakeUserRepo()
    # object() lacks get_title → AttributeError should be caught and ignored
    _app, client, _mod, _titles_repo, _ = _mk_app(
        monkeypatch, user_repo=user_repo, titles_repo=object()
    )
    r = client.post(_url("ttY"))
    assert r.status_code == 204
    assert user_repo.calls == 1 and user_repo.last_tid == "ttY"


def test_add_watchlist_user_repo_exception_returns_500(monkeypatch):
    user_repo = FakeUserRepo(raise_exc=True)
    _app, client, _mod, _titles_repo, _ = _mk_app(monkeypatch, user_repo=user_repo)

    r = client.post(_url("ttZ"))
    assert r.status_code == 500


def test_add_watchlist_auth_dependency_unauthorized(monkeypatch):
    user_repo = FakeUserRepo()
    _app, client, mod, _titles_repo, _ = _mk_app(monkeypatch, user_repo=user_repo)

    async def _raise_unauth():
        raise HTTPException(status_code=401, detail="Unauthorized")
    monkeypatch.setattr(mod, "get_current_user", _raise_unauth, raising=True)

    r = client.post(_url("tt1"))
    assert r.status_code == 401
    assert user_repo.calls == 0


def test_add_watchlist_api_key_enforcement_plain(monkeypatch):
    key = "sekret123"
    user_repo = FakeUserRepo()
    _app, client, _mod, _titles_repo, _ = _mk_app(monkeypatch, user_repo=user_repo, enforce_key=key, hashed=False)

    r1 = client.post(_url("tt1"))
    assert r1.status_code == 401

    r2 = client.post(_url("tt1"), headers={"X-API-Key": key})
    assert r2.status_code == 204

    r3 = client.post(_url("tt1") + f"?api_key={key}")
    assert r3.status_code == 204


def test_add_watchlist_api_key_enforcement_hashed(monkeypatch):
    key = "super-secret"
    user_repo = FakeUserRepo()
    _app, client, _mod, _titles_repo, _ = _mk_app(monkeypatch, user_repo=user_repo, enforce_key=key, hashed=True)

    r1 = client.post(_url("tt1"))
    assert r1.status_code == 401

    r2 = client.post(_url("tt1"), headers={"X-API-Key": key})
    assert r2.status_code == 204
