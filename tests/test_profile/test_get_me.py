# tests/test_user/test_get_me.py

import importlib
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────

class FakeUserRepo:
    def __init__(self, *, profile=None, raise_exc=False):
        # Minimal valid profile must include "id"
        self.profile = profile or {"id": "u-123"}
        self.raise_exc = raise_exc
        self.last_user_id = None
        self.calls = 0

    def get_profile(self, user_id: str):
        self.calls += 1
        self.last_user_id = user_id
        if self.raise_exc:
            raise RuntimeError("boom")
        return dict(self.profile)  # return a copy to avoid accidental mutation


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
      - PUBLIC_API_KEY / PUBLIC_API_KEY_SHA256 (optional)
    """
    mod = importlib.import_module("app.api.v1.routers.user.me")

    # No-op rate limiter
    async def _no_rate_limit(*_, **__):
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # Repo provider
    monkeypatch.setattr(mod, "get_user_repository", lambda: repo, raising=True)

    # Auth dependency
    if user_ctx is None:
        user_ctx = {"id": "u-123", "email": "user@example.com"}
    async def _fake_current_user():
        return user_ctx
    # In me.py, get_current_user is already a dependency fn; replace it.
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
    return "/api/v1/me"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_get_me_happy_path_no_store_and_email_enrichment(monkeypatch):
    # Repo omits email → route should enrich from authenticated user
    repo = FakeUserRepo(profile={"id": "u-123", "display_name": "Ada"})
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    r = client.get(_url())
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == "u-123"
    assert body["display_name"] == "Ada"
    assert body["email"] == "user@example.com"  # enriched from user ctx

    # no-store cache headers
    assert r.headers.get("Cache-Control") == "no-store"
    assert r.headers.get("Pragma") == "no-cache"
    assert r.headers.get("Expires") == "0"

    # repo was called with authed user id
    assert repo.calls == 1 and repo.last_user_id == "u-123"


def test_get_me_does_not_overwrite_existing_email(monkeypatch):
    repo = FakeUserRepo(profile={"id": "u-123", "email": "repo@example.com"})
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, user_ctx={"id": "u-123", "email": "user@should-not-win"})
    r = client.get(_url())
    assert r.status_code == 200
    assert r.json()["email"] == "repo@example.com"  # unchanged


def test_get_me_unauthorized_when_auth_dependency_raises(monkeypatch):
    repo = FakeUserRepo(profile={"id": "u-zzz"})
    mod = importlib.import_module("app.api.v1.routers.user.me")

    # Build app first, then replace get_current_user with one that raises
    _app, client, mod2, _ = _mk_app(monkeypatch, repo=repo, user_ctx={"id": "u-zzz"})
    assert mod2 is mod  # ensure same module

    async def _raise_unauth():
        raise HTTPException(status_code=401, detail="Unauthorized")
    monkeypatch.setattr(mod, "get_current_user", _raise_unauth, raising=True)

    r = client.get(_url())
    assert r.status_code == 401


def test_get_me_api_key_enforcement_plain(monkeypatch):
    key = "sekret123"
    repo = FakeUserRepo(profile={"id": "u-123"})
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=False)

    r1 = client.get(_url())
    assert r1.status_code == 401  # missing API key

    r2 = client.get(_url(), headers={"X-API-Key": key})
    assert r2.status_code == 200

    r3 = client.get(_url() + f"?api_key={key}")
    assert r3.status_code == 200


def test_get_me_api_key_enforcement_hashed(monkeypatch):
    key = "super-secret"
    repo = FakeUserRepo(profile={"id": "u-123"})
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=True)

    r1 = client.get(_url())
    assert r1.status_code == 401

    r2 = client.get(_url(), headers={"X-API-Key": key})
    assert r2.status_code == 200


def test_get_me_logs_action(monkeypatch):
    repo = FakeUserRepo(profile={"id": "u-123"})
    _app, client, _mod, log_calls = _mk_app(monkeypatch, repo=repo, record_log=True)

    r = client.get(_url())
    assert r.status_code == 200
    # ensure _log_user_action was invoked with PROFILE_GET
    assert any(call["action"] == "PROFILE_GET" and call["user_id"] == "u-123" for call in log_calls)


def test_get_me_repo_exception_yields_500(monkeypatch):
    repo = FakeUserRepo(raise_exc=True)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    r = client.get(_url())
    # Unhandled repo exception should surface as 500
    assert r.status_code == 500
