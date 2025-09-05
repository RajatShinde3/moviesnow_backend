# tests/test_user/test_remove_favorite.py

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

    def remove_favorite(self, user_id: str, title_id: str):
        self.calls += 1
        self.last_user_id = user_id
        self.last_tid = title_id
        if self.raise_exc:
            raise RuntimeError("boom")


# ─────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    user_repo: FakeUserRepo,
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
      - sanitize_title_id -> passthrough (tests may override)
      - _log_user_action -> recorder (optional)
      - PUBLIC_API_KEY / PUBLIC_API_KEY_SHA256 (optional)
    """
    mod = importlib.import_module("app.api.v1.routers.user.me")

    # no-op rate limiter
    async def _no_rate_limit(*_, **__):
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # repo & auth
    monkeypatch.setattr(mod, "get_user_repository", lambda: user_repo, raising=True)

    if user_ctx is None:
        user_ctx = {"id": "u-123", "email": "user@example.com"}

    async def _fake_current_user():
        return user_ctx

    monkeypatch.setattr(mod, "get_current_user", _fake_current_user, raising=True)

    # sanitize passthrough (tests may override)
    if sanitize_passthrough:
        monkeypatch.setattr(mod, "sanitize_title_id", lambda x: x, raising=True)

    # optional log recorder
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


def _url(tid: str):
    return f"/api/v1/favorites/{tid}"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_remove_favorite_happy_path_persists_and_logs(monkeypatch):
    user_repo = FakeUserRepo()
    _app, client, _mod, log_calls = _mk_app(monkeypatch, user_repo=user_repo, record_log=True)

    r = client.delete(_url("tt123"))
    assert r.status_code == 204
    assert r.text == ""  # empty body

    # repo called with authed user and tid
    assert user_repo.calls == 1
    assert user_repo.last_user_id == "u-123"
    assert user_repo.last_tid == "tt123"

    # logged
    assert any(
        c["action"] == "FAVORITES_REMOVE"
        and c["user_id"] == "u-123"
        and c["meta"].get("title_id") == "tt123"
        for c in log_calls
    )


def test_remove_favorite_applies_sanitize_and_forwards(monkeypatch):
    user_repo = FakeUserRepo()
    _app, client, mod, _ = _mk_app(
        monkeypatch, user_repo=user_repo, sanitize_passthrough=False
    )
    # sanitize to sentinel
    monkeypatch.setattr(mod, "sanitize_title_id", lambda raw: "SANITIZED", raising=True)

    r = client.delete(_url("WeIRD-slug_123"))
    assert r.status_code == 204
    assert user_repo.last_tid == "SANITIZED"


def test_remove_favorite_user_repo_exception_returns_500(monkeypatch):
    user_repo = FakeUserRepo(raise_exc=True)
    _app, client, _mod, _ = _mk_app(monkeypatch, user_repo=user_repo)

    r = client.delete(_url("ttZ"))
    assert r.status_code == 500


def test_remove_favorite_auth_dependency_unauthorized(monkeypatch):
    user_repo = FakeUserRepo()
    _app, client, mod, _ = _mk_app(monkeypatch, user_repo=user_repo)

    async def _raise_unauth():
        raise HTTPException(status_code=401, detail="Unauthorized")
    monkeypatch.setattr(mod, "get_current_user", _raise_unauth, raising=True)

    r = client.delete(_url("tt1"))
    assert r.status_code == 401
    assert user_repo.calls == 0


def test_remove_favorite_api_key_enforcement_plain(monkeypatch):
    key = "sekret123"
    user_repo = FakeUserRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, user_repo=user_repo, enforce_key=key, hashed=False)

    r1 = client.delete(_url("tt1"))
    assert r1.status_code == 401

    r2 = client.delete(_url("tt1"), headers={"X-API-Key": key})
    assert r2.status_code == 204

    r3 = client.delete(_url("tt1") + f"?api_key={key}")
    assert r3.status_code == 204


def test_remove_favorite_api_key_enforcement_hashed(monkeypatch):
    key = "super-secret"
    user_repo = FakeUserRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, user_repo=user_repo, enforce_key=key, hashed=True)

    r1 = client.delete(_url("tt1"))
    assert r1.status_code == 401

    r2 = client.delete(_url("tt1"), headers={"X-API-Key": key})
    assert r2.status_code == 204
