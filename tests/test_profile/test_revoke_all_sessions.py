# tests/test_user/test_revoke_all_sessions.py

import importlib
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────

class FakeUserRepo:
    def __init__(self, *, revoked=0, raise_exc=False):
        self.revoked = revoked
        self.raise_exc = raise_exc
        self.calls = 0
        self.last_user_id = None

    def revoke_all_sessions(self, user_id: str):
        self.calls += 1
        self.last_user_id = user_id
        if self.raise_exc:
            raise RuntimeError("boom")
        return int(self.revoked)


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
    async def _no_rate_limit(*_, **__): return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # Repo provider
    monkeypatch.setattr(mod, "get_user_repository", lambda: repo, raising=True)

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
    return "/api/v1/sessions/revoke-all"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_revoke_all_sessions_happy_path_no_store_and_logging(monkeypatch):
    repo = FakeUserRepo(revoked=7)
    _app, client, _mod, log_calls = _mk_app(monkeypatch, repo=repo, record_log=True)

    r = client.post(_url())
    assert r.status_code == 202
    assert r.json() == {"revoked": 7}

    # Repo received user id
    assert repo.calls == 1
    assert repo.last_user_id == "u-123"

    # no-store headers
    assert r.headers.get("Cache-Control") == "no-store"
    assert r.headers.get("Pragma") == "no-cache"
    assert r.headers.get("Expires") == "0"

    # Logged with metadata
    assert any(
        c["action"] == "SESSIONS_REVOKE_ALL"
        and c["user_id"] == "u-123"
        and c["meta"].get("revoked") == 7
        for c in log_calls
    )


def test_revoke_all_sessions_auth_dependency_unauthorized(monkeypatch):
    repo = FakeUserRepo(revoked=0)
    _app, client, mod, _ = _mk_app(monkeypatch, repo=repo)

    async def _raise_unauth():
        raise HTTPException(status_code=401, detail="Unauthorized")
    monkeypatch.setattr(mod, "get_current_user", _raise_unauth, raising=True)

    r = client.post(_url())
    assert r.status_code == 401
    assert repo.calls == 0


def test_revoke_all_sessions_repo_exception_yields_500(monkeypatch):
    repo = FakeUserRepo(raise_exc=True)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    r = client.post(_url())
    assert r.status_code == 500


def test_revoke_all_sessions_api_key_enforcement_plain(monkeypatch):
    key = "sekret123"
    repo = FakeUserRepo(revoked=3)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=False)

    r1 = client.post(_url())
    assert r1.status_code == 401

    r2 = client.post(_url(), headers={"X-API-Key": key})
    assert r2.status_code == 202 and r2.json() == {"revoked": 3}

    r3 = client.post(_url() + f"?api_key={key}")
    assert r3.status_code == 202 and r3.json() == {"revoked": 3}


def test_revoke_all_sessions_api_key_enforcement_hashed(monkeypatch):
    key = "super-secret"
    repo = FakeUserRepo(revoked=1)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=True)

    r1 = client.post(_url())
    assert r1.status_code == 401

    r2 = client.post(_url(), headers={"X-API-Key": key})
    assert r2.status_code == 202 and r2.json() == {"revoked": 1}
