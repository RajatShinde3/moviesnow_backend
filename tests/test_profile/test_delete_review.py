# tests/test_user/test_delete_review_route.py

import importlib
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────

class FakeUserRepo:
    def __init__(self, *, returns_ok=True, raise_exc=False):
        self.returns_ok = returns_ok
        self.raise_exc = raise_exc
        self.calls = 0
        self.last_user_id = None
        self.last_review_id = None

    def delete_review(self, user_id: str, review_id: str):
        self.calls += 1
        self.last_user_id = user_id
        self.last_review_id = review_id
        if self.raise_exc:
            raise RuntimeError("boom")
        return bool(self.returns_ok)


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


def _url(review_id: str):
    return f"/api/v1/reviews/{review_id}"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_delete_review_happy_path_204_and_logs(monkeypatch):
    repo = FakeUserRepo(returns_ok=True)
    _app, client, _mod, log_calls = _mk_app(monkeypatch, repo=repo, record_log=True)

    r = client.delete(_url("rev-123"))
    assert r.status_code == 204
    assert r.text == ""  # empty body

    # repo received correct args
    assert repo.calls == 1
    assert repo.last_user_id == "u-123"
    assert repo.last_review_id == "rev-123"

    # logged
    assert any(
        c["action"] == "REVIEW_DELETE"
        and c["user_id"] == "u-123"
        and c["meta"].get("review_id") == "rev-123"
        and c["meta"].get("deleted") is True
        for c in log_calls
    )

    # 204 responses normally have no cache headers
    assert r.headers.get("Cache-Control") is None


def test_delete_review_not_found_returns_404_and_no_log(monkeypatch):
    repo = FakeUserRepo(returns_ok=False)
    _app, client, _mod, log_calls = _mk_app(monkeypatch, repo=repo, record_log=True)

    r = client.delete(_url("rev-missing"))
    assert r.status_code == 404
    assert r.json()["detail"] == "Review not found or not owned"

    assert repo.calls == 1
    assert repo.last_review_id == "rev-missing"
    # route logs only on success
    assert len(log_calls) == 0


def test_delete_review_repo_exception_yields_500(monkeypatch):
    repo = FakeUserRepo(raise_exc=True)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    r = client.delete(_url("rev-err"))
    assert r.status_code == 500


def test_delete_review_auth_dependency_unauthorized(monkeypatch):
    repo = FakeUserRepo()
    _app, client, mod, _ = _mk_app(monkeypatch, repo=repo)

    async def _raise_unauth():
        raise HTTPException(status_code=401, detail="Unauthorized")
    monkeypatch.setattr(mod, "get_current_user", _raise_unauth, raising=True)

    r = client.delete(_url("rev-1"))
    assert r.status_code == 401
    assert repo.calls == 0


def test_delete_review_api_key_enforcement_plain(monkeypatch):
    key = "sekret123"
    repo = FakeUserRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=False)

    r1 = client.delete(_url("rev-1"))
    assert r1.status_code == 401

    r2 = client.delete(_url("rev-1"), headers={"X-API-Key": key})
    assert r2.status_code == 204

    r3 = client.delete(_url("rev-1") + f"?api_key={key}")
    assert r3.status_code == 204


def test_delete_review_api_key_enforcement_hashed(monkeypatch):
    key = "super-secret"
    repo = FakeUserRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=True)

    r1 = client.delete(_url("rev-1"))
    assert r1.status_code == 401

    r2 = client.delete(_url("rev-1"), headers={"X-API-Key": key})
    assert r2.status_code == 204
