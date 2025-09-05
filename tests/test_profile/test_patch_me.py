# tests/test_user/test_patch_me.py

import importlib
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────

class FakeUserRepo:
    def __init__(self, *, updated_return=None, raise_exc=False):
        self.updated_return = updated_return
        self.raise_exc = raise_exc
        self.calls = 0
        self.last_user_id = None
        self.last_changes = None

    def update_profile(self, user_id: str, changes: dict):
        self.calls += 1
        self.last_user_id = user_id
        self.last_changes = dict(changes)
        if self.raise_exc:
            raise RuntimeError("boom")
        # Default: echo back an "updated" snapshot
        if self.updated_return is not None:
            return dict(self.updated_return)
        snap = {"id": user_id}
        snap.update(changes)
        return snap


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

def test_patch_me_happy_path_persists_and_no_store_headers(monkeypatch):
    repo = FakeUserRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    payload = {"display_name": "Ada Lovelace"}
    r = client.patch(_url(), json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == "u-123"
    assert body["display_name"] == "Ada Lovelace"

    # Repo called with current user id and exact changes (exclude_unset)
    assert repo.calls == 1
    assert repo.last_user_id == "u-123"
    assert repo.last_changes == payload

    # no-store cache headers
    assert r.headers.get("Cache-Control") == "no-store"
    assert r.headers.get("Pragma") == "no-cache"
    assert r.headers.get("Expires") == "0"


def test_patch_me_multiple_fields_and_logs_fields(monkeypatch):
    repo = FakeUserRepo()
    _app, client, mod, log_calls = _mk_app(monkeypatch, repo=repo, record_log=True)

    changes = {"display_name": "Neo", "bio": "I know kung fu."}
    r = client.patch(_url(), json=changes)
    assert r.status_code == 200

    # log called with PROFILE_PATCH and correct field set
    assert any(
        call["action"] == "PROFILE_PATCH"
        and call["user_id"] == "u-123"
        and set(call["meta"].get("fields", [])) == set(changes.keys())
        for call in log_calls
    )


def test_patch_me_does_not_allow_empty_body_returns_400(monkeypatch):
    repo = FakeUserRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    r = client.patch(_url(), json={})
    assert r.status_code == 400
    assert r.json()["detail"] == "No changes provided"


def test_patch_me_missing_body_returns_422(monkeypatch):
    repo = FakeUserRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    r = client.patch(_url())
    assert r.status_code == 422  # body is required


def test_patch_me_validation_errors_422(monkeypatch):
    # display_name has min_length=1; empty string should raise 422
    repo = FakeUserRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    r = client.patch(_url(), json={"display_name": ""})
    assert r.status_code == 422


def test_patch_me_repo_exception_yields_500(monkeypatch):
    repo = FakeUserRepo(raise_exc=True)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    r = client.patch(_url(), json={"bio": "Hello"})
    assert r.status_code == 500


def test_patch_me_api_key_enforcement_plain(monkeypatch):
    key = "sekret123"
    repo = FakeUserRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=False)

    r1 = client.patch(_url(), json={"bio": "x"})
    assert r1.status_code == 401  # missing API key

    r2 = client.patch(_url(), json={"bio": "x"}, headers={"X-API-Key": key})
    assert r2.status_code == 200

    r3 = client.patch(_url() + f"?api_key={key}", json={"bio": "x"})
    assert r3.status_code == 200


def test_patch_me_api_key_enforcement_hashed(monkeypatch):
    key = "super-secret"
    repo = FakeUserRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=True)

    r1 = client.patch(_url(), json={"bio": "x"})
    assert r1.status_code == 401

    r2 = client.patch(_url(), json={"bio": "x"}, headers={"X-API-Key": key})
    assert r2.status_code == 200


def test_patch_me_unauthorized_when_auth_dependency_raises(monkeypatch):
    repo = FakeUserRepo()
    _app, client, mod, _ = _mk_app(monkeypatch, repo=repo)

    async def _raise_unauth():
        raise HTTPException(status_code=401, detail="Unauthorized")
    monkeypatch.setattr(mod, "get_current_user", _raise_unauth, raising=True)

    r = client.patch(_url(), json={"bio": "x"})
    assert r.status_code == 401
