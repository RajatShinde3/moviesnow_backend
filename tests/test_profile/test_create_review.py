# tests/test_user/test_create_review.py

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
        self.last_content = None
        self.last_rating = None

    def create_review(self, user_id: str, title_id: str, content: str, rating):
        self.calls += 1
        self.last_user_id = user_id
        self.last_tid = title_id
        self.last_content = content
        self.last_rating = rating
        if self.raise_exc:
            raise RuntimeError("boom")
        # Echo back a plausible review payload
        return {
            "id": "rev-1",
            "user_id": user_id,
            "title_id": title_id,
            "content": content,
            "rating": rating,
            "created_at": 1_700_000_000,
        }


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
      - sanitize_title_id -> passthrough (tests may override)
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

    # sanitize passthrough (tests may override)
    if sanitize_passthrough:
        monkeypatch.setattr(mod, "sanitize_title_id", lambda raw: raw, raising=True)

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
    return "/api/v1/reviews"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_create_review_happy_path_201_location_no_store_and_logging(monkeypatch):
    repo = FakeUserRepo()
    _app, client, _mod, log_calls = _mk_app(monkeypatch, repo=repo, record_log=True)

    payload = {"title_id": "tt123", "content": "Great movie!", "rating": 8}
    r = client.post(_url(), json=payload)
    assert r.status_code == 201

    body = r.json()
    assert body["id"] == "rev-1"
    assert body["user_id"] == "u-123"
    assert body["title_id"] == "tt123"
    assert body["content"] == "Great movie!"
    assert body["rating"] == 8
    assert isinstance(body["created_at"], int)

    # Location header points to /me/reviews?title_id=...
    assert r.headers.get("Location") == "/api/v1/me/reviews?title_id=tt123" or r.headers.get("Location") == "/me/reviews?title_id=tt123"

    # repo was called with authed user id and forwarded args
    assert repo.calls == 1
    assert repo.last_user_id == "u-123"
    assert repo.last_tid == "tt123"
    assert repo.last_content == "Great movie!"
    assert repo.last_rating == 8

    # logging
    assert any(
        call["action"] == "REVIEW_CREATE"
        and call["user_id"] == "u-123"
        and call["meta"].get("title_id") == "tt123"
        and call["meta"].get("has_rating") is True
        and call["meta"].get("review_id") == "rev-1"
        for call in log_calls
    )

    # no-store style caching headers (allow either exact or with max-age=0)
    cc = r.headers.get("Cache-Control", "")
    assert "no-store" in cc
    assert r.headers.get("Pragma") == "no-cache"


def test_create_review_without_rating_logs_has_rating_false(monkeypatch):
    repo = FakeUserRepo()
    _app, client, _mod, log_calls = _mk_app(monkeypatch, repo=repo, record_log=True)

    payload = {"title_id": "tt9", "content": "ok"}
    # content must be >= 3 chars; use 3 exactly
    payload["content"] = "ok!"
    r = client.post(_url(), json=payload)
    assert r.status_code == 201

    assert repo.last_rating is None
    assert any(
        call["action"] == "REVIEW_CREATE"
        and call["meta"].get("has_rating") is False
        for call in log_calls
    )


def test_create_review_applies_sanitize_and_forwards(monkeypatch):
    repo = FakeUserRepo()
    _app, client, mod, _ = _mk_app(
        monkeypatch, repo=repo, sanitize_passthrough=False
    )
    # Sanitize to a sentinel
    monkeypatch.setattr(mod, "sanitize_title_id", lambda raw: "SANITIZED", raising=True)

    payload = {"title_id": "WeIRD-slug_123", "content": "Loved it", "rating": 9.5}
    r = client.post(_url(), json=payload)
    assert r.status_code == 201
    assert repo.last_tid == "SANITIZED"
    # Location header uses sanitized id
    assert r.headers.get("Location") in ("/me/reviews?title_id=SANITIZED", "/api/v1/me/reviews?title_id=SANITIZED")


def test_create_review_validation_errors_422(monkeypatch):
    repo = FakeUserRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    # Body required
    assert client.post(_url()).status_code == 422

    # Missing title_id
    assert client.post(_url(), json={"content": "Nice!"}).status_code == 422

    # Missing content
    assert client.post(_url(), json={"title_id": "tt1"}).status_code == 422

    # content too short (<3)
    assert client.post(_url(), json={"title_id": "tt1", "content": "ab"}).status_code == 422

    # rating wrong type
    assert client.post(_url(), json={"title_id": "tt1", "content": "ok!", "rating": "nope"}).status_code == 422

    # rating out of range
    assert client.post(_url(), json={"title_id": "tt1", "content": "ok!", "rating": -1}).status_code == 422
    assert client.post(_url(), json={"title_id": "tt1", "content": "ok!", "rating": 10.5}).status_code == 422


def test_create_review_repo_exception_yields_500(monkeypatch):
    repo = FakeUserRepo(raise_exc=True)
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo)

    r = client.post(_url(), json={"title_id": "ttZ", "content": "meh"})
    assert r.status_code == 500


def test_create_review_auth_dependency_unauthorized(monkeypatch):
    repo = FakeUserRepo()
    _app, client, mod, _ = _mk_app(monkeypatch, repo=repo)

    async def _raise_unauth():
        raise HTTPException(status_code=401, detail="Unauthorized")
    monkeypatch.setattr(mod, "get_current_user", _raise_unauth, raising=True)

    r = client.post(_url(), json={"title_id": "tt1", "content": "ok!"})
    assert r.status_code == 401
    assert repo.calls == 0


def test_create_review_api_key_enforcement_plain(monkeypatch):
    key = "sekret123"
    repo = FakeUserRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=False)

    r1 = client.post(_url(), json={"title_id": "tt1", "content": "ok!"})
    assert r1.status_code == 401

    r2 = client.post(_url(), json={"title_id": "tt1", "content": "ok!"}, headers={"X-API-Key": key})
    assert r2.status_code == 201

    r3 = client.post(_url() + f"?api_key={key}", json={"title_id": "tt1", "content": "ok!"})
    assert r3.status_code == 201


def test_create_review_api_key_enforcement_hashed(monkeypatch):
    key = "super-secret"
    repo = FakeUserRepo()
    _app, client, _mod, _ = _mk_app(monkeypatch, repo=repo, enforce_key=key, hashed=True)

    r1 = client.post(_url(), json={"title_id": "tt1", "content": "ok!"})
    assert r1.status_code == 401

    r2 = client.post(_url(), json={"title_id": "tt1", "content": "ok!"}, headers={"X-API-Key": key})
    assert r2.status_code == 201
