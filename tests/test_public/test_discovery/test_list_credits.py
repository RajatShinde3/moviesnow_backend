# tests/test_public/test_discovery/test_list_credits.py

import importlib
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────

class FakeRepo:
    def __init__(self, *, credits=None, raise_exc=False):
        self.credits = credits if credits is not None else []
        self.raise_exc = raise_exc
        self.last_tid = None
        self.called = False

    def get_credits(self, tid):
        self.called = True
        self.last_tid = tid
        if self.raise_exc:
            raise RuntimeError("boom")
        return self.credits


# ─────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    repo_provider,
    enforce_key=None,
    hashed=False,
    sanitize_passthrough=True,
):
    """
    Build an app mounting the public discovery router at /api/v1:
      - rate_limit -> no-op
      - get_titles_repository -> repo_provider() return
      - optional PUBLIC_API_KEY / PUBLIC_API_KEY_SHA256
      - optional sanitize passthrough (tests may override)
    """
    mod = importlib.import_module("app.api.v1.routers.public.discovery")

    # no-op rate limiter
    async def _no_rate_limit(*_, **__):
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # repo provider override
    monkeypatch.setattr(mod, "get_titles_repository", repo_provider, raising=True)

    # sanitize passthrough (tests may override to assert forwarding)
    if sanitize_passthrough:
        monkeypatch.setattr(mod, "sanitize_title_id", lambda x: x, raising=True)

    # API key envs
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
    return app, client, mod


def _url(**params):
    base = "/api/v1/credits"
    if not params:
        return base
    from urllib.parse import urlencode
    return f"{base}?{urlencode(params, doseq=True)}"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_credits_happy_path_from_repo(monkeypatch):
    # Provide dicts; route will coerce each to Credit(**)
    credits = [
        {"name": "Tom Hanks", "role": "actor", "character": "Woody", "order": 1},
        {"name": "Tim Allen", "role": "actor", "character": "Buzz Lightyear", "order": 2},
        {"name": "John Lasseter", "role": "director"},
    ]
    repo = FakeRepo(credits=credits)
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo)

    r = client.get(_url(title_id="toy-story"))
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list) and len(body) == 3
    assert body[0]["name"] == "Tom Hanks" and body[0]["role"] == "actor"
    assert repo.called is True
    assert repo.last_tid == "toy-story"

    # This route doesn't set caching headers
    assert r.headers.get("ETag") is None
    assert r.headers.get("Cache-Control") is None
    assert r.headers.get("Vary") is None


def test_credits_accepts_existing_model_instances(monkeypatch):
    # Build real model instances from the module's Credit class
    mod = importlib.import_module("app.api.v1.routers.public.discovery")
    inst1 = mod.Credit(name="Keanu Reeves", role="actor", character="Neo", order=1)
    inst2 = mod.Credit(name="Lana Wachowski", role="director")
    repo = FakeRepo(credits=[inst1, inst2])
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo)

    r = client.get(_url(title_id="the-matrix"))
    assert r.status_code == 200
    assert r.json() == [
        {"name": "Keanu Reeves", "role": "actor", "character": "Neo", "order": 1},
        {"name": "Lana Wachowski", "role": "director", "character": None, "order": None},
    ]


def test_credits_missing_repo_returns_empty_list(monkeypatch):
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: None)
    r = client.get(_url(title_id="anything"))
    assert r.status_code == 200
    assert r.json() == []


def test_credits_missing_method_returns_empty_list(monkeypatch):
    # Provide an object without get_credits()
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: object())
    r = client.get(_url(title_id="anything"))
    assert r.status_code == 200
    assert r.json() == []


def test_credits_repo_exception_returns_500(monkeypatch):
    repo = FakeRepo(raise_exc=True)
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo)
    r = client.get(_url(title_id="oops"))
    assert r.status_code == 500
    assert r.json()["detail"] == "Failed to fetch credits"


def test_credits_enforces_public_api_key_plain(monkeypatch):
    key = "sekret123"
    repo = FakeRepo(credits=[{"name": "A", "role": "actor"}])
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo, enforce_key=key, hashed=False)

    r1 = client.get(_url(title_id="tt"))
    assert r1.status_code == 401

    r2 = client.get(_url(title_id="tt"), headers={"X-API-Key": key})
    assert r2.status_code == 200

    r3 = client.get(_url(title_id="tt", api_key=key))
    assert r3.status_code == 200


def test_credits_enforces_public_api_key_hashed(monkeypatch):
    key = "super-secret"
    repo = FakeRepo(credits=[{"name": "B", "role": "director"}])
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo, enforce_key=key, hashed=True)

    r1 = client.get(_url(title_id="tt"))
    assert r1.status_code == 401

    r2 = client.get(_url(title_id="tt"), headers={"X-API-Key": key})
    assert r2.status_code == 200


def test_credits_applies_sanitize_title_id(monkeypatch):
    repo = FakeRepo(credits=[{"name": "C", "role": "writer"}])
    _app, client, mod = _mk_app(
        monkeypatch,
        repo_provider=lambda: repo,
        sanitize_passthrough=False,
    )
    # Force sanitize to return a sentinel so we can assert forwarding
    monkeypatch.setattr(mod, "sanitize_title_id", lambda raw: "SANITIZED", raising=True)

    r = client.get(_url(title_id="WeIRD-slug_123"))
    assert r.status_code == 200
    assert repo.last_tid == "SANITIZED"


def test_credits_validation_422_when_missing_title_id(monkeypatch):
    repo = FakeRepo(credits=[])
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo)
    r = client.get(_url())  # no title_id query param
    assert r.status_code == 422
