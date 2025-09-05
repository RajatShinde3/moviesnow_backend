# tests/test_public/test_discovery/test_similar_titles.py

import importlib
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────

class FakeRepo:
    def __init__(self, *, items=None, raise_exc=False):
        self.items = items if items is not None else []
        self.raise_exc = raise_exc
        self.called = False
        self.last_tid = None

    def get_similar(self, tid):
        self.called = True
        self.last_tid = tid
        if self.raise_exc:
            raise RuntimeError("boom")
        return self.items


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


def _url(tid: str) -> str:
    return f"/api/v1/similar/{tid}"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_similar_titles_happy_path_from_repo(monkeypatch):
    items = [
        {"id": "tt1", "name": "Toy Story"},
        {"id": "tt2", "name": "A Bug's Life"},
    ]
    repo = FakeRepo(items=items)
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo)

    r = client.get(_url("toy-story"))
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list) and len(body) == 2
    # Spot-check core fields; response_model may filter/augment other fields
    assert body[0]["id"] == "tt1" and body[0]["name"] == "Toy Story"
    assert repo.called is True and repo.last_tid == "toy-story"

    # This route doesn't set caching headers
    assert r.headers.get("ETag") is None
    assert r.headers.get("Cache-Control") is None
    assert r.headers.get("Vary") is None


def test_similar_titles_accepts_existing_model_instances(monkeypatch):
    # Build model instances using the real TitleSummary from the module
    mod = importlib.import_module("app.api.v1.routers.public.discovery")
    inst1 = mod.TitleSummary(id="tt1", name="Toy Story")
    inst2 = mod.TitleSummary(id="tt2", name="Toy Story 2")
    repo = FakeRepo(items=[inst1, inst2])
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo)

    r = client.get(_url("tt123"))
    assert r.status_code == 200
    body = r.json()
    # Only assert stable core fields to avoid overfitting the schema
    assert body[0]["id"] == "tt1" and body[0]["name"] == "Toy Story"
    assert body[1]["id"] == "tt2" and body[1]["name"] == "Toy Story 2"


def test_similar_titles_missing_repo_returns_empty_list(monkeypatch):
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: None)
    r = client.get(_url("anything"))
    assert r.status_code == 200
    assert r.json() == []


def test_similar_titles_missing_method_returns_empty_list(monkeypatch):
    # Provide an object without get_similar()
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: object())
    r = client.get(_url("anything"))
    assert r.status_code == 200
    assert r.json() == []


def test_similar_titles_repo_exception_returns_500(monkeypatch):
    repo = FakeRepo(raise_exc=True)
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo)
    r = client.get(_url("oops"))
    assert r.status_code == 500
    assert r.json()["detail"] == "Failed to fetch similar titles"


def test_similar_titles_enforces_public_api_key_plain(monkeypatch):
    key = "sekret123"
    repo = FakeRepo(items=[{"id": "tt1", "name": "X"}])
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo, enforce_key=key, hashed=False)

    r1 = client.get(_url("tt"))
    assert r1.status_code == 401

    r2 = client.get(_url("tt"), headers={"X-API-Key": key})
    assert r2.status_code == 200

    r3 = client.get(_url("tt") + f"?api_key={key}")
    assert r3.status_code == 200


def test_similar_titles_enforces_public_api_key_hashed(monkeypatch):
    key = "super-secret"
    repo = FakeRepo(items=[{"id": "tt1", "name": "X"}])
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo, enforce_key=key, hashed=True)

    r1 = client.get(_url("tt"))
    assert r1.status_code == 401

    r2 = client.get(_url("tt"), headers={"X-API-Key": key})
    assert r2.status_code == 200


def test_similar_titles_applies_sanitize_title_id(monkeypatch):
    repo = FakeRepo(items=[])
    _app, client, mod = _mk_app(
        monkeypatch,
        repo_provider=lambda: repo,
        sanitize_passthrough=False,
    )
    # Force sanitize to return a sentinel so we can assert it was forwarded
    monkeypatch.setattr(mod, "sanitize_title_id", lambda raw: "SANITIZED", raising=True)

    r = client.get(_url("WeIRD-slug_123"))
    assert r.status_code == 200
    assert repo.last_tid == "SANITIZED"
