# tests/test_public/test_discovery/test_list_genres.py

import importlib
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────

class FakeRepo:
    def __init__(self, *, genres=None, raise_exc=False):
        self.genres = genres if genres is not None else []
        self.raise_exc = raise_exc
        self.called = False

    def list_genres(self):
        self.called = True
        if self.raise_exc:
            raise RuntimeError("boom")
        return self.genres


# ─────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    repo_provider,
    enforce_key=None,
    hashed=False,
):
    """
    Build an app mounting the public discovery router at /api/v1:
      - rate_limit -> no-op
      - get_titles_repository -> repo_provider() return
      - optional PUBLIC_API_KEY / PUBLIC_API_KEY_SHA256
    """
    mod = importlib.import_module("app.api.v1.routers.public.discovery")

    # no-op rate limiter
    async def _no_rate_limit(*_, **__):
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # repo provider override
    monkeypatch.setattr(mod, "get_titles_repository", repo_provider, raising=True)

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


def _url():
    return "/api/v1/genres"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_list_genres_happy_path_from_repo(monkeypatch):
    repo = FakeRepo(genres=["Action", "Comedy", "Drama"])
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo)

    r = client.get(_url())
    assert r.status_code == 200
    assert r.json() == ["Action", "Comedy", "Drama"]
    assert repo.called is True


def test_list_genres_coerces_values_to_str(monkeypatch):
    class GenreLike:
        def __str__(self):
            return "Mystery"
    repo = FakeRepo(genres=[1, 2, GenreLike()])
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo)

    r = client.get(_url())
    assert r.status_code == 200
    assert r.json() == ["1", "2", "Mystery"]


def test_list_genres_repo_exception_returns_500(monkeypatch):
    repo = FakeRepo(raise_exc=True)
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo)

    r = client.get(_url())
    assert r.status_code == 500
    assert r.json()["detail"] == "Failed to fetch genres"


def test_list_genres_falls_back_when_no_repo(monkeypatch):
    # get_titles_repository() -> None triggers the fallback static list
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: None)

    r = client.get(_url())
    assert r.status_code == 200
    assert r.json() == [
        "Action",
        "Adventure",
        "Comedy",
        "Drama",
        "Horror",
        "Romance",
        "Sci-Fi",
        "Thriller",
        "Animation",
        "Documentary",
    ]


def test_list_genres_falls_back_when_method_missing(monkeypatch):
    # Provide an object without list_genres()
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: object())

    r = client.get(_url())
    assert r.status_code == 200
    assert "Action" in r.json() and "Documentary" in r.json()


def test_list_genres_enforces_public_api_key_plain(monkeypatch):
    key = "sekret123"
    repo = FakeRepo(genres=["Action"])
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo, enforce_key=key, hashed=False)

    r1 = client.get(_url())
    assert r1.status_code == 401

    r2 = client.get(_url(), headers={"X-API-Key": key})
    assert r2.status_code == 200
    assert r2.json() == ["Action"]

    r3 = client.get(_url() + f"?api_key={key}")
    assert r3.status_code == 200


def test_list_genres_enforces_public_api_key_hashed(monkeypatch):
    key = "super-secret"
    repo = FakeRepo(genres=["Comedy"])
    _app, client, _ = _mk_app(monkeypatch, repo_provider=lambda: repo, enforce_key=key, hashed=True)

    r1 = client.get(_url())
    assert r1.status_code == 401

    r2 = client.get(_url(), headers={"X-API-Key": key})
    assert r2.status_code == 200
    assert r2.json() == ["Comedy"]
