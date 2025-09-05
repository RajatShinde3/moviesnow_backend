# tests/test_public/test_discovery/test_get_download_url.py

import importlib
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes & helpers
# ─────────────────────────────────────────────────────────────

class FakeRepo:
    def __init__(self, *, raise_exc=False):
        self.raise_exc = raise_exc
        self.last_tid = None

    def get_download_resource_path(self, tid):
        self.last_tid = tid
        if self.raise_exc:
            raise RuntimeError("boom")
        # pretend origin path provided by repo
        return f"origin/{tid}/package.zip"


class SignerRecorder:
    def __init__(self):
        self.calls = []

    def __call__(self, *, resource_path, quality, expires_in, purpose):
        self.calls.append(
            {
                "resource_path": resource_path,
                "quality": quality,
                "expires_in": expires_in,
                "purpose": purpose,
            }
        )
        qstr = getattr(quality, "value", str(quality))
        class _DummySigned:
            def __init__(self, url):
                self._data = {"url": url}
            def dict(self):
                return dict(self._data)
        return _DummySigned(url=f"https://signed.test/{resource_path}/{qstr}?e={expires_in}&p={purpose}")


def _mk_app(
    monkeypatch,
    *,
    repo_provider,
    enforce_key=None,
    hashed=False,
    sanitize_passthrough=True,
    signer=None,
):
    """
    Mount the public discovery router at /api/v1 and override:
      - rate_limit -> no-op
      - get_titles_repository -> repo_provider() return
      - generate_signed_url -> signer (recorder)
      - optional sanitize passthrough
      - optional PUBLIC_API_KEY / PUBLIC_API_KEY_SHA256
    """
    mod = importlib.import_module("app.api.v1.routers.public.discovery")

    # no-op rate limiter
    async def _no_rate_limit(*_, **__):
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # repo provider
    monkeypatch.setattr(mod, "get_titles_repository", repo_provider, raising=True)

    # signer
    if signer is None:
        signer = SignerRecorder()
    monkeypatch.setattr(mod, "generate_signed_url", lambda **kw: signer(**kw), raising=True)

    # sanitize passthrough
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
    return app, client, mod, signer


def _url(tid: str, quality: str, **params):
    base = f"/api/v1/download/{tid}/{quality}"
    if not params:
        return base
    from urllib.parse import urlencode
    return f"{base}?{urlencode(params)}"


# ─────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────

def test_download_url_happy_path_uses_repo_path_and_no_store_headers(monkeypatch):
    repo = FakeRepo()
    signer = SignerRecorder()
    _app, client, mod, signer = _mk_app(
        monkeypatch, repo_provider=lambda: repo, signer=signer
    )

    r = client.get(_url("toy-story", "1080p", expires_in=3600))
    assert r.status_code == 200
    body = r.json()
    assert "url" in body and body["url"].startswith("https://signed.test/")

    # signer captured expected args
    assert len(signer.calls) == 1
    call = signer.calls[0]
    assert call["resource_path"] == "origin/toy-story/package.zip"
    assert getattr(call["quality"], "value", str(call["quality"])) == "1080p"
    assert call["expires_in"] == 3600
    assert call["purpose"] == "download"

    # no-store caching headers
    assert r.headers.get("Cache-Control") == "no-store"
    assert r.headers.get("Pragma") == "no-cache"
    assert r.headers.get("Expires") == "0"


def test_download_url_defaults_to_fallback_resource_path_when_method_missing(monkeypatch):
    signer = SignerRecorder()
    # object() has no get_download_resource_path
    _app, client, mod, signer = _mk_app(
        monkeypatch, repo_provider=lambda: object(), signer=signer
    )
    r = client.get(_url("tt123", "720p", expires_in=1200))
    assert r.status_code == 200
    call = signer.calls[0]
    assert call["resource_path"] == "download/tt123"  # fallback path
    assert getattr(call["quality"], "value", str(call["quality"])) == "720p"
    assert call["expires_in"] == 1200
    assert call["purpose"] == "download"


def test_download_url_falls_back_when_repo_raises(monkeypatch):
    repo = FakeRepo(raise_exc=True)
    signer = SignerRecorder()
    _app, client, mod, signer = _mk_app(
        monkeypatch, repo_provider=lambda: repo, signer=signer
    )
    r = client.get(_url("slug", "480p"))
    assert r.status_code == 200
    call = signer.calls[0]
    assert call["resource_path"] == "download/slug"  # fallback on exception
    assert getattr(call["quality"], "value", str(call["quality"])) == "480p"
    assert call["purpose"] == "download"


def test_download_url_quality_validation_400_for_unsupported(monkeypatch):
    repo = FakeRepo()
    signer = SignerRecorder()
    _app, client, mod, signer = _mk_app(
        monkeypatch, repo_provider=lambda: repo, signer=signer
    )
    # QualityEnum may include 2160p; route restricts to {480p,720p,1080p} and should raise 400
    r = client.get(_url("slug", "2160p"))
    assert r.status_code == 400
    assert r.json()["detail"] == "Unsupported quality; allowed: 480p, 720p, 1080p"
    assert len(signer.calls) == 0  # signer not called


def test_download_url_expires_in_query_bounds_422(monkeypatch):
    repo = FakeRepo()
    signer = SignerRecorder()
    _app, client, mod, signer = _mk_app(
        monkeypatch, repo_provider=lambda: repo, signer=signer
    )
    assert client.get(_url("slug", "720p", expires_in=59)).status_code == 422
    assert client.get(_url("slug", "720p", expires_in=86401)).status_code == 422


def test_download_url_enforces_public_api_key_plain(monkeypatch):
    key = "sekret123"
    repo = FakeRepo()
    signer = SignerRecorder()
    _app, client, mod, signer = _mk_app(
        monkeypatch, repo_provider=lambda: repo, enforce_key=key, hashed=False, signer=signer
    )

    r1 = client.get(_url("slug", "480p"))
    assert r1.status_code == 401

    r2 = client.get(_url("slug", "480p"), headers={"X-API-Key": key})
    assert r2.status_code == 200

    r3 = client.get(_url("slug", "480p") + f"?api_key={key}")
    assert r3.status_code == 200


def test_download_url_enforces_public_api_key_hashed(monkeypatch):
    key = "super-secret"
    repo = FakeRepo()
    signer = SignerRecorder()
    _app, client, mod, signer = _mk_app(
        monkeypatch, repo_provider=lambda: repo, enforce_key=key, hashed=True, signer=signer
    )

    r1 = client.get(_url("slug", "1080p"))
    assert r1.status_code == 401

    r2 = client.get(_url("slug", "1080p"), headers={"X-API-Key": key})
    assert r2.status_code == 200


def test_download_url_applies_sanitize_title_id(monkeypatch):
    repo = FakeRepo()
    signer = SignerRecorder()
    _app, client, mod, signer = _mk_app(
        monkeypatch,
        repo_provider=lambda: repo,
        signer=signer,
        sanitize_passthrough=False,
    )
    # Force sanitize to return a sentinel value; repo should see it
    monkeypatch.setattr(mod, "sanitize_title_id", lambda raw: "SANITIZED", raising=True)

    r = client.get(_url("WeIRD-slug_123", "720p"))
    assert r.status_code == 200
    assert repo.last_tid == "SANITIZED"
    # signer should have used repo's path derived from sanitized tid
    assert signer.calls[0]["resource_path"] == "origin/SANITIZED/package.zip"
    assert signer.calls[0]["purpose"] == "download"


def test_download_url_signer_exception_returns_500(monkeypatch):
    repo = FakeRepo()

    def exploding_signer(**_):
        raise RuntimeError("signing failed")

    _app, client, mod, _ = _mk_app(
        monkeypatch, repo_provider=lambda: repo, signer=exploding_signer
    )
    r = client.get(_url("slug", "720p"))
    # Unhandled exception → 500 Internal Server Error
    assert r.status_code == 500
