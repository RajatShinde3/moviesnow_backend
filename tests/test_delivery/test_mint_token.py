import importlib
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _mk_app(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.delivery")

    # No-op limiter and admin gate
    async def _no_rate_limit(*_, **__): return None
    async def _ok(*_, **__): return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)
    monkeypatch.setattr(mod, "require_admin", _ok, raising=False)

    # Fake redis wrapper for token storage
    class _Client:
        async def expire(self, *_a, **_k): return True
        async def setex(self, *_a, **_k): return True
    class _Redis:
        client = _Client()
        async def json_set(self, *_a, **_k): return True
    monkeypatch.setattr(mod, "redis_wrapper", _Redis(), raising=False)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")
    return app, TestClient(app)


def test_mint_token_happy(monkeypatch):
    app, client = _mk_app(monkeypatch)
    payload = {"storage_key": "downloads/tt1/file.mp4", "ttl_seconds": 600}
    r = client.post("/api/v1/delivery/mint-token", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body.get("token") and body.get("storage_key") == payload["storage_key"]
    # no-store headers
    cc = (r.headers.get("Cache-Control") or "").lower()
    assert "no-store" in cc


def test_mint_token_forbidden_key(monkeypatch):
    app, client = _mk_app(monkeypatch)
    r = client.post("/api/v1/delivery/mint-token", json={"storage_key": "bad/prefix.mp4", "ttl_seconds": 60})
    assert r.status_code == 403

