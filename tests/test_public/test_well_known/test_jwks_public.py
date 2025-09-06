import importlib
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _mk_app(monkeypatch):
    mod = importlib.import_module("app.api.well_known")

    async def _fake_get_public_jwks():
        return {"keys": [{"kty": "RSA", "kid": "k1"}]}

    monkeypatch.setattr(mod, "get_public_jwks", _fake_get_public_jwks, raising=True)

    app = FastAPI()
    app.include_router(mod.router)  # no prefix; route is absolute
    return app, TestClient(app)


def test_public_jwks_etag_and_304(monkeypatch):
    app, client = _mk_app(monkeypatch)

    r1 = client.get("/.well-known/jwks.json")
    assert r1.status_code == 200
    body = r1.json()
    assert isinstance(body.get("keys"), list)
    etag = r1.headers.get("ETag")
    assert etag and etag.startswith("\"")
    # Conditional GET should return 304
    r2 = client.get("/.well-known/jwks.json", headers={"If-None-Match": etag})
    assert r2.status_code == 304
    # Cache headers present
    cc = (r1.headers.get("Cache-Control") or "").lower()
    assert "max-age" in cc and "s-maxage" in cc

