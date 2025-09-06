import importlib
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _mk_app(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.admin.jwks")

    # Disable rate limiter
    async def _no_rate_limit(*_, **__):
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # Bypass admin + MFA gates
    async def _ok(*_, **__):
        return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Stub JWKS service fns
    async def _list_keys():
        return [{"kty": "RSA", "kid": "a"}, {"kty": "EC", "kid": "b"}]
    async def _rotate():
        return {"kid": "new1", "public_jwk": {"kty": "RSA", "kid": "new1"}}
    async def _prune():
        return 3
    async def _pub():
        return {"keys": [{"kty": "RSA", "kid": "pub1"}]}

    monkeypatch.setattr(mod, "list_keys", _list_keys, raising=True)
    monkeypatch.setattr(mod, "rotate_key", _rotate, raising=True)
    monkeypatch.setattr(mod, "prune_retired", _prune, raising=True)
    monkeypatch.setattr(mod, "get_public_jwks", _pub, raising=True)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    return app, TestClient(app), mod


def test_jwks_list_and_rotate_and_prune(monkeypatch):
    app, client, mod = _mk_app(monkeypatch)

    r1 = client.get("/api/v1/admin/jwks/keys")
    assert r1.status_code == 200
    body = r1.json()
    assert isinstance(body.get("keys"), list) and len(body["keys"]) == 2
    # no-store headers
    cc = (r1.headers.get("Cache-Control") or "").lower()
    assert "no-store" in cc

    r2 = client.post("/api/v1/admin/jwks/rotate")
    assert r2.status_code == 201
    assert r2.json().get("kid") == "new1"

    r3 = client.post("/api/v1/admin/jwks/prune")
    assert r3.status_code == 200
    assert r3.json().get("removed") == 3

    r4 = client.get("/api/v1/admin/jwks/public")
    assert r4.status_code == 200
    assert isinstance(r4.json().get("keys"), list)


def test_jwks_delete_200_and_404(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.admin.jwks")

    # Gates off
    async def _ok(*_, **__):
        return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Disable rate limiter
    async def _no_rate_limit(*_, **__):
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # Case 1: delete returns True
    async def _del_true(kid: str):
        return True
    monkeypatch.setattr(mod, "delete_key", _del_true, raising=True)
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    c = TestClient(app)
    r_ok = c.delete("/api/v1/admin/jwks/keys/x1")
    assert r_ok.status_code == 200
    assert r_ok.json().get("deleted") is True

    # Case 2: delete returns False -> 404
    async def _del_false(kid: str):
        return False
    monkeypatch.setattr(mod, "delete_key", _del_false, raising=True)
    r_nf = c.delete("/api/v1/admin/jwks/keys/x2")
    assert r_nf.status_code == 404
