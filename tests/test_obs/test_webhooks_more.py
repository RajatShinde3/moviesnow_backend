import importlib
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient


def _mk_app(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.ops.observability")

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")

    # Disable rate limiter
    async def _no_rate_limit(*_, **__):
        return None
    app.dependency_overrides[mod.rate_limit] = _no_rate_limit

    calls = {"verify": 0}

    def _verify_ok(request: Request, secret_env: str):
        calls["verify"] += 1
        return True

    monkeypatch.setattr(mod, "verify_webhook_signature", _verify_ok, raising=False)
    return app, TestClient(app), calls


def test_encoding_status_and_payments(monkeypatch):
    app, client, calls = _mk_app(monkeypatch)

    r1 = client.post("/api/v1/webhooks/encoding-status", json={"id": "enc-1", "status": "done"})
    assert r1.status_code == 202
    r2 = client.post("/api/v1/webhooks/payments", json={"id": "pay-1", "amount": 100})
    assert r2.status_code == 202
    assert calls["verify"] >= 2

