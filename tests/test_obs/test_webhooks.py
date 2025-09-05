import importlib
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient


def _mk_app(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.ops.observability")
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")

    # Disable global limiter / use override to count
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    calls = {"rate_limit": 0, "verify": 0, "audit_add": 0}

    async def _fake_rate_limit(request: Request, response: Response, limit: int = 120, window_seconds: int = 60):
        calls["rate_limit"] += 1
        
    async def _verify_ok(request: Request, secret_env: str):
        calls["verify"] += 1
        return True

    class FakeRepo:
        def add(self, **_k):
            calls["audit_add"] += 1

    app.dependency_overrides[mod.rate_limit] = _fake_rate_limit
    monkeypatch.setattr(mod, "verify_webhook_signature", _verify_ok, raising=False)
    monkeypatch.setattr(mod, "get_audit_repository", lambda: FakeRepo(), raising=False)
    monkeypatch.setenv("WEBHOOKS_DEDUP_TTL", "1")

    client = TestClient(app)
    return app, client, mod, calls


def test_webhook_accepts_and_dedupes(monkeypatch):
    app, client, mod, calls = _mk_app(monkeypatch)

    headers = {"x-event-id": "evt-1", "X-Request-Id": "rid-2"}
    r1 = client.post("/api/v1/webhooks/email-events", headers=headers, json={"id": "evt-1", "x": 1})
    assert r1.status_code == 202
    # Should echo correlation and set no-store
    assert r1.headers.get("x-request-id") == "rid-2"
    assert r1.headers.get("Cache-Control", "").startswith("no-store")

    # Dedup same event id
    r2 = client.post("/api/v1/webhooks/email-events", headers=headers, json={"id": "evt-1"})
    assert r2.status_code == 202
    # Only one audit add despite two calls
    assert calls["audit_add"] == 1
    # Limiter invoked twice
    assert calls["rate_limit"] == 2


def test_webhook_invalid_signature_401(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.ops.observability")
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")

    async def _fake_rate_limit(request: Request, response: Response, limit: int = 120, window_seconds: int = 60):
        return None

    async def _verify_bad(request: Request, secret_env: str):
        return False

    app.dependency_overrides[mod.rate_limit] = _fake_rate_limit
    monkeypatch.setattr(mod, "verify_webhook_signature", _verify_bad, raising=False)

    client = TestClient(app)
    r = client.post("/api/v1/webhooks/cdn/invalidation-callback", headers={"x-event-id": "evt-x"}, json={})
    assert r.status_code == 401
