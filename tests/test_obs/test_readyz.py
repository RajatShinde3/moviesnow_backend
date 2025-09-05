import importlib
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient


def _mk_app(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.ops.observability")

    # Disable global limiter behavior; use override to count calls
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")

    calls = {"rate_limit": 0}

    async def _fake_rate_limit(request: Request, response: Response, limit: int = 120, window_seconds: int = 60):
        calls["rate_limit"] += 1
        return None

    # Override Depends(rate_limit)
    app.dependency_overrides[mod.rate_limit] = _fake_rate_limit

    client = TestClient(app)
    return app, client, mod, calls


def test_readyz_all_ok_returns_200_and_no_store(monkeypatch):
    app, client, mod, calls = _mk_app(monkeypatch)

    # Stub checks to all OK
    monkeypatch.setattr(mod, "_check_database", lambda: {"ok": True, "configured": True}, raising=False)
    monkeypatch.setattr(mod, "_check_redis", lambda: {"ok": True, "configured": True}, raising=False)
    monkeypatch.setattr(mod, "_check_s3", lambda: {"ok": True, "configured": False}, raising=False)
    monkeypatch.setattr(mod, "_check_kms", lambda: {"ok": True, "configured": False}, raising=False)
    monkeypatch.setattr(mod, "_check_repositories", lambda: {"ok": True}, raising=False)

    r = client.get("/api/v1/readyz", headers={"X-Request-Id": "abc"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["ok"] is True
    assert isinstance(data.get("checks"), list) and data["checks"]
    # Headers
    assert r.headers.get("Cache-Control", "").startswith("no-store")
    assert r.headers.get("Pragma") == "no-cache"
    assert r.headers.get("x-request-id") == "abc"
    # Limiter called
    assert calls["rate_limit"] == 1


def test_readyz_one_fail_returns_503(monkeypatch):
    app, client, mod, calls = _mk_app(monkeypatch)

    monkeypatch.setattr(mod, "_check_database", lambda: {"ok": True, "configured": True}, raising=False)
    monkeypatch.setattr(mod, "_check_redis", lambda: {"ok": False, "configured": True, "error": "down"}, raising=False)
    monkeypatch.setattr(mod, "_check_s3", lambda: {"ok": True, "configured": False}, raising=False)
    monkeypatch.setattr(mod, "_check_kms", lambda: {"ok": True, "configured": False}, raising=False)
    monkeypatch.setattr(mod, "_check_repositories", lambda: {"ok": True}, raising=False)

    r = client.get("/api/v1/readyz")
    assert r.status_code == 503
    data = r.json()
    assert data["ok"] is False
    assert any(not c.get("ok") for c in data.get("checks", []))
    assert r.headers.get("Cache-Control", "").startswith("no-store")
    assert r.headers.get("Pragma") == "no-cache"


def test_readyz_head_has_no_store_headers(monkeypatch):
    app, client, mod, calls = _mk_app(monkeypatch)

    r = client.head("/api/v1/readyz")
    assert r.status_code == 200
    assert r.headers.get("Cache-Control", "").startswith("no-store")
    assert r.headers.get("Pragma") == "no-cache"
    assert calls["rate_limit"] == 1
