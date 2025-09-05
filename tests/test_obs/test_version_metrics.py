import importlib
import sys
import types
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient


def _mk_app(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.ops.observability")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")

    calls = {"rate_limit": 0}

    async def _fake_rate_limit(request: Request, response: Response, limit: int = 120, window_seconds: int = 60):
        calls["rate_limit"] += 1
        return None

    app.dependency_overrides[mod.rate_limit] = _fake_rate_limit
    return app, TestClient(app), mod, calls


def test_version_uses_env_and_no_store(monkeypatch):
    app, client, mod, calls = _mk_app(monkeypatch)
    monkeypatch.setenv("APP_VERSION", "1.2.3")
    monkeypatch.setenv("APP_BUILD", "42")
    monkeypatch.setenv("GIT_SHA", "deadbeef")

    r = client.get("/api/v1/version", headers={"traceparent": "00-abc-ef-01"})
    assert r.status_code == 200
    body = r.json()
    assert body["version"] == "1.2.3"
    assert body["build"] == "42"
    assert body["commit"] == "deadbeef"
    # no-store and correlation echo
    assert r.headers.get("Cache-Control", "").startswith("no-store")
    assert r.headers.get("Pragma") == "no-cache"
    assert r.headers.get("traceparent") == "00-abc-ef-01"
    assert calls["rate_limit"] == 1


def test_metrics_fallback_plaintext_when_prometheus_missing(monkeypatch):
    app, client, mod, calls = _mk_app(monkeypatch)

    # Provide a dummy prometheus_client that raises inside generate_latest
    dummy = types.ModuleType("prometheus_client")

    def _generate_latest():
        raise RuntimeError("boom")

    dummy.generate_latest = _generate_latest  # type: ignore[attr-defined]
    dummy.CONTENT_TYPE_LATEST = "text/plain"
    sys.modules["prometheus_client"] = dummy

    r = client.get("/api/v1/metrics")
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("text/plain")
    text = r.text
    assert "app_heartbeat" in text
    # Limiter called
    assert calls["rate_limit"] == 1
