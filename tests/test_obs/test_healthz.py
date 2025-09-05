# tests/test_observability/test_healthz.py
import importlib
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _mk_app(monkeypatch):
    """
    Test app with the observability router mounted at /api/v1
    and a fake rate_limit dependency that just increments a counter.
    """
    mod = importlib.import_module("app.api.v1.routers.ops.observability")

    # Be nice to CI environments that wire in a global limiter
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")

    calls = {"rate_limit": 0}

    async def _fake_rate_limit():
        calls["rate_limit"] += 1

    # Override the dependency used by Depends(rate_limit)
    app.dependency_overrides[mod.rate_limit] = _fake_rate_limit

    client = TestClient(app)
    return app, client, mod, calls


def test_healthz_happy_path_json_and_no_store(monkeypatch):
    app, client, mod, calls = _mk_app(monkeypatch)

    resp = client.get("/api/v1/healthz")
    assert resp.status_code == 200

    data = resp.json()
    assert data["status"] == "ok"
    assert isinstance(data["ts"], int)

    # Strict no-store cache headers
    assert resp.headers.get("Cache-Control", "").startswith("no-store")
    assert resp.headers.get("Pragma") == "no-cache"

    # Dependency executed
    assert calls["rate_limit"] == 1


def test_healthz_echoes_correlation_headers(monkeypatch):
    app, client, mod, calls = _mk_app(monkeypatch)

    headers = {
        "X-Request-Id": "req-123",
        "traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
    }
    resp = client.get("/api/v1/healthz", headers=headers)
    assert resp.status_code == 200

    # Response should echo the same values (case-insensitive access)
    assert resp.headers.get("x-request-id") == headers["X-Request-Id"]
    assert resp.headers.get("traceparent") == headers["traceparent"]

    # Strict no-store cache headers still present
    assert resp.headers.get("Cache-Control", "").startswith("no-store")
    assert resp.headers.get("Pragma") == "no-cache"

    # Dependency executed
    assert calls["rate_limit"] == 1


def test_healthz_head_minimal_and_no_store(monkeypatch):
    app, client, mod, calls = _mk_app(monkeypatch)

    resp = client.head("/api/v1/healthz")
    assert resp.status_code == 200
    # HEAD should not return a JSON body; just ensure headers are correct
    assert resp.headers.get("Cache-Control", "").startswith("no-store")
    assert resp.headers.get("Pragma") == "no-cache"

    # Dependency executed for HEAD too
    assert calls["rate_limit"] == 1


def test_healthz_both_methods_call_rate_limit(monkeypatch):
    app, client, mod, calls = _mk_app(monkeypatch)

    _ = client.get("/api/v1/healthz")
    _ = client.head("/api/v1/healthz")
    assert calls["rate_limit"] == 2
