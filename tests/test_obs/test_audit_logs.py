import importlib
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient


def _mk_app(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.ops.observability")
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")

    # Bypass rate limiter
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    calls = {"require_admin": 0}

    async def _ok_admin(request: Request):
        calls["require_admin"] += 1
        return None

    # Dependency override
    app.dependency_overrides[mod.require_admin] = _ok_admin

    # Stub repo
    class FakeRepo:
        def list(self, *, page: int, page_size: int, source=None, actor=None):  # noqa: ANN001
            return ([{"id": 1, "action": "LOGIN"}], 1)

    monkeypatch.setattr(mod, "get_audit_repository", lambda: FakeRepo(), raising=False)

    return app, TestClient(app), mod, calls


def test_debug_audit_logs_requires_admin_and_no_store(monkeypatch):
    app, client, mod, calls = _mk_app(monkeypatch)

    r = client.get("/api/v1/debug/audit-logs?page=2&page_size=10&source=auth&actor=joe",
                   headers={"X-Request-Id": "rid-1"})
    assert r.status_code == 200
    body = r.json()
    assert body["page"] == 2 and body["page_size"] == 10 and body["total"] == 1
    assert isinstance(body["items"], list) and body["items"][0]["action"] == "LOGIN"
    # no-store + correlation echo
    assert r.headers.get("Cache-Control", "").startswith("no-store")
    assert r.headers.get("Pragma") == "no-cache"
    assert r.headers.get("x-request-id") == "rid-1"
    # Admin check invoked
    assert calls["require_admin"] == 1
