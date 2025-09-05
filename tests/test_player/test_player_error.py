# tests/test_player/test_error.py
import importlib
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel


# ─────────────────────────────────────────────────────────────────────────────
# Minimal body model to avoid importing the real one
# ─────────────────────────────────────────────────────────────────────────────

class ErrorInput(BaseModel):
    message: Optional[str] = None
    code: Optional[str] = None
    position_sec: Optional[float] = None
    fatal: Optional[bool] = None
    extra: Optional[Dict[str, Any]] = None


# ─────────────────────────────────────────────────────────────────────────────
# Fake repository returned by get_player_repository()
# ─────────────────────────────────────────────────────────────────────────────

class FakeRepo:
    def __init__(self, *, return_ok: bool = True, raise_on_append: bool = False):
        self.return_ok = return_ok
        self.raise_on_append = raise_on_append
        self.append_calls: List[Tuple[str, str, Dict[str, Any]]] = []

    def append_event(self, session_id: str, event: str, payload: Dict[str, Any]) -> bool:
        if self.raise_on_append:
            raise RuntimeError("boom")
        self.append_calls.append((session_id, event, payload))
        return self.return_ok


# ─────────────────────────────────────────────────────────────────────────────
# App factory: patch module deps, mount router, override dependencies
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, repo: Optional[FakeRepo] = None):
    """
    Build a FastAPI app with the player telemetry router mounted at
    /api/v1/player/sessions, and override everything error() touches.
    """
    mod = importlib.import_module("app.api.v1.routers.player.sessions")

    # Patch the Pydantic model used by the route
    monkeypatch.setattr(mod, "ErrorInput", ErrorInput, raising=False)

    # Provide a fake repo
    repo = repo or FakeRepo()
    def _fake_get_repo():
        return repo
    monkeypatch.setattr(mod, "get_player_repository", _fake_get_repo, raising=False)

    # Dependency counters for rate_limit + API key enforcement
    calls = {"rate_limit": 0, "api_key": 0}
    async def _fake_rate_limit_dep():
        calls["rate_limit"] += 1
    async def _fake_api_key_dep():
        calls["api_key"] += 1

    # Test app
    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/player/sessions")

    # Override deps
    app.dependency_overrides[mod.rate_limit] = _fake_rate_limit_dep
    app.dependency_overrides[mod.enforce_public_api_key] = _fake_api_key_dep

    client = TestClient(app)
    return app, client, mod, repo, calls


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _body(**overrides):
    base = {
        "message": "decoder crashed",
        "code": "E_DECODER",
        "position_sec": 123.45,
        "fatal": True,
        "extra": {"stack": "Trace...", "component": "hls"},
    }
    base.update(overrides)
    return base


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_error_happy_202_echo_headers_and_no_store(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    headers = {
        "X-Request-Id": "req-err-1",
        "traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
    }
    sess_id = "sess_ERR_1"
    body = _body()
    resp = client.post(f"/api/v1/player/sessions/{sess_id}/error", json=body, headers=headers)

    assert resp.status_code == 202
    assert resp.content in (b"",)  # empty Accepted body

    # Strict no-store + correlation echo
    assert resp.headers.get("Cache-Control", "").startswith("no-store")
    assert resp.headers.get("Pragma") == "no-cache"
    assert resp.headers.get("x-request-id") == headers["X-Request-Id"]
    assert resp.headers.get("traceparent") == headers["traceparent"]

    # Repo append_event called correctly
    assert repo.append_calls and repo.append_calls[-1][0] == sess_id
    assert repo.append_calls[-1][1] == "error"
    assert repo.append_calls[-1][2] == body

    # Dependencies called
    assert calls["rate_limit"] == 1
    assert calls["api_key"] == 1


def test_error_excludes_none_fields(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    minimal = {
        "message": "oops",
        "position_sec": 0.0,
        "code": None,
        "fatal": None,
        "extra": None,
    }
    resp = client.post("/api/v1/player/sessions/sess_MIN/error", json=minimal)
    assert resp.status_code == 202

    # Only non-None fields sent to repo
    payload = repo.append_calls[-1][2]
    assert payload == {"message": "oops", "position_sec": 0.0}


def test_error_404_when_repo_returns_false(monkeypatch):
    r = FakeRepo(return_ok=False)
    app, client, mod, repo, calls = _mk_app(monkeypatch, repo=r)

    resp = client.post("/api/v1/player/sessions/sess_NOTFOUND/error", json=_body())
    assert resp.status_code == 404

    # deps still executed
    assert calls["rate_limit"] == 1
    assert calls["api_key"] == 1


def test_error_500_when_repo_raises(monkeypatch):
    r = FakeRepo(raise_on_append=True)
    app, client, mod, repo, calls = _mk_app(monkeypatch, repo=r)

    resp = client.post("/api/v1/player/sessions/sess_ERR/error", json=_body())
    assert resp.status_code == 500


def test_error_multiple_calls_increment_deps(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    _ = client.post("/api/v1/player/sessions/s1/error", json=_body())
    _ = client.post("/api/v1/player/sessions/s2/error", json=_body())
    assert calls["rate_limit"] == 2
    assert calls["api_key"] == 2
