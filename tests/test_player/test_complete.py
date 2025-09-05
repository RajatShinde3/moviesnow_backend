# tests/test_player/test_complete.py
import importlib
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel


# ─────────────────────────────────────────────────────────────────────────────
# Minimal body model to avoid importing the real one
# ─────────────────────────────────────────────────────────────────────────────

class CompleteInput(BaseModel):
    # Keep fields optional so we can test exclude_none behavior easily
    position_sec: Optional[float] = None
    total_watch_sec: Optional[float] = None
    reason: Optional[str] = None
    quality_avg: Optional[int] = None
    rebuffer_count: Optional[int] = None


# ─────────────────────────────────────────────────────────────────────────────
# Fake repository returned by get_player_repository()
# ─────────────────────────────────────────────────────────────────────────────

class FakeRepo:
    def __init__(self, *, return_ok: bool = True, raise_on_complete: bool = False):
        self.return_ok = return_ok
        self.raise_on_complete = raise_on_complete
        self.complete_calls: List[Tuple[str, Dict[str, Any]]] = []

    def complete(self, session_id: str, payload: Dict[str, Any]) -> bool:
        if self.raise_on_complete:
            raise RuntimeError("boom")
        self.complete_calls.append((session_id, payload))
        return self.return_ok


# ─────────────────────────────────────────────────────────────────────────────
# App factory: patch module deps, mount router, override dependencies
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, repo: Optional[FakeRepo] = None):
    """
    Build a FastAPI app with the player telemetry router mounted at
    /api/v1/player/sessions, and override everything complete() touches.
    """
    mod = importlib.import_module("app.api.v1.routers.player.sessions")

    # Patch the Pydantic model used by the route
    monkeypatch.setattr(mod, "CompleteInput", CompleteInput, raising=False)

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

    # Make the app
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
        "position_sec": 987.65,
        "total_watch_sec": 1234.5,
        "reason": "ended",
        "quality_avg": 6,
        "rebuffer_count": 2,
    }
    base.update(overrides)
    return base


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_complete_happy_202_empty_body_and_headers(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    headers = {
        "X-Request-Id": "req-999",
        "traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
    }
    sess_id = "sess_COMPLETE_1"
    body = _body()
    resp = client.post(f"/api/v1/player/sessions/{sess_id}/complete", json=body, headers=headers)

    assert resp.status_code == 202
    assert resp.content in (b"",)  # empty body (Accepted)

    # Strict no-store + correlation echo
    assert resp.headers.get("Cache-Control", "").startswith("no-store")
    assert resp.headers.get("Pragma") == "no-cache"
    assert resp.headers.get("x-request-id") == headers["X-Request-Id"]
    assert resp.headers.get("traceparent") == headers["traceparent"]

    # Repo called with right args
    assert repo.complete_calls and repo.complete_calls[-1][0] == sess_id
    payload = repo.complete_calls[-1][1]
    assert payload == body

    # Dependencies called
    assert calls["rate_limit"] == 1
    assert calls["api_key"] == 1


def test_complete_excludes_none_fields(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    # Only send position_sec; others None → excluded by exclude_none=True
    minimal = {
        "position_sec": 42.0,
        "total_watch_sec": None,
        "reason": None,
        "quality_avg": None,
        "rebuffer_count": None,
    }
    resp = client.post("/api/v1/player/sessions/sess_MIN/complete", json=minimal)
    assert resp.status_code == 202

    payload = repo.complete_calls[-1][1]
    assert payload == {"position_sec": 42.0}


def test_complete_404_when_repo_returns_false(monkeypatch):
    r = FakeRepo(return_ok=False)
    app, client, mod, repo, calls = _mk_app(monkeypatch, repo=r)

    resp = client.post("/api/v1/player/sessions/sess_NOTFOUND/complete", json=_body())
    assert resp.status_code == 404

    # deps still executed
    assert calls["rate_limit"] == 1
    assert calls["api_key"] == 1


def test_complete_500_when_repo_raises(monkeypatch):
    r = FakeRepo(raise_on_complete=True)
    app, client, mod, repo, calls = _mk_app(monkeypatch, repo=r)

    resp = client.post("/api/v1/player/sessions/sess_ERR/complete", json=_body())
    assert resp.status_code == 500


def test_complete_multiple_calls_increment_deps(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    _ = client.post("/api/v1/player/sessions/s1/complete", json=_body())
    _ = client.post("/api/v1/player/sessions/s2/complete", json=_body())
    assert calls["rate_limit"] == 2
    assert calls["api_key"] == 2
