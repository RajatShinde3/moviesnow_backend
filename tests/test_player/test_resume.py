# tests/test_player/test_resume.py
import importlib
from typing import Any, Dict, List, Optional, Tuple

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel


# ─────────────────────────────────────────────────────────────────────────────
# Minimal body model to avoid importing the real one
# ─────────────────────────────────────────────────────────────────────────────

class HeartbeatInput(BaseModel):
    # Keep everything optional so {} works
    position_sec: Optional[float] = None
    reason: Optional[str] = None
    bitrate_kbps: Optional[int] = None
    dropped_frames: Optional[int] = None


# ─────────────────────────────────────────────────────────────────────────────
# Fake repository returned by get_player_repository()
# ─────────────────────────────────────────────────────────────────────────────

class FakeRepo:
    def __init__(self, *, return_ok: bool = True, raise_on_append: bool = False):
        self.return_ok = return_ok
        self.raise_on_append = raise_on_append
        self.append_calls: List[Tuple[str, str, Dict[str, Any]]] = []

    def append_event(self, session_id: str, kind: str, payload: Dict[str, Any]) -> bool:
        if self.raise_on_append:
            raise RuntimeError("boom")
        self.append_calls.append((session_id, kind, payload))
        return self.return_ok


# ─────────────────────────────────────────────────────────────────────────────
# App factory: patch module deps, mount router, override dependencies
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, repo: Optional[FakeRepo] = None):
    """
    Build a FastAPI app with the player telemetry router mounted at
    /api/v1/player/sessions, and override everything resume() touches.
    """
    mod = importlib.import_module("app.api.v1.routers.player.sessions")

    # Patch the Pydantic model used by the route
    monkeypatch.setattr(mod, "HeartbeatInput", HeartbeatInput, raising=False)

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
        "position_sec": 321.0,
        "reason": "user_pressed_play",
        "bitrate_kbps": 3500,
        "dropped_frames": 1,
    }
    base.update(overrides)
    return base


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_resume_happy_202_empty_body_and_headers(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    headers = {
        "X-Request-Id": "req-999",
        "traceparent": "00-cccccccccccccccccccccccccccccccc-dddddddddddddddd-01",
    }
    sess_id = "sess_RESUME123"
    resp = client.post(f"/api/v1/player/sessions/{sess_id}/resume", json=_body(), headers=headers)

    assert resp.status_code == 202
    assert resp.content in (b"",)  # empty body

    # Strict no-store + correlation echo
    assert resp.headers.get("Cache-Control", "").startswith("no-store")
    assert resp.headers.get("Pragma") == "no-cache"
    assert resp.headers.get("x-request-id") == headers["X-Request-Id"]
    assert resp.headers.get("traceparent") == headers["traceparent"]

    # Repo called with right args
    assert repo.append_calls and repo.append_calls[-1][0] == sess_id
    kind = repo.append_calls[-1][1]
    payload = repo.append_calls[-1][2]
    assert kind == "resume"
    # Payload should include our fields + enforced flags
    for k, v in _body().items():
        assert payload[k] == v
    assert payload["event"] == "resume"
    assert payload["playing"] is True

    # Dependencies called
    assert calls["rate_limit"] == 1
    assert calls["api_key"] == 1


def test_resume_excludes_none_fields_and_sets_flags(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    # Only send position; others None → excluded by exclude_none
    minimal = {"position_sec": 7.5, "reason": None, "bitrate_kbps": None}
    resp = client.post("/api/v1/player/sessions/sess_X/resume", json=minimal)
    assert resp.status_code == 202

    payload = repo.append_calls[-1][2]
    assert payload == {"position_sec": 7.5, "event": "resume", "playing": True}


def test_resume_404_when_repo_returns_false(monkeypatch):
    r = FakeRepo(return_ok=False)
    app, client, mod, repo, calls = _mk_app(monkeypatch, repo=r)

    resp = client.post("/api/v1/player/sessions/sess_Y/resume", json=_body())
    assert resp.status_code == 404

    # deps still executed
    assert calls["rate_limit"] == 1
    assert calls["api_key"] == 1


def test_resume_500_when_repo_raises(monkeypatch):
    r = FakeRepo(raise_on_append=True)
    app, client, mod, repo, calls = _mk_app(monkeypatch, repo=r)

    resp = client.post("/api/v1/player/sessions/sess_Z/resume", json=_body())
    assert resp.status_code == 500


def test_resume_multiple_calls_increment_deps(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    _ = client.post("/api/v1/player/sessions/sess_1/resume", json=_body())
    _ = client.post("/api/v1/player/sessions/sess_2/resume", json=_body())
    assert calls["rate_limit"] == 2
    assert calls["api_key"] == 2
