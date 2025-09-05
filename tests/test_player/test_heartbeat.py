# tests/test_player/test_heartbeat.py
import importlib
from typing import Any, Dict, List, Optional, Tuple

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel


# ─────────────────────────────────────────────────────────────────────────────
# Minimal fake schema to avoid importing the real one
# ─────────────────────────────────────────────────────────────────────────────

class HeartbeatInput(BaseModel):
    # keep fields optional to verify exclude_none behavior
    bitrate_kbps: Optional[int] = None
    dropped_frames: Optional[int] = None
    buffering_ms: Optional[int] = None
    error_codes: Optional[List[str]] = None
    # add any other QoE-ish fields your server may accept; optional = safe


# ─────────────────────────────────────────────────────────────────────────────
# Fake repository returned by get_player_repository()
# ─────────────────────────────────────────────────────────────────────────────

class FakeRepo:
    def __init__(self, *, return_ok: bool = True, raise_on_heartbeat: bool = False):
        self.return_ok = return_ok
        self.raise_on_heartbeat = raise_on_heartbeat
        self.heartbeat_calls: List[Tuple[str, Dict[str, Any]]] = []

    def heartbeat(self, session_id: str, payload: Dict[str, Any]) -> bool:
        if self.raise_on_heartbeat:
            raise RuntimeError("boom")
        self.heartbeat_calls.append((session_id, payload))
        return self.return_ok


# ─────────────────────────────────────────────────────────────────────────────
# App factory: patch module deps, mount router, override dependencies
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, repo: Optional[FakeRepo] = None):
    """
    Build a FastAPI app with the player telemetry router mounted at
    /api/v1/player/sessions, and override everything heartbeat touches.
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
        "bitrate_kbps": 2500,
        "dropped_frames": 12,
        "buffering_ms": 140,
        "error_codes": ["E_NET_1"],
    }
    base.update(overrides)
    return base


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_heartbeat_happy_202_empty_body_and_headers(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    headers = {
        "X-Request-Id": "req-777",
        "traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
    }
    # Use a session id that looks like your ecosystem's (start_session used 'sess_ABC12345')
    sess_id = "sess_ABC12345"
    resp = client.post(f"/api/v1/player/sessions/{sess_id}/heartbeat", json=_body(), headers=headers)

    assert resp.status_code == 202

    # Route returns empty body for 202
    assert resp.content in (b"",)  # no JSON payload by design

    # Strict no-store + correlation echo
    assert resp.headers.get("Cache-Control", "").startswith("no-store")
    assert resp.headers.get("Pragma") == "no-cache"
    assert resp.headers.get("x-request-id") == headers["X-Request-Id"]
    assert resp.headers.get("traceparent") == headers["traceparent"]

    # Repo called with right args
    assert repo.heartbeat_calls and repo.heartbeat_calls[-1][0] == sess_id
    sent_payload = repo.heartbeat_calls[-1][1]
    assert sent_payload == _body()  # exclude_none=True means identical to provided base

    # Dependencies called
    assert calls["rate_limit"] == 1
    assert calls["api_key"] == 1


def test_heartbeat_404_when_repo_returns_false(monkeypatch):
    r = FakeRepo(return_ok=False)
    app, client, mod, repo, calls = _mk_app(monkeypatch, repo=r)

    resp = client.post("/api/v1/player/sessions/sess_ABC12345/heartbeat", json=_body())
    assert resp.status_code == 404

    # deps still executed
    assert calls["rate_limit"] == 1
    assert calls["api_key"] == 1


def test_heartbeat_500_when_repo_raises(monkeypatch):
    r = FakeRepo(raise_on_heartbeat=True)
    app, client, mod, repo, calls = _mk_app(monkeypatch, repo=r)

    resp = client.post("/api/v1/player/sessions/sess_ABC12345/heartbeat", json=_body())
    assert resp.status_code == 500


def test_heartbeat_excludes_none_fields(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    # Provide only one field; others None → excluded from forwarded payload
    minimal = {"bitrate_kbps": 900, "dropped_frames": None, "buffering_ms": None}
    resp = client.post("/api/v1/player/sessions/sess_ABC12345/heartbeat", json=minimal)
    assert resp.status_code == 202

    sent_payload = repo.heartbeat_calls[-1][1]
    assert sent_payload == {"bitrate_kbps": 900}  # only non-None field forwarded


def test_heartbeat_multiple_calls_increment_deps(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    _ = client.post("/api/v1/player/sessions/sess_1/heartbeat", json=_body())
    _ = client.post("/api/v1/player/sessions/sess_2/heartbeat", json=_body())
    assert calls["rate_limit"] == 2
    assert calls["api_key"] == 2
