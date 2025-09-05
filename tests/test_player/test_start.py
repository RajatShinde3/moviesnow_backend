# tests/test_player/test_start_session.py
import importlib
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel
from enum import Enum


# ─────────────────────────────────────────────────────────────────────────────
# Minimal fake schemas to avoid importing the real ones
# ─────────────────────────────────────────────────────────────────────────────

class FakeQuality(str, Enum):
    auto = "auto"
    hd = "hd"


class FakeDevice(BaseModel):
    os: Optional[str] = None
    model: Optional[str] = None
    app_version: Optional[str] = None


class FakeNetwork(BaseModel):
    type: Optional[str] = None
    down_mbps: Optional[float] = None


class StartSessionInput(BaseModel):
    title_id: str
    quality: FakeQuality = FakeQuality.auto
    device: Optional[FakeDevice] = None
    playback_type: Optional[str] = None
    position_sec: Optional[float] = None
    network: Optional[FakeNetwork] = None


class StartSessionResponse(BaseModel):
    id: str
    title_id: str
    user_id: Optional[str] = None
    anon_id: Optional[str] = None
    created_at: str
    status: str


# ─────────────────────────────────────────────────────────────────────────────
# Fake repository (what get_player_repository() returns)
# ─────────────────────────────────────────────────────────────────────────────

class FakeRepo:
    def __init__(self):
        self.raise_on_start: bool = False
        self.start_calls: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []

    def start_session(self, **kwargs):
        if self.raise_on_start:
            raise RuntimeError("boom")
        # capture args and nested playback dict for assertions
        self.start_calls.append((kwargs, kwargs.get("playback") or {}))
        # what the route expects back
        return {
            "id": "sess_ABC12345",
            "title_id": kwargs["title_id"],
            "user_id": kwargs.get("user_id"),
            "anon_id": kwargs.get("anon_id"),
            "created_at": datetime.utcnow().isoformat() + "Z",
            "status": "active",
        }


# ─────────────────────────────────────────────────────────────────────────────
# App factory: patch module deps, mount router, override dependencies
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, repo: Optional[FakeRepo] = None):
    """
    Build a FastAPI app with the player telemetry router mounted at
    /api/v1/player/sessions, and override everything start_session touches.
    """
    mod = importlib.import_module("app.api.v1.routers.player.sessions")

    # Clean / set env so tests are deterministic
    monkeypatch.delenv("ALLOW_ANON_TELEMETRY", raising=False)
    monkeypatch.delenv("TELEMETRY_USER_ID_HEADER", raising=False)
    monkeypatch.setenv("TELEMETRY_USER_ID_HEADER", "x-user-id")

    # Override Pydantic models used by the route
    monkeypatch.setattr(mod, "StartSessionInput", StartSessionInput, raising=False)
    monkeypatch.setattr(mod, "StartSessionResponse", StartSessionResponse, raising=False)

    # Deterministic title sanitizer & anon id generator
    san_calls: List[str] = []
    def _sanitize(title_id: str) -> str:
        san_calls.append(title_id)
        return f"sanitized::{title_id.strip()}"
    monkeypatch.setattr(mod, "sanitize_title_id", _sanitize, raising=False)

    def _anon_fixed(request) -> str:  # noqa: ARG001
        return "anon_fixed_32chars_abcdefghijklmnop"
    monkeypatch.setattr(mod, "_anon_id_from_request", _anon_fixed, raising=False)

    # Deterministic storage helpers (so we can assert they were merged)
    def _ip_fields(req):  # noqa: ARG001
        return {"client_ip": "203.0.113.9"}
    def _ua_fields(req):  # noqa: ARG001
        return {"ua": "pytest-UA/1.0"}
    monkeypatch.setattr(mod, "_ip_fields_for_storage", _ip_fields, raising=False)
    monkeypatch.setattr(mod, "_ua_fields_for_storage", _ua_fields, raising=False)

    # Fresh in-process idempotency cache per test
    class _TinyTTL:
        def __init__(self): self.store = {}
        def get(self, k): return self.store.get(k)
        def set(self, k, v, ttl):  # ttl ignored but accepted
            self.store[k] = v
    monkeypatch.setattr(mod, "_idem_cache", _TinyTTL(), raising=False)

    # Plug our fake repo
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

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/player/sessions")
    app.dependency_overrides[mod.rate_limit] = _fake_rate_limit_dep
    app.dependency_overrides[mod.enforce_public_api_key] = _fake_api_key_dep

    client = TestClient(app)
    return app, client, mod, repo, calls, san_calls


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _body(**overrides):
    base = {
        "title_id": "   MOV-9   ",
        "quality": "auto",
        "device": {"os": "Android", "model": "X1", "app_version": "9.9"},
        "network": {"type": "wifi", "down_mbps": 75.5},
        # playback_type + position_sec omitted → exercise defaults
    }
    base.update(overrides)
    return base


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_start_happy_201_with_user_id_and_headers(monkeypatch):
    app, client, mod, repo, calls, san_calls = _mk_app(monkeypatch)

    headers = {
        "x-user-id": "user-123",
        "X-Request-Id": "req-777",
        "traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
    }
    resp = client.post("/api/v1/player/sessions/start", json=_body(), headers=headers)
    assert resp.status_code == 201

    data = resp.json()
    assert data["id"] == "sess_ABC12345"
    assert data["user_id"] == "user-123"
    assert data["anon_id"] is None
    assert data["title_id"] == "sanitized::MOV-9"
    assert isinstance(data["created_at"], str) and data["created_at"].endswith("Z")
    assert data["status"] == "active"

    # Headers: no-store & correlation echo + X-Session-Id
    assert resp.headers.get("Cache-Control", "").startswith("no-store")
    assert resp.headers.get("Pragma") == "no-cache"
    assert resp.headers.get("x-request-id") == headers["X-Request-Id"]
    assert resp.headers.get("traceparent") == headers["traceparent"]
    assert resp.headers.get("X-Session-Id") == "sess_ABC12345"

    # Repo received sanitized title and merged context
    assert repo.start_calls, "repo.start_session was not called"
    args, playback = repo.start_calls[0]
    assert args["title_id"] == "sanitized::MOV-9"
    assert args["quality"] == "auto"  # enum value passed
    assert args["device"] == {"os": "Android", "model": "X1", "app_version": "9.9"}
    # playback defaults + helpers merged
    assert playback["type"] == "stream"
    assert playback["position_sec"] == 0.0
    assert playback["client_ip"] == "203.0.113.9"
    assert playback["ua"] == "pytest-UA/1.0"
    assert playback["network"] == {"type": "wifi", "down_mbps": 75.5}

    # Dependencies called
    assert calls["rate_limit"] == 1
    assert calls["api_key"] == 1

def test_start_anon_denied_when_env_false(monkeypatch):
    app, client, mod, repo, calls, san_calls = _mk_app(monkeypatch)
    # no x-user-id
    resp = client.post("/api/v1/player/sessions/start", json=_body())
    assert resp.status_code == 401
    # deps called; repo not called
    assert calls["rate_limit"] == 1 and calls["api_key"] == 1
    assert repo.start_calls == []

def test_start_anon_allowed_with_env_true(monkeypatch):
    app, client, mod, repo, calls, san_calls = _mk_app(monkeypatch)
    os.environ["ALLOW_ANON_TELEMETRY"] = "true"
    resp = client.post("/api/v1/player/sessions/start", json=_body())
    assert resp.status_code == 201
    data = resp.json()
    assert data["user_id"] is None
    assert data["anon_id"] == "anon_fixed_32chars_abcdefghijklmnop"
    assert data["title_id"] == "sanitized::MOV-9"

def test_start_custom_user_header_env(monkeypatch):
    app, client, mod, repo, calls, san_calls = _mk_app(monkeypatch)
    os.environ["TELEMETRY_USER_ID_HEADER"] = "x-auth-user"
    resp = client.post("/api/v1/player/sessions/start", json=_body(), headers={"x-auth-user": "U-9"})
    assert resp.status_code == 201
    assert resp.json()["user_id"] == "U-9"

def test_start_idempotency_replay_uses_snapshot(monkeypatch):
    app, client, mod, repo, calls, san_calls = _mk_app(monkeypatch)
    headers = {"x-user-id": "u", "Idempotency-Key": "idem-key-1"}
    first = client.post("/api/v1/player/sessions/start", json=_body(), headers=headers)
    again = client.post("/api/v1/player/sessions/start", json=_body(), headers=headers)
    assert first.status_code == 201 and again.status_code == 201
    assert first.json() == again.json()
    # repo was called only once
    assert len(repo.start_calls) == 1
    # replay still has strict no-store
    assert again.headers.get("Cache-Control", "").startswith("no-store")

def test_start_repo_error_500(monkeypatch):
    r = FakeRepo(); r.raise_on_start = True
    app, client, mod, repo, calls, san_calls = _mk_app(monkeypatch, repo=r)
    resp = client.post("/api/v1/player/sessions/start", json=_body(), headers={"x-user-id": "u"})
    assert resp.status_code == 500

def test_start_overrides_playback_type_and_position(monkeypatch):
    app, client, mod, repo, calls, san_calls = _mk_app(monkeypatch)
    body = _body(playback_type="download", position_sec=12.5, quality="hd")
    _ = client.post("/api/v1/player/sessions/start", json=body, headers={"x-user-id": "u"})
    args, playback = repo.start_calls[-1]
    assert args["quality"] == "hd"
    assert playback["type"] == "download"
    assert playback["position_sec"] == 12.5
