# tests/test_player/test_get_session.py
import importlib
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict


# ─────────────────────────────────────────────────────────────────────────────
# Tolerant response model to avoid importing the real one
# ─────────────────────────────────────────────────────────────────────────────

class SessionSummary(BaseModel):
    """Accept any fields the route gives us (pydantic v2-style config)."""
    model_config = ConfigDict(extra="allow")


# ─────────────────────────────────────────────────────────────────────────────
# Fake repository returned by get_player_repository()
# ─────────────────────────────────────────────────────────────────────────────

class FakeRepo:
    def __init__(self, *, rec: Optional[Dict[str, Any]] = None, raise_on_get: bool = False):
        self._rec = rec
        self.raise_on_get = raise_on_get
        self.get_calls: List[str] = []

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        if self.raise_on_get:
            raise RuntimeError("boom")
        self.get_calls.append(session_id)
        return self._rec


# ─────────────────────────────────────────────────────────────────────────────
# App factory: patch module deps, mount router, override dependencies
# ─────────────────────────────────────────────────────────────────────────────

def _mk_app(monkeypatch, *, repo: Optional[FakeRepo] = None):
    """
    Build a FastAPI app with the player telemetry router mounted at
    /api/v1/player/sessions, and override everything get_session() touches.
    """
    mod = importlib.import_module("app.api.v1.routers.player.sessions")

    # Patch the Pydantic model used by the route to a tolerant one
    monkeypatch.setattr(mod, "SessionSummary", SessionSummary, raising=False)

    # Provide a fake repo
    repo = repo or FakeRepo(
        rec={
            "id": "sess_abc123",
            "title_id": "tt-001",
            "user_id": "user-9",
            "anon_id": None,
            "created_at": "2024-01-01T00:00:00Z",
            "status": "active",
            "duration_sec": 42.5,
        }
    )

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
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_get_session_happy_path_200_json_and_no_store(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    headers = {
        "X-Request-Id": "req-getsess-1",
        "traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
    }
    resp = client.get("/api/v1/player/sessions/sess_abc123", headers=headers)
    assert resp.status_code == 200

    data = resp.json()
    # Minimal shape
    assert data["id"] == "sess_abc123"
    assert data["title_id"] == "tt-001"
    assert data["status"] == "active"

    # Strict no-store + correlation echo
    assert resp.headers.get("Cache-Control", "").startswith("no-store")
    assert resp.headers.get("Pragma") == "no-cache"
    assert resp.headers.get("x-request-id") == headers["X-Request-Id"]
    assert resp.headers.get("traceparent") == headers["traceparent"]

    # Repo was called with the session id
    assert repo.get_calls == ["sess_abc123"]

    # Dependencies executed
    assert calls["rate_limit"] == 1
    assert calls["api_key"] == 1


def test_get_session_404_when_missing(monkeypatch):
    r = FakeRepo(rec=None)
    app, client, mod, repo, calls = _mk_app(monkeypatch, repo=r)

    resp = client.get("/api/v1/player/sessions/sess_missing")
    assert resp.status_code == 404

    # deps executed even on 404
    assert calls["rate_limit"] == 1
    assert calls["api_key"] == 1

    # no-store headers still present
    assert resp.headers.get("Cache-Control", "").startswith("no-store")
    assert resp.headers.get("Pragma") == "no-cache"


def test_get_session_500_when_repo_raises(monkeypatch):
    r = FakeRepo(rec=None, raise_on_get=True)
    app, client, mod, repo, calls = _mk_app(monkeypatch, repo=r)

    resp = client.get("/api/v1/player/sessions/sess_err")
    assert resp.status_code == 500

    # deps executed
    assert calls["rate_limit"] == 1
    assert calls["api_key"] == 1


def test_get_session_multiple_calls_increment_deps(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    _ = client.get("/api/v1/player/sessions/s1")
    _ = client.get("/api/v1/player/sessions/s2")
    assert calls["rate_limit"] == 2
    assert calls["api_key"] == 2
