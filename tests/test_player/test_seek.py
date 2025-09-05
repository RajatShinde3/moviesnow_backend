# tests/test_player/test_seek.py
import importlib
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel


# ─────────────────────────────────────────────────────────────────────────────
# Minimal body model to avoid importing the real one
# ─────────────────────────────────────────────────────────────────────────────

class SeekInput(BaseModel):
    # Keep everything optional so {} works in tests if needed
    from_position_sec: Optional[float] = None
    to_position_sec: Optional[float] = None
    reason: Optional[str] = None


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
    /api/v1/player/sessions, and override everything seek() touches.
    """
    mod = importlib.import_module("app.api.v1.routers.player.sessions")

    # Patch the Pydantic model used by the route
    monkeypatch.setattr(mod, "SeekInput", SeekInput, raising=False)

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
        "from_position_sec": 123.45,
        "to_position_sec": 234.56,
        "reason": "user_scrubbed",
    }
    base.update(overrides)
    return base


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_seek_happy_202_empty_body_and_headers(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    headers = {
        "X-Request-Id": "req-777",
        "traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
    }
    sess_id = "sess_SEEK123"
    resp = client.post(f"/api/v1/player/sessions/{sess_id}/seek", json=_body(), headers=headers)

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
    assert kind == "seek"
    assert payload == _body()

    # Dependencies called
    assert calls["rate_limit"] == 1
    assert calls["api_key"] == 1


def test_seek_excludes_none_fields(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    # Only send from_position_sec; to_position_sec/ reason are None → excluded
    minimal = {"from_position_sec": 7.5, "to_position_sec": None, "reason": None}
    resp = client.post("/api/v1/player/sessions/sess_X/seek", json=minimal)
    assert resp.status_code == 202

    payload = repo.append_calls[-1][2]
    assert payload == {"from_position_sec": 7.5}


def test_seek_404_when_repo_returns_false(monkeypatch):
    r = FakeRepo(return_ok=False)
    app, client, mod, repo, calls = _mk_app(monkeypatch, repo=r)

    resp = client.post("/api/v1/player/sessions/sess_Y/seek", json=_body())
    assert resp.status_code == 404

    # deps still executed
    assert calls["rate_limit"] == 1
    assert calls["api_key"] == 1


def test_seek_500_when_repo_raises(monkeypatch):
    r = FakeRepo(raise_on_append=True)
    app, client, mod, repo, calls = _mk_app(monkeypatch, repo=r)

    resp = client.post("/api/v1/player/sessions/sess_Z/seek", json=_body())
    assert resp.status_code == 500


def test_seek_multiple_calls_increment_deps(monkeypatch):
    app, client, mod, repo, calls = _mk_app(monkeypatch)

    _ = client.post("/api/v1/player/sessions/s1/seek", json=_body())
    _ = client.post("/api/v1/player/sessions/s2/seek", json=_body())
    assert calls["rate_limit"] == 2
    assert calls["api_key"] == 2
