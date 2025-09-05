# tests/test_admin/test_taxonomy/test_compliance_flags.py

import importlib
import uuid
from typing import Dict, List, Tuple, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────────────────
# Fakes / scaffolding
# ─────────────────────────────────────────────────────────────────────────────

class FakeUser:
    def __init__(self, id: Optional[uuid.UUID] = None):
        self.id = id or uuid.uuid4()


def _mk_app(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.admin.taxonomy")

    # Disable rate limiting for tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Patch security checks to no-ops but count calls
    dep_mod = importlib.import_module("app.dependencies.admin")
    calls: Dict[str, int] = {"ensure_admin": 0, "ensure_mfa": 0}

    async def _ensure_admin(user):  # noqa: ARG001
        calls["ensure_admin"] += 1

    async def _ensure_mfa(request):  # noqa: ARG001
        calls["ensure_mfa"] += 1

    monkeypatch.setattr(dep_mod, "ensure_admin", _ensure_admin, raising=False)
    monkeypatch.setattr(dep_mod, "ensure_mfa", _ensure_mfa, raising=False)

    # Build app + dependency overrides
    app = FastAPI()
    # Keep router itself unprefixed; we set /api/v1/admin here to avoid double-prefixing.
    app.include_router(mod.router, prefix="/api/v1/admin")

    user = FakeUser()
    app.dependency_overrides[mod.get_current_user] = lambda: user

    client = TestClient(app)
    return app, client, mod, calls


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_compliance_flags_happy_path_returns_enums_and_no_store(monkeypatch):
    app, client, mod, calls = _mk_app(monkeypatch)

    resp = client.get("/api/v1/admin/compliance/flags")
    assert resp.status_code == 200

    data = resp.json()
    # keys present
    assert set(data.keys()) == {
        "certification_systems",
        "advisory_kinds",
        "advisory_severities",
    }

    # values are lists of enum names (compare to module enums)
    expected_systems = [e.name for e in mod.CertificationSystem]
    expected_kinds = [e.name for e in mod.AdvisoryKind]
    expected_severities = [e.name for e in mod.AdvisorySeverity]

    assert data["certification_systems"] == expected_systems
    assert data["advisory_kinds"] == expected_kinds
    assert data["advisory_severities"] == expected_severities

    # Cache headers
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("Pragma") == "no-cache"


def test_compliance_flags_calls_security_checks(monkeypatch):
    app, client, mod, calls = _mk_app(monkeypatch)

    resp = client.get("/api/v1/admin/compliance/flags")
    assert resp.status_code == 200

    # Ensure both checks were actually invoked exactly once
    assert calls["ensure_admin"] == 1
    assert calls["ensure_mfa"] == 1
