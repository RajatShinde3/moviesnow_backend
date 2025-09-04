# tests/test_validate_media_policy.py

import uuid
from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

# Import the router and enums directly from the module that defines the route.
# If your file lives at app.api.admin.validation, change the import accordingly.
import app.api.v1.routers.admin.assets.validation as mod  # adjust to your actual module path

# ─────────────────────────────────────────────────────────────────────────────
# Test doubles (rows & DB)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SV:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    is_streamable: bool = False
    stream_tier: Optional[Any] = None   # StreamTier or None
    is_audio_only: bool = False
    protocol: Any = None                # StreamProtocol or None
    media_asset_id: uuid.UUID = field(default_factory=uuid.uuid4)

@dataclass
class MA:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    kind: Any = None                    # MediaAssetKind
    bytes_size: Optional[int] = 123
    checksum_sha256: str = "deadbeef"

@dataclass
class SUB:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    language: str = "en"
    is_default: bool = False
    is_forced: bool = False
    active: bool = True


class _Scalars:
    def __init__(self, items: List[Any]): self._items = items
    def all(self): return self._items

class _Result:
    def __init__(self, items: List[Any]): self._items = items
    def scalars(self): return _Scalars(self._items)

class FakeDB:
    """
    Very small async stub that returns your provided lists in the order
    the endpoint executes its three queries:
      1) StreamVariant list
      2) MediaAsset list
      3) Subtitle list
    """
    def __init__(self, chunks: List[List[Any]]):
        self._chunks = list(chunks)

    async def execute(self, _query):
        items = self._chunks.pop(0) if self._chunks else []
        return _Result(items)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _noop(*_a, **_k): return None
async def _raise_403(*_a, **_k): raise HTTPException(status_code=403, detail="Forbidden")
async def _raise_401(*_a, **_k): raise HTTPException(status_code=401, detail="MFA required")

class _User:  # minimal current_user
    id = uuid.uuid4()

def _mk_app(db: FakeDB, monkeypatch, ensure_admin=_noop, ensure_mfa=_noop) -> Tuple[FastAPI, TestClient]:
    # Bypass rate limiter in tests
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Monkeypatch admin/MFA gate (imported lazily inside the endpoint)
    monkeypatch.setattr("app.dependencies.admin.ensure_admin", ensure_admin, raising=False)
    monkeypatch.setattr("app.dependencies.admin.ensure_mfa", ensure_mfa, raising=False)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")

    # Dependency overrides
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: _User()

    return app, TestClient(app)


def _tier(t):
    # convenience for handling enum or string interchangeably
    return getattr(t, "value", t)


# ─────────────────────────────────────────────────────────────────────────────
# Happy path
# ─────────────────────────────────────────────────────────────────────────────

def test_validate_media_happy_path_empty_issues_and_no_store_headers(monkeypatch):
    title_id = uuid.uuid4()

    # 3 good streamable HLS tiers
    sv = [
        SV(is_streamable=True, stream_tier=mod.StreamTier.P480, protocol=mod.StreamProtocol.HLS),
        SV(is_streamable=True, stream_tier=mod.StreamTier.P720, protocol=mod.StreamProtocol.HLS),
        SV(is_streamable=True, stream_tier=mod.StreamTier.P1080, protocol=mod.StreamProtocol.HLS),
    ]
    # Download-like assets with complete metadata
    a = [
        MA(kind=mod.MediaAssetKind.DOWNLOAD, bytes_size=10, checksum_sha256="a1"),
        MA(kind=mod.MediaAssetKind.VIDEO,    bytes_size=20, checksum_sha256="b2"),
    ]
    # Clean subtitles (no conflicts)
    subs = [
        SUB(language="en", is_default=True),
        SUB(language="es", is_forced=True),
    ]

    app, client = _mk_app(FakeDB([sv, a, subs]), monkeypatch)
    r = client.get(f"/api/v1/admin/titles/{title_id}/validate-media")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body.get("issues"), list)
    assert body["issues"] == []  # empty list = 👍
    # Strict no-store from the endpoint helper
    assert r.headers.get("Cache-Control", "").startswith("no-store")
    assert r.headers.get("Pragma") == "no-cache"


# ─────────────────────────────────────────────────────────────────────────────
# Stream variant validations
# ─────────────────────────────────────────────────────────────────────────────

def test_missing_tier_reports_error(monkeypatch):
    title_id = uuid.uuid4()
    sv = [
        SV(is_streamable=True, stream_tier=mod.StreamTier.P480, protocol=mod.StreamProtocol.HLS),
        SV(is_streamable=True, stream_tier=mod.StreamTier.P720, protocol=mod.StreamProtocol.HLS),
        # P1080 missing
    ]
    app, client = _mk_app(FakeDB([sv, [], []]), monkeypatch)
    r = client.get(f"/api/v1/admin/titles/{title_id}/validate-media")
    issues = r.json()["issues"]
    assert any(i["code"] == "MISSING_TIER" and _tier(mod.StreamTier.P1080) == i["tier"] for i in issues)

def test_multi_tier_reports_error(monkeypatch):
    title_id = uuid.uuid4()
    sv = [
        SV(is_streamable=True, stream_tier=mod.StreamTier.P480,  protocol=mod.StreamProtocol.HLS),
        SV(is_streamable=True, stream_tier=mod.StreamTier.P720,  protocol=mod.StreamProtocol.HLS),
        SV(is_streamable=True, stream_tier=mod.StreamTier.P720,  protocol=mod.StreamProtocol.HLS),  # duplicate tier
        SV(is_streamable=True, stream_tier=mod.StreamTier.P1080, protocol=mod.StreamProtocol.HLS),
    ]
    app, client = _mk_app(FakeDB([sv, [], []]), monkeypatch)
    r = client.get(f"/api/v1/admin/titles/{title_id}/validate-media")
    issues = r.json()["issues"]
    assert any(i["code"] == "MULTI_TIER" and i["tier"] == _tier(mod.StreamTier.P720) and i["count"] == 2 for i in issues)

def test_duplicate_streamable_per_asset_and_tier(monkeypatch):
    title_id = uuid.uuid4()
    shared_asset = uuid.uuid4()
    sv = [
        SV(is_streamable=True, stream_tier=mod.StreamTier.P720, protocol=mod.StreamProtocol.HLS, media_asset_id=shared_asset),
        SV(is_streamable=True, stream_tier=mod.StreamTier.P720, protocol=mod.StreamProtocol.HLS, media_asset_id=shared_asset),
        # include other tiers so the only tier-level error is MULTI_TIER for P720 (expected) + DUP_* for same asset+tier
        SV(is_streamable=True, stream_tier=mod.StreamTier.P480,  protocol=mod.StreamProtocol.HLS),
        SV(is_streamable=True, stream_tier=mod.StreamTier.P1080, protocol=mod.StreamProtocol.HLS),
    ]
    app, client = _mk_app(FakeDB([sv, [], []]), monkeypatch)
    r = client.get(f"/api/v1/admin/titles/{title_id}/validate-media")
    issues = r.json()["issues"]
    assert any(i["code"] == "DUP_STREAMABLE_PER_ASSET_TIER" and i["asset_id"] == str(shared_asset) and i["tier"] == _tier(mod.StreamTier.P720) and i["count"] == 2 for i in issues)
    assert any(i["code"] == "MULTI_TIER" and i["tier"] == _tier(mod.StreamTier.P720) and i["count"] == 2 for i in issues)

def test_streamable_audio_only_is_error(monkeypatch):
    title_id = uuid.uuid4()
    sv = [
        SV(is_streamable=True, stream_tier=mod.StreamTier.P480,  protocol=mod.StreamProtocol.HLS),
        SV(is_streamable=True, stream_tier=mod.StreamTier.P720,  protocol=mod.StreamProtocol.HLS, is_audio_only=True),  # ❌
        SV(is_streamable=True, stream_tier=mod.StreamTier.P1080, protocol=mod.StreamProtocol.HLS),
    ]
    app, client = _mk_app(FakeDB([sv, [], []]), monkeypatch)
    r = client.get(f"/api/v1/admin/titles/{title_id}/validate-media")
    issues = r.json()["issues"]
    assert any(i["code"] == "STREAMABLE_AUDIO_ONLY" for i in issues)

def test_streamable_not_hls_is_warning(monkeypatch):
    title_id = uuid.uuid4()
    # Set protocol to None to trigger "not HLS" warning (anything != HLS)
    sv = [
        SV(is_streamable=True, stream_tier=mod.StreamTier.P480,  protocol=None),   # ⚠️
        SV(is_streamable=True, stream_tier=mod.StreamTier.P720,  protocol=mod.StreamProtocol.HLS),
        SV(is_streamable=True, stream_tier=mod.StreamTier.P1080, protocol=mod.StreamProtocol.HLS),
    ]
    app, client = _mk_app(FakeDB([sv, [], []]), monkeypatch)
    r = client.get(f"/api/v1/admin/titles/{title_id}/validate-media")
    issues = r.json()["issues"]
    assert any(i["code"] == "STREAMABLE_NOT_HLS" for i in issues)

def test_streamable_missing_tier_is_error(monkeypatch):
    title_id = uuid.uuid4()
    sv = [
        SV(is_streamable=True, stream_tier=None,                  protocol=mod.StreamProtocol.HLS),  # ❌ no tier
        SV(is_streamable=True, stream_tier=mod.StreamTier.P720,   protocol=mod.StreamProtocol.HLS),
        SV(is_streamable=True, stream_tier=mod.StreamTier.P1080,  protocol=mod.StreamProtocol.HLS),
    ]
    app, client = _mk_app(FakeDB([sv, [], []]), monkeypatch)
    r = client.get(f"/api/v1/admin/titles/{title_id}/validate-media")
    issues = r.json()["issues"]
    assert any(i["code"] == "STREAMABLE_NO_TIER" for i in issues)


# ─────────────────────────────────────────────────────────────────────────────
# Download completeness
# ─────────────────────────────────────────────────────────────────────────────

def test_download_missing_fields_warn(monkeypatch):
    title_id = uuid.uuid4()
    # stream variants OK (so we focus on download warnings)
    sv = [
        SV(is_streamable=True, stream_tier=mod.StreamTier.P480,  protocol=mod.StreamProtocol.HLS),
        SV(is_streamable=True, stream_tier=mod.StreamTier.P720,  protocol=mod.StreamProtocol.HLS),
        SV(is_streamable=True, stream_tier=mod.StreamTier.P1080, protocol=mod.StreamProtocol.HLS),
    ]
    # Assets with missing fields
    a = [
        MA(kind=mod.MediaAssetKind.DOWNLOAD, bytes_size=None, checksum_sha256=""),         # both missing
        MA(kind=mod.MediaAssetKind.ORIGINAL, bytes_size=10,    checksum_sha256=""),        # missing checksum
    ]
    app, client = _mk_app(FakeDB([sv, a, []]), monkeypatch)
    r = client.get(f"/api/v1/admin/titles/{title_id}/validate-media")
    issues = r.json()["issues"]
    codes = [i["code"] for i in issues]
    assert "DOWNLOAD_SIZE_MISSING" in codes
    assert "DOWNLOAD_SHA_MISSING" in codes


# ─────────────────────────────────────────────────────────────────────────────
# Subtitles per-language uniqueness
# ─────────────────────────────────────────────────────────────────────────────

def test_subtitle_multi_default_and_forced_errors(monkeypatch):
    title_id = uuid.uuid4()
    # stream variants OK
    sv = [
        SV(is_streamable=True, stream_tier=mod.StreamTier.P480,  protocol=mod.StreamProtocol.HLS),
        SV(is_streamable=True, stream_tier=mod.StreamTier.P720,  protocol=mod.StreamProtocol.HLS),
        SV(is_streamable=True, stream_tier=mod.StreamTier.P1080, protocol=mod.StreamProtocol.HLS),
    ]
    # Conflicting subtitles
    subs = [
        SUB(language="en", is_default=True),
        SUB(language="en", is_default=True),     # ❌ multi default
        SUB(language="fr", is_forced=True),
        SUB(language="fr", is_forced=True),      # ❌ multi forced
    ]
    app, client = _mk_app(FakeDB([sv, [], subs]), monkeypatch)
    r = client.get(f"/api/v1/admin/titles/{title_id}/validate-media")
    issues = r.json()["issues"]
    assert any(i["code"] == "SUBTITLE_MULTI_DEFAULT" and i["language"] == "en" and i["count"] == 2 for i in issues)
    assert any(i["code"] == "SUBTITLE_MULTI_FORCED"  and i["language"] == "fr" and i["count"] == 2 for i in issues)


# ─────────────────────────────────────────────────────────────────────────────
# AuthZ + MFA
# ─────────────────────────────────────────────────────────────────────────────

def test_admin_required(monkeypatch):
    title_id = uuid.uuid4()
    app, client = _mk_app(FakeDB([[], [], []]), monkeypatch, ensure_admin=_raise_403, ensure_mfa=_noop)
    r = client.get(f"/api/v1/admin/titles/{title_id}/validate-media")
    assert r.status_code == 403
    assert r.json()["detail"] == "Forbidden"

def test_mfa_required(monkeypatch):
    title_id = uuid.uuid4()
    app, client = _mk_app(FakeDB([[], [], []]), monkeypatch, ensure_admin=_noop, ensure_mfa=_raise_401)
    r = client.get(f"/api/v1/admin/titles/{title_id}/validate-media")
    assert r.status_code == 401
    assert r.json()["detail"] == "MFA required"
