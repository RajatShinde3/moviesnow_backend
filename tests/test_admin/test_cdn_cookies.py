import importlib
import json
import os
import sys
import types
import time
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# -----------------------------------------------------------------------------
# Test helpers
# -----------------------------------------------------------------------------

def _mk_app(monkeypatch, *, crypto_ok=True, signer_ok=True):
    """
    Build a FastAPI app with the admin/MFA/rate-limit stubs and controllable
    "cryptography" presence and signing behavior.
    """
    mod = importlib.import_module("app.api.v1.routers.admin.cdn_cookies")  # adjust if your module path differs

    # Disable rate limiter
    async def _no_rate_limit(*_, **__):
        return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)

    # Bypass admin + MFA gates
    async def _ok(*_, **__):
        return None
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    # Prepare fake cryptography modules when crypto_ok=True
    if crypto_ok:
        # Minimal fakes to satisfy "from cryptography.... import ..." in endpoint
        serialization = types.ModuleType("serialization")
        def load_pem_private_key(_pem, password=None):
            class _Key:
                def sign(self, data, padding, hash_alg):
                    if signer_ok:
                        return b"sig"
                    raise ValueError("boom")  # triggers Signing failed
            return _Key()
        serialization.load_pem_private_key = load_pem_private_key

        hashes = types.ModuleType("hashes")
        class SHA1:
            pass
        hashes.SHA1 = SHA1

        padding = types.ModuleType("padding")
        class PKCS1v15:
            def __call__(self):  # allow calling as constructor
                return self
        padding.PKCS1v15 = PKCS1v15

        primitives = types.ModuleType("primitives")
        primitives.hashes = hashes
        primitives.asymmetric = types.SimpleNamespace(padding=padding)
        primitives.serialization = serialization

        hazmat = types.ModuleType("hazmat")
        hazmat.primitives = primitives

        cryptography = types.ModuleType("cryptography")
        cryptography.hazmat = hazmat

        # Inject into sys.modules so "from cryptography..." imports succeed
        monkeypatch.setitem(sys.modules, "cryptography", cryptography)
        monkeypatch.setitem(sys.modules, "cryptography.hazmat", hazmat)
        monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives", primitives)
        monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.hashes", hashes)
        monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.asymmetric", primitives.asymmetric)
        monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.asymmetric.padding", padding)
        monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.serialization", serialization)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    return app, TestClient(app), mod


def _set_env(monkeypatch, key_pair="KID123", pem="-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----"):
    monkeypatch.setenv("CF_KEY_PAIR_ID", key_pair or "")
    monkeypatch.setenv("CF_PRIVATE_KEY_PEM", pem or "")


# -----------------------------------------------------------------------------
# Happy path
# -----------------------------------------------------------------------------

def test_signed_cookies_success(monkeypatch):
    app, client, _ = _mk_app(monkeypatch, crypto_ok=True, signer_ok=True)
    _set_env(monkeypatch)

    now = int(time.time())
    payload = {"resource": "https://d123.cloudfront.net/downloads/*", "ttl_seconds": 600}
    r = client.post("/api/v1/admin/cdn/signed-cookies", json=payload)
    assert r.status_code == 200

    body = r.json()
    # keys should use aliases with hyphens
    assert "CloudFront-Policy" in body
    assert "CloudFront-Signature" in body
    assert "CloudFront-Key-Pair-Id" in body and body["CloudFront-Key-Pair-Id"] == "KID123"
    assert "expires" in body
    # expires should be not-too-far from now + 600 (allow small drift)
    exp = int(body["expires"])
    assert now + 550 <= exp <= now + 650

    # Cache headers
    cc = (r.headers.get("Cache-Control") or "").lower()
    assert "no-store" in cc


# -----------------------------------------------------------------------------
# Input validation (Pydantic + custom resource validation)
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("bad_payload, expected_status, expected_detail", [
    # Missing scheme
    ({"resource": "d123.cloudfront.net/downloads/*", "ttl_seconds": 600}, 400, "https:// or http://"),
    # Missing host
    ({"resource": "https:///downloads/*", "ttl_seconds": 600}, 400, "include a host"),
    # Wrong path
    ({"resource": "https://d123.cloudfront.net/files/*", "ttl_seconds": 600}, 400, "path must start with /downloads/"),
    # Query not allowed
    ({"resource": "https://d123.cloudfront.net/downloads/*?x=1", "ttl_seconds": 600}, 400, "must not include query"),
])
def test_resource_pattern_validation(monkeypatch, bad_payload, expected_status, expected_detail):
    app, client, _ = _mk_app(monkeypatch)
    _set_env(monkeypatch)
    r = client.post("/api/v1/admin/cdn/signed-cookies", json=bad_payload)
    assert r.status_code == expected_status
    assert expected_detail in r.text


@pytest.mark.parametrize("ttl", [59, 0, -1, 86401, 10**6])
def test_ttl_bounds_enforced_by_pydantic(monkeypatch, ttl):
    app, client, _ = _mk_app(monkeypatch)
    _set_env(monkeypatch)
    r = client.post("/api/v1/admin/cdn/signed-cookies", json={
        "resource": "https://d123.cloudfront.net/downloads/*",
        "ttl_seconds": ttl
    })
    assert r.status_code == 422  # Pydantic field constraints


# -----------------------------------------------------------------------------
# Env / cryptography availability / signing failure
# -----------------------------------------------------------------------------

def test_signing_unavailable_without_env(monkeypatch):
    app, client, _ = _mk_app(monkeypatch)
    # Missing env vars → 503
    monkeypatch.delenv("CF_KEY_PAIR_ID", raising=False)
    monkeypatch.delenv("CF_PRIVATE_KEY_PEM", raising=False)
    r = client.post("/api/v1/admin/cdn/signed-cookies", json={
        "resource": "https://d123.cloudfront.net/downloads/*",
        "ttl_seconds": 600
    })
    assert r.status_code == 503
    assert "Signing unavailable" in r.text


def test_cryptography_import_failure_returns_503(monkeypatch):
    # Provide env so code reaches import section
    app, client, mod = _mk_app(monkeypatch, crypto_ok=False)
    _set_env(monkeypatch)

    # Force ImportError for cryptography.* via import hook
    real_import = __import__
    def _fake_import(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ImportError("no crypto here")
        return real_import(name, *args, **kwargs)
    monkeypatch.setattr("__builtins__", "__import__", _fake_import)

    r = client.post("/api/v1/admin/cdn/signed-cookies", json={
        "resource": "https://d123.cloudfront.net/downloads/*",
        "ttl_seconds": 600
    })
    assert r.status_code == 503
    assert "Signing unavailable" in r.text


def test_signing_failed_when_key_sign_raises(monkeypatch):
    # crypto imports succeed but sign raises → 503 "Signing failed"
    app, client, _ = _mk_app(monkeypatch, crypto_ok=True, signer_ok=False)
    _set_env(monkeypatch)
    r = client.post("/api/v1/admin/cdn/signed-cookies", json={
        "resource": "https://d123.cloudfront.net/downloads/*",
        "ttl_seconds": 600
    })
    assert r.status_code == 503
    assert "Signing failed" in r.text


# -----------------------------------------------------------------------------
# Auth/MFA gate propagation
# -----------------------------------------------------------------------------

def test_admin_gate_401(monkeypatch):
    app, client, mod = _mk_app(monkeypatch)
    async def _deny_admin(*_, **__):
        raise HTTPException(status_code=401, detail="Unauthorized")
    monkeypatch.setattr(mod, "_ensure_admin", _deny_admin, raising=False)

    _set_env(monkeypatch)
    r = client.post("/api/v1/admin/cdn/signed-cookies", json={
        "resource": "https://d123.cloudfront.net/downloads/*",
        "ttl_seconds": 600
    })
    assert r.status_code == 401


def test_mfa_gate_403(monkeypatch):
    app, client, mod = _mk_app(monkeypatch)
    async def _deny_mfa(*_, **__):
        raise HTTPException(status_code=403, detail="Forbidden")
    monkeypatch.setattr(mod, "_ensure_mfa", _deny_mfa, raising=False)

    _set_env(monkeypatch)
    r = client.post("/api/v1/admin/cdn/signed-cookies", json={
        "resource": "https://d123.cloudfront.net/downloads/*",
        "ttl_seconds": 600
    })
    assert r.status_code == 403
