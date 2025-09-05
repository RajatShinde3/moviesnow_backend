# tests/test_public/test_delivery/test_bundle_url.py

import importlib
import os
from types import SimpleNamespace
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes & helpers
# ─────────────────────────────────────────────────────────────

class FakeStorageError(Exception):
    pass


class FakeS3:
    """
    Minimal stand-in for the S3 wrapper used by the route.

    Args:
      head_ok: if False, HEAD always fails (404 path)
      raise_on_presign: if set, presigned_get raises that exception
    """
    def __init__(self, *, head_ok=True, raise_on_presign: Exception | None = None):
        self.client = self
        self.bucket = "unit-test-bucket"
        self._head_ok = head_ok
        self._raise_on_presign = raise_on_presign
        self.head_calls = []
        self.presign_calls = []

    def head_object(self, *, Bucket, Key):
        self.head_calls.append({"Bucket": Bucket, "Key": Key})
        if not self._head_ok:
            raise Exception("not found")

    def presigned_get(
        self,
        key,
        *,
        expires_in: int,
        response_content_disposition: str | None,
        response_content_type: str,
    ) -> str:
        self.presign_calls.append(
            {
                "key": key,
                "expires_in": expires_in,
                "content_disposition": response_content_disposition,
                "content_type": response_content_type,
            }
        )
        if self._raise_on_presign:
            raise self._raise_on_presign
        return f"https://signed.example/{key}?e={expires_in}"


class RedeemRecorder:
    """Async stand-in for _redeem_optional_token."""
    def __init__(self, *, raise_http_exc: HTTPException | None = None):
        self.calls = 0
        self.last_token = None
        self.last_expected_key = None
        self.raise_http_exc = raise_http_exc

    async def __call__(self, token, *, expected_key):
        self.calls += 1
        self.last_token = token
        self.last_expected_key = expected_key
        if self.raise_http_exc:
            raise self.raise_http_exc


# ─────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    fake_s3: FakeS3,
    redeem: RedeemRecorder | None = None,
    enforce_key: str | None = None,
    hashed: bool = False,
    settings_overrides: dict | None = None,
    sanitize_filename_impl=None,
):
    """
    Mount the delivery router and override:
      - rate_limit -> no-op
      - _s3 -> returns provided FakeS3
      - _redeem_optional_token -> provided RedeemRecorder (or no-op)
      - S3StorageError -> FakeStorageError
      - settings.(DELIVERY_MIN_TTL, DELIVERY_MAX_TTL) -> overrides or env
      - sanitize_filename -> optional custom impl for Content-Disposition
      - PUBLIC_API_KEY / PUBLIC_API_KEY_SHA256 (optional)
    """
    mod = importlib.import_module("app.api.v1.routers.delivery")

    # No-op rate limiter
    async def _no_rl(*_, **__): return None
    monkeypatch.setattr(mod, "rate_limit", _no_rl, raising=False)

    # Inject S3 and error class
    monkeypatch.setattr(mod, "_s3", lambda: fake_s3, raising=True)
    monkeypatch.setattr(mod, "S3StorageError", FakeStorageError, raising=True)

    # Token redemption
    if redeem is None:
        redeem = RedeemRecorder()
    monkeypatch.setattr(mod, "_redeem_optional_token", redeem, raising=True)

    # Settings overrides
    if settings_overrides is None:
        settings_overrides = {}
    monkeypatch.setattr(mod, "settings", SimpleNamespace(**settings_overrides), raising=True)

    # Optional sanitize_filename hook (used inside _derive_download_filename)
    if sanitize_filename_impl is not None:
        monkeypatch.setattr(mod, "sanitize_filename", sanitize_filename_impl, raising=True)

    # API key enforcement
    if enforce_key is None:
        monkeypatch.delenv("PUBLIC_API_KEY", raising=False)
        monkeypatch.delenv("PUBLIC_API_KEY_SHA256", raising=False)
    else:
        if hashed:
            import hashlib
            monkeypatch.setenv("PUBLIC_API_KEY_SHA256", hashlib.sha256(enforce_key.encode("utf-8")).hexdigest())
            monkeypatch.delenv("PUBLIC_API_KEY", raising=False)
        else:
            monkeypatch.setenv("PUBLIC_API_KEY", enforce_key)
            monkeypatch.delenv("PUBLIC_API_KEY_SHA256", raising=False)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")
    client = TestClient(app)
    return app, client, mod, redeem


def _url():
    return "/api/v1/delivery/bundle-url"


# ─────────────────────────────────────────────────────────────
# Tests — happy path
# ─────────────────────────────────────────────────────────────

def test_bundle_url_happy_path_presigns_no_store_and_redeems_token(monkeypatch):
    fake_s3 = FakeS3(head_ok=True)
    redeem = RedeemRecorder()
    _app, client, _mod, rec = _mk_app(monkeypatch, fake_s3=fake_s3, redeem=redeem)

    payload = {
        "storage_key": "bundles/tt123/S01.zip",
        "ttl_seconds": 600,
        "attachment_filename": "S01.zip",
        "token": "tok-123",
    }
    r = client.post(_url(), json=payload)
    assert r.status_code == 200

    body = r.json()
    assert "url" in body and body["url"].startswith("https://signed.example/bundles/tt123/S01.zip")

    # HEAD + presign called
    assert fake_s3.head_calls and fake_s3.head_calls[0]["Key"] == "bundles/tt123/S01.zip"
    pc = fake_s3.presign_calls[0]
    assert pc["key"] == "bundles/tt123/S01.zip"
    assert pc["expires_in"] == 600
    assert pc["content_type"] == "application/zip"
    assert pc["content_disposition"] == 'attachment; filename="S01.zip"'

    # Redemption called with token and expected_key
    assert rec.calls == 1
    assert rec.last_token == "tok-123"
    assert rec.last_expected_key == "bundles/tt123/S01.zip"

    # no-store headers
    assert r.headers.get("Cache-Control") == "no-store"
    assert r.headers.get("Pragma") == "no-cache"
    assert r.headers.get("Expires") == "0"


def test_bundle_url_calls_redeem_even_when_token_none(monkeypatch):
    fake_s3 = FakeS3(head_ok=True)
    redeem = RedeemRecorder()
    _app, client, _mod, rec = _mk_app(monkeypatch, fake_s3=fake_s3, redeem=redeem)

    r = client.post(_url(), json={"storage_key": "bundles/ttX/S01.zip", "ttl_seconds": 600})
    assert r.status_code == 200
    assert rec.calls == 1
    assert rec.last_token is None
    assert rec.last_expected_key == "bundles/ttX/S01.zip"


# ─────────────────────────────────────────────────────────────
# Tests — validation
# ─────────────────────────────────────────────────────────────

def test_bundle_url_400_invalid_key_variants(monkeypatch):
    fake_s3 = FakeS3()
    _app, client, _mod, _ = _mk_app(monkeypatch, fake_s3=fake_s3)

    bad = [
        "", "  ",
        "downloads/tt1/S01.zip",     # wrong prefix
        "bundles/tt1/S01.txt",       # not .zip
        "/bundles/tt1/S01.zip",      # leading slash (safe_key/strip should reject → 400)
        "bundles/tt1/../S01.zip",    # traversal
    ]
    for key in bad:
        r = client.post(_url(), json={"storage_key": key, "ttl_seconds": 600})
        assert r.status_code == 400
        assert "Invalid bundle key" in r.json()["detail"] or r.json()["detail"].startswith("Invalid")


def test_bundle_url_404_when_head_missing(monkeypatch):
    fake_s3 = FakeS3(head_ok=False)
    _app, client, _mod, _ = _mk_app(monkeypatch, fake_s3=fake_s3)

    r = client.post(_url(), json={"storage_key": "bundles/tt999/S01.zip", "ttl_seconds": 600})
    assert r.status_code == 404
    assert r.json()["detail"] in ("Bundle not found or expired", "Bundle not found")


def test_bundle_url_503_on_presign_failure(monkeypatch):
    fake_s3 = FakeS3(head_ok=True, raise_on_presign=FakeStorageError("s3 down"))
    _app, client, _mod, _ = _mk_app(monkeypatch, fake_s3=fake_s3)

    r = client.post(_url(), json={"storage_key": "bundles/tt1/S01.zip", "ttl_seconds": 600})
    assert r.status_code == 503
    assert r.json()["detail"] == "s3 down"


def test_bundle_url_403_when_token_redemption_fails(monkeypatch):
    fake_s3 = FakeS3(head_ok=True)
    redeem = RedeemRecorder(raise_http_exc=HTTPException(status_code=403, detail="Token invalid or not authorized"))
    _app, client, _mod, rec = _mk_app(monkeypatch, fake_s3=fake_s3, redeem=redeem)

    r = client.post(
        _url(),
        json={"storage_key": "bundles/ttX/S02.zip", "ttl_seconds": 600, "token": "bad-token"},
    )
    assert r.status_code == 403
    # When redeem fails, presign should not be attempted
    assert fake_s3.presign_calls == []


# ─────────────────────────────────────────────────────────────
# Tests — TTL clamp & filename sanitization
# ─────────────────────────────────────────────────────────────

def test_bundle_url_clamps_ttl_to_settings_bounds(monkeypatch):
    fake_s3 = FakeS3(head_ok=True)
    _app, client, _mod, _ = _mk_app(
        monkeypatch,
        fake_s3=fake_s3,
        settings_overrides={"DELIVERY_MIN_TTL": 120, "DELIVERY_MAX_TTL": 180},
    )

    # Above max → clamped to 180
    r1 = client.post(_url(), json={"storage_key": "bundles/tt1/S01.zip", "ttl_seconds": 999})
    assert r1.status_code == 200
    assert fake_s3.presign_calls[-1]["expires_in"] == 180

    # Below min → clamped to 120
    r2 = client.post(_url(), json={"storage_key": "bundles/tt1/S02.zip", "ttl_seconds": 60})
    assert r2.status_code == 200
    assert fake_s3.presign_calls[-1]["expires_in"] == 120


def test_bundle_url_clamps_ttl_from_env_when_settings_missing(monkeypatch):
    fake_s3 = FakeS3(head_ok=True)
    _app, client, mod, _ = _mk_app(monkeypatch, fake_s3=fake_s3, settings_overrides={})
    monkeypatch.setenv("DELIVERY_MIN_TTL", "300")
    monkeypatch.setenv("DELIVERY_MAX_TTL", "300")

    r = client.post(_url(), json={"storage_key": "bundles/ttX/S01.zip", "ttl_seconds": 60})
    assert r.status_code == 200
    assert fake_s3.presign_calls[-1]["expires_in"] == 300


def test_bundle_url_uses_sanitized_attachment_filename_when_provided(monkeypatch):
    fake_s3 = FakeS3(head_ok=True)

    def _sanitize(name: str, fallback: str = "bundle.zip") -> str:
        return "safe_bundle.zip"

    _app, client, _mod, _ = _mk_app(
        monkeypatch,
        fake_s3=fake_s3,
        sanitize_filename_impl=_sanitize,
    )

    r = client.post(
        _url(),
        json={
            "storage_key": "bundles/ttX/S03.zip",
            "ttl_seconds": 600,
            "attachment_filename": "../evil/name?.zip",
        },
    )
    assert r.status_code == 200
    disp = fake_s3.presign_calls[-1]["content_disposition"]
    assert disp == 'attachment; filename="safe_bundle.zip"'


def test_bundle_url_derives_filename_from_key_when_not_provided(monkeypatch):
    fake_s3 = FakeS3(head_ok=True)
    _app, client, _mod, _ = _mk_app(monkeypatch, fake_s3=fake_s3)

    r = client.post(_url(), json={"storage_key": "bundles/ttX/Season_01.zip", "ttl_seconds": 600})
    assert r.status_code == 200
    disp = fake_s3.presign_calls[-1]["content_disposition"]
    assert disp == 'attachment; filename="Season_01.zip"'


# ─────────────────────────────────────────────────────────────
# Tests — API key enforcement
# ─────────────────────────────────────────────────────────────

def test_bundle_url_api_key_enforcement_plain_and_hashed(monkeypatch):
    for hashed in (False, True):
        key = "sekret123"
        fake_s3 = FakeS3(head_ok=True)
        _app, client, _mod, _ = _mk_app(
            monkeypatch,
            fake_s3=fake_s3,
            enforce_key=key,
            hashed=hashed,
        )

        r1 = client.post(_url(), json={"storage_key": "bundles/tt1/S01.zip", "ttl_seconds": 600})
        assert r1.status_code == 401

        r2 = client.post(
            _url(),
            json={"storage_key": "bundles/tt1/S01.zip", "ttl_seconds": 600},
            headers={"X-API-Key": key},
        )
        assert r2.status_code == 200

        r3 = client.post(
            _url() + f"?api_key={key}",
            json={"storage_key": "bundles/tt1/S01.zip", "ttl_seconds": 600},
        )
        assert r3.status_code == 200
