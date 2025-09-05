# tests/test_public/test_delivery/test_batch_download_urls.py

import importlib
import os
from types import SimpleNamespace
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────
# Fakes & helpers
# ─────────────────────────────────────────────────────────────

class FakeS3:
    """
    Minimal stand-in for the S3 wrapper used by the route.

    Accepts:
      - existing_keys: set of keys for which head_object succeeds
      - presign_fail_keys: set of keys for which presigned_get raises Exception

    Exposes:
      - client.head_object(...)
      - bucket attribute
      - presigned_get(...)
    Captures last call arguments for assertions.
    """
    def __init__(self, *, existing_keys=None, presign_fail_keys=None):
        self.client = self
        self.bucket = "unit-test"
        self.existing_keys = set(existing_keys or [])
        self.presign_fail_keys = set(presign_fail_keys or [])
        self.head_calls = []
        self.presign_calls = []

    # HEAD existence check
    def head_object(self, *, Bucket, Key):
        self.head_calls.append({"Bucket": Bucket, "Key": Key})
        if Key not in self.existing_keys:
            raise Exception("not found")

    # Presign GET
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
        if key in self.presign_fail_keys:
            raise Exception("presign failed")
        return f"https://signed.example/{key}?e={expires_in}"


# ─────────────────────────────────────────────────────────────
# App factory
# ─────────────────────────────────────────────────────────────

def _mk_app(
    monkeypatch,
    *,
    fake_s3: FakeS3,
    enforce_key: str | None = None,
    hashed: bool = False,
    settings_overrides: dict | None = None,
    sanitize_filename_impl=None,
):
    """
    Mount the delivery router and override:
      - rate_limit -> no-op
      - _s3 -> returns provided FakeS3
      - settings.(BATCH_DOWNLOAD_MAX_ITEMS, DELIVERY_MIN_TTL, DELIVERY_MAX_TTL) -> overrides or env
      - sanitize_filename -> optional custom impl for Content-Disposition
      - PUBLIC_API_KEY / PUBLIC_API_KEY_SHA256 (optional)
    """
    mod = importlib.import_module("app.api.v1.routers.delivery")

    # No-op rate limiter
    async def _no_rl(*_, **__): return None
    monkeypatch.setattr(mod, "rate_limit", _no_rl, raising=False)

    # Inject fake S3
    monkeypatch.setattr(mod, "_s3", lambda: fake_s3, raising=True)

    # Settings overrides or env fallback
    if settings_overrides is None:
        settings_overrides = {}
    monkeypatch.setattr(mod, "settings", SimpleNamespace(**settings_overrides), raising=True)

    # sanitize_filename hook (optional)
    if sanitize_filename_impl is not None:
        monkeypatch.setattr(mod, "sanitize_filename", sanitize_filename_impl, raising=True)

    # API key enforcement (optional)
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
    return app, client, mod


def _url():
    return "/api/v1/delivery/batch-download-urls"


# ─────────────────────────────────────────────────────────────
# Tests — happy path & per-item outcomes
# ─────────────────────────────────────────────────────────────

def test_batch_download_urls_mixed_results_and_no_store_headers(monkeypatch):
    existing = {
        "bundles/tt1/S01.zip",
        "downloads/ttX/extras/foo.zip",
        "bundles/tt1/S03.zip",  # exists but will fail on presign for internal_error case
    }
    fake_s3 = FakeS3(existing_keys=existing, presign_fail_keys={"bundles/tt1/S03.zip"})
    _app, client, _ = _mk_app(monkeypatch, fake_s3=fake_s3)

    payload = {
        "ttl_seconds": 600,
        "items": [
            {"storage_key": "bundles/tt1/S01.zip", "attachment_filename": "custom_S01.zip"},  # success
            {"storage_key": "bundles/tt1/S01.zip"},  # duplicate → ignored
            {"storage_key": "bundles/tt1/S01.txt"},  # forbidden (not .zip)
            {"storage_key": "bundles/tt1/S02.zip"},  # allowed but missing → not_found
            {"storage_key": "downloads/ttX/extras/foo.zip"},  # success
            {"storage_key": "bundles/tt1/S03.zip"},  # exists but presign fails → internal_error
        ],
    }

    r = client.post(_url(), json=payload)
    assert r.status_code == 200
    data = r.json()
    assert "results" in data and isinstance(data["results"], list)
    # There should be exactly len(items) result rows
    assert len(data["results"]) == len(payload["items"])

    # Check each indexed result
    # 0: success url
    assert data["results"][0]["index"] == 0
    assert "url" in data["results"][0]
    # Also verify Content-Disposition for first presign (uses provided filename)
    assert fake_s3.presign_calls[0]["content_disposition"] == 'attachment; filename="custom_S01.zip"'

    # 1: duplicate ignored
    assert data["results"][1] == {"index": 1, "storage_key": "bundles/tt1/S01.zip", "ignored": True}

    # 2: forbidden
    assert data["results"][2] == {"index": 2, "storage_key": "bundles/tt1/S01.txt", "error": "forbidden"}

    # 3: not found
    assert data["results"][3] == {"index": 3, "storage_key": "bundles/tt1/S02.zip", "error": "not_found"}

    # 4: success
    assert "url" in data["results"][4]
    assert fake_s3.presign_calls[-2]["key"] == "downloads/ttX/extras/foo.zip"

    # 5: internal_error
    assert data["results"][5] == {"index": 5, "storage_key": "bundles/tt1/S03.zip", "error": "internal_error"}

    # no-store cache headers applied on overall 200
    assert r.headers.get("Cache-Control") == "no-store"
    assert r.headers.get("Pragma") == "no-cache"
    assert r.headers.get("Expires") == "0"


# ─────────────────────────────────────────────────────────────
# Tests — envelope validation & limits
# ─────────────────────────────────────────────────────────────

def test_batch_download_urls_400_when_no_items(monkeypatch):
    fake_s3 = FakeS3()
    _app, client, _ = _mk_app(monkeypatch, fake_s3=fake_s3)

    r = client.post(_url(), json={"ttl_seconds": 600, "items": []})
    assert r.status_code == 400
    assert r.json()["detail"] == "No items provided"


def test_batch_download_urls_400_when_over_limit_from_settings(monkeypatch):
    fake_s3 = FakeS3()
    _app, client, _ = _mk_app(
        monkeypatch,
        fake_s3=fake_s3,
        settings_overrides={"BATCH_DOWNLOAD_MAX_ITEMS": 3},
    )

    r = client.post(
        _url(),
        json={
            "ttl_seconds": 600,
            "items": [{"storage_key": f"bundles/tt1/S0{i}.zip"} for i in range(1, 5)],  # 4 > 3
        },
    )
    assert r.status_code == 400
    assert "Too many items (max 3)" in r.json()["detail"]


def test_batch_download_urls_400_when_over_limit_from_env(monkeypatch):
    fake_s3 = FakeS3()
    _app, client, mod = _mk_app(
        monkeypatch,
        fake_s3=fake_s3,
        settings_overrides={},  # force env fallback
    )
    monkeypatch.setenv("BATCH_DOWNLOAD_MAX_ITEMS", "2")

    r = client.post(
        _url(),
        json={
            "ttl_seconds": 600,
            "items": [{"storage_key": "bundles/tt1/S01.zip"}, {"storage_key": "bundles/tt1/S02.zip"}, {"storage_key": "bundles/tt1/S03.zip"}],
        },
    )
    assert r.status_code == 400
    assert "Too many items (max 2)" in r.json()["detail"]


# ─────────────────────────────────────────────────────────────
# Tests — TTL clamp & filename sanitization
# ─────────────────────────────────────────────────────────────

def test_batch_download_urls_clamps_ttl_to_settings_bounds(monkeypatch):
    fake_s3 = FakeS3(existing_keys={"bundles/tt1/S01.zip"})
    _app, client, _ = _mk_app(
        monkeypatch,
        fake_s3=fake_s3,
        settings_overrides={"DELIVERY_MIN_TTL": 120, "DELIVERY_MAX_TTL": 180},
    )
    # Above max → clamped to 180
    r = client.post(
        _url(),
        json={"ttl_seconds": 999, "items": [{"storage_key": "bundles/tt1/S01.zip"}]},
    )
    assert r.status_code == 200
    assert fake_s3.presign_calls[-1]["expires_in"] == 180

    # Below min → clamped to 120
    r2 = client.post(
        _url(),
        json={"ttl_seconds": 60, "items": [{"storage_key": "bundles/tt1/S01.zip"}]},
    )
    assert r2.status_code == 200
    assert fake_s3.presign_calls[-1]["expires_in"] == 120


def test_batch_download_urls_sanitizes_attachment_filename(monkeypatch):
    fake_s3 = FakeS3(existing_keys={"bundles/tt1/S01.zip"})

    def _sanitize(name: str, fallback: str = "download.zip") -> str:
        return "safe_name.zip"

    _app, client, _ = _mk_app(
        monkeypatch,
        fake_s3=fake_s3,
        sanitize_filename_impl=_sanitize,
    )

    r = client.post(
        _url(),
        json={
            "ttl_seconds": 600,
            "items": [{"storage_key": "bundles/tt1/S01.zip", "attachment_filename": "../evil?.zip"}],
        },
    )
    assert r.status_code == 200
    disp = fake_s3.presign_calls[-1]["content_disposition"]
    assert disp == 'attachment; filename="safe_name.zip"'


# ─────────────────────────────────────────────────────────────
# Tests — API key enforcement
# ─────────────────────────────────────────────────────────────

def test_batch_download_urls_api_key_enforcement_plain_and_hashed(monkeypatch):
    for hashed in (False, True):
        key = "sekret123"
        fake_s3 = FakeS3(existing_keys={"bundles/tt1/S01.zip"})
        _app, client, _ = _mk_app(
            monkeypatch,
            fake_s3=fake_s3,
            enforce_key=key,
            hashed=hashed,
        )

        r1 = client.post(_url(), json={"ttl_seconds": 600, "items": [{"storage_key": "bundles/tt1/S01.zip"}]})
        assert r1.status_code == 401

        r2 = client.post(
            _url(),
            json={"ttl_seconds": 600, "items": [{"storage_key": "bundles/tt1/S01.zip"}]},
            headers={"X-API-Key": key},
        )
        assert r2.status_code == 200

        r3 = client.post(
            _url() + f"?api_key={key}",
            json={"ttl_seconds": 600, "items": [{"storage_key": "bundles/tt1/S01.zip"}]},
        )
        assert r3.status_code == 200
