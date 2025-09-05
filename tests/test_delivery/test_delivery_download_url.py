# tests/test_public/test_delivery/test_download_url.py

import importlib
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

    Exposes:
      - client.head_object(...)
      - bucket attribute
      - presigned_get(...)
    Captures last call arguments for assertions.
    """
    def __init__(self, *, head_ok=True, raise_on_presign: Exception | None = None):
        self.client = self
        self.bucket = "unit-test-bucket"
        self._head_ok = head_ok
        self._raise_on_presign = raise_on_presign
        self.head_calls = []
        self.presign_calls = []

    # Head existence check
    def head_object(self, *, Bucket, Key):
        self.head_calls.append({"Bucket": Bucket, "Key": Key})
        if not self._head_ok:
            raise Exception("not found")  # route treats any Exception as 404

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
        if self._raise_on_presign:
            raise self._raise_on_presign
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
      - S3StorageError -> FakeStorageError
      - settings.(DELIVERY_MIN_TTL, DELIVERY_MAX_TTL) -> from settings_overrides or env fallback
      - sanitize_filename -> optional custom impl for content-disposition tests
      - PUBLIC_API_KEY / PUBLIC_API_KEY_SHA256 (optional)
    """
    mod = importlib.import_module("app.api.v1.routers.delivery")

    # No-op rate limiter
    async def _no_rl(*_, **__): return None
    monkeypatch.setattr(mod, "rate_limit", _no_rl, raising=False)

    # Inject fake S3 & error class
    monkeypatch.setattr(mod, "_s3", lambda: fake_s3, raising=True)
    monkeypatch.setattr(mod, "S3StorageError", FakeStorageError, raising=True)

    # Settings overrides or env fallback
    if settings_overrides is None:
        settings_overrides = {}
    monkeypatch.setattr(
        mod,
        "settings",
        SimpleNamespace(**settings_overrides),
        raising=True,
    )

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
    return "/api/v1/delivery/download-url"


# ─────────────────────────────────────────────────────────────
# Tests — happy path
# ─────────────────────────────────────────────────────────────

def test_download_url_happy_path_bundles_key_presigns_and_sets_no_store(monkeypatch):
    fake_s3 = FakeS3(head_ok=True)
    _app, client, mod = _mk_app(monkeypatch, fake_s3=fake_s3)

    payload = {
        "storage_key": "bundles/tt123/S01.zip",
        "ttl_seconds": 600,
        "attachment_filename": "S01.zip",
    }
    r = client.post(_url(), json=payload)
    assert r.status_code == 200

    body = r.json()
    assert "url" in body and body["url"].startswith("https://signed.example/bundles/tt123/S01.zip")

    # HEAD + presign called with expected args
    assert fake_s3.head_calls and fake_s3.head_calls[0]["Key"] == "bundles/tt123/S01.zip"
    assert fake_s3.presign_calls
    pc = fake_s3.presign_calls[0]
    assert pc["key"] == "bundles/tt123/S01.zip"
    assert pc["expires_in"] == 600
    assert pc["content_disposition"] == 'attachment; filename="S01.zip"'
    assert pc["content_type"] == "application/zip"

    # no-store cache headers applied
    assert r.headers.get("Cache-Control") == "no-store"
    assert r.headers.get("Pragma") == "no-cache"
    assert r.headers.get("Expires") == "0"


def test_download_url_allows_downloads_extras_path(monkeypatch):
    fake_s3 = FakeS3(head_ok=True)
    _app, client, mod = _mk_app(monkeypatch, fake_s3=fake_s3)

    payload = {
        "storage_key": "downloads/tt123/extras/behind_the_scenes.zip",
        "ttl_seconds": 700,
    }
    r = client.post(_url(), json=payload)
    assert r.status_code == 200
    pc = fake_s3.presign_calls[0]
    assert pc["key"] == "downloads/tt123/extras/behind_the_scenes.zip"
    assert pc["expires_in"] == 700
    # fallback filename derived from key tail
    assert pc["content_disposition"] == 'attachment; filename="behind_the_scenes.zip"'


# ─────────────────────────────────────────────────────────────
# Tests — validation & authorization
# ─────────────────────────────────────────────────────────────

def test_download_url_rejects_invalid_storage_key_400(monkeypatch):
    fake_s3 = FakeS3()
    _app, client, _ = _mk_app(monkeypatch, fake_s3=fake_s3)

    bad_keys = [
        "", "  ", "/bundles/tt123/S01.zip", "bundles/tt123/../S01.zip", "bundles/tt 123/S01.zip", "not/zip.txt"
    ]
    for k in bad_keys:
        # the non-zip still fails first by regex/format (space) or will be caught by 403 later;
        # use an obviously invalid one for 400
        payload = {"storage_key": k, "ttl_seconds": 600}
        r = client.post(_url(), json=payload)
        # keys with bad chars/leading slash/traversal → 400; non-zip but otherwise valid → 403 below
        if k in ("not/zip.txt",):
            assert r.status_code in (400, 403)
        else:
            assert r.status_code == 400


def test_download_url_forbidden_when_not_allowed_area_403(monkeypatch):
    fake_s3 = FakeS3()
    _app, client, _ = _mk_app(monkeypatch, fake_s3=fake_s3)

    # Valid-looking key but outside allowed prefixes/patterns
    payloads = [
        {"storage_key": "downloads/tt123/season1/video.zip", "ttl_seconds": 600},  # no /extras/
        {"storage_key": "images/posters/tt123.zip", "ttl_seconds": 600},           # wrong prefix
        {"storage_key": "bundles/tt123/S01.txt", "ttl_seconds": 600},              # not a .zip
    ]
    for p in payloads:
        r = client.post(_url(), json=p)
        assert r.status_code == 403
        assert r.json()["detail"].startswith("Downloads are restricted")


def test_download_url_404_on_missing_object(monkeypatch):
    fake_s3 = FakeS3(head_ok=False)
    _app, client, _ = _mk_app(monkeypatch, fake_s3=fake_s3)

    r = client.post(_url(), json={"storage_key": "bundles/tt999/S01.zip", "ttl_seconds": 600})
    assert r.status_code == 404
    assert r.json()["detail"] == "File not found"


def test_download_url_503_on_presign_failure(monkeypatch):
    fake_s3 = FakeS3(head_ok=True, raise_on_presign=FakeStorageError("s3 down"))
    _app, client, _ = _mk_app(monkeypatch, fake_s3=fake_s3)

    r = client.post(_url(), json={"storage_key": "bundles/tt123/S01.zip", "ttl_seconds": 600})
    assert r.status_code == 503
    assert r.json()["detail"] == "s3 down"


def test_download_url_api_key_enforcement_plain_and_hashed(monkeypatch):
    for hashed in (False, True):
        key = "sekret123"
        fake_s3 = FakeS3(head_ok=True)
        _app, client, _ = _mk_app(monkeypatch, fake_s3=fake_s3, enforce_key=key, hashed=hashed)

        # missing key → 401
        r1 = client.post(_url(), json={"storage_key": "bundles/tt123/S01.zip", "ttl_seconds": 600})
        assert r1.status_code == 401

        # header key works
        r2 = client.post(
            _url(),
            json={"storage_key": "bundles/tt123/S01.zip", "ttl_seconds": 600},
            headers={"X-API-Key": key},
        )
        assert r2.status_code == 200

        # query param key works
        r3 = client.post(
            _url() + f"?api_key={key}",
            json={"storage_key": "bundles/tt123/S01.zip", "ttl_seconds": 600},
        )
        assert r3.status_code == 200


# ─────────────────────────────────────────────────────────────
# Tests — TTL clamp & filename sanitization
# ─────────────────────────────────────────────────────────────

def test_download_url_clamps_ttl_to_settings_bounds(monkeypatch):
    # Settings clamp: min=120, max=180
    fake_s3 = FakeS3(head_ok=True)
    _app, client, mod = _mk_app(
        monkeypatch,
        fake_s3=fake_s3,
        settings_overrides={"DELIVERY_MIN_TTL": 120, "DELIVERY_MAX_TTL": 180},
    )

    # Above max → clamped to 180
    r1 = client.post(_url(), json={"storage_key": "bundles/tt123/S01.zip", "ttl_seconds": 999})
    assert r1.status_code == 200
    assert fake_s3.presign_calls[-1]["expires_in"] == 180

    # Below min → clamped to 120
    r2 = client.post(_url(), json={"storage_key": "bundles/tt123/S02.zip", "ttl_seconds": 60})
    assert r2.status_code == 200
    assert fake_s3.presign_calls[-1]["expires_in"] == 120


def test_download_url_clamps_ttl_via_env_when_settings_missing(monkeypatch):
    # No attributes on settings → falls back to env
    fake_s3 = FakeS3(head_ok=True)
    _app, client, mod = _mk_app(
        monkeypatch,
        fake_s3=fake_s3,
        settings_overrides={},  # empty -> getattr(..., os.environ[...])
    )
    monkeypatch.setenv("DELIVERY_MIN_TTL", "300")
    monkeypatch.setenv("DELIVERY_MAX_TTL", "300")

    r = client.post(_url(), json={"storage_key": "bundles/ttX/S01.zip", "ttl_seconds": 60})
    assert r.status_code == 200
    assert fake_s3.presign_calls[-1]["expires_in"] == 300


def test_download_url_uses_sanitized_attachment_filename_when_provided(monkeypatch):
    fake_s3 = FakeS3(head_ok=True)

    def _sanitize(name: str, fallback: str = "download.zip") -> str:
        # Simulate strong sanitization (strip path & weird chars)
        return "safe_name.zip"

    _app, client, _ = _mk_app(
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
    assert disp == 'attachment; filename="safe_name.zip"'


def test_download_url_derives_filename_from_key_when_not_provided(monkeypatch):
    fake_s3 = FakeS3(head_ok=True)
    _app, client, _ = _mk_app(monkeypatch, fake_s3=fake_s3)

    r = client.post(
        _url(),
        json={"storage_key": "bundles/ttX/Season_01.zip", "ttl_seconds": 600},
    )
    assert r.status_code == 200
    disp = fake_s3.presign_calls[-1]["content_disposition"]
    assert disp == 'attachment; filename="Season_01.zip"'
