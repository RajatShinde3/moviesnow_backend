import importlib
import uuid
from fastapi import FastAPI
from fastapi.testclient import TestClient


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows
    def scalars(self):
        class _S:
            def __init__(self, rows): self._rows = rows
            def all(self): return list(self._rows)
            def first(self): return self._rows[0] if self._rows else None
        return _S(self._rows)


class Variant:
    def __init__(self, *, url_path: str, height: int = 1080, width: int = 1920, bandwidth_bps: int = 2000000):
        self.url_path = url_path
        self.height = height
        self.width = width
        self.bandwidth_bps = bandwidth_bps
        class _Enum:  # minimal container/codec enums
            def __init__(self, name): self.name = name
        self.container = _Enum("MP4")
        self.video_codec = _Enum("H264")
        self.audio_codec = _Enum("AAC")
        self.media_asset = type("MA", (), {"checksum_sha256": None})()


class _FakeDB:
    def __init__(self, rows):
        self.rows = rows
    async def execute(self, *_a, **_k):
        return _FakeResult(self.rows)


def _mk_app(monkeypatch, *, variants):
    mod = importlib.import_module("app.api.v1.routers.public.downloads")

    # No-op deps
    async def _no_rate_limit(*_, **__): return None
    async def _no_key(*_, **__): return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)
    monkeypatch.setattr(mod, "enforce_public_api_key", _no_key, raising=False)

    # Fake DB
    db = _FakeDB(variants)
    monkeypatch.setattr(mod, "get_async_db", lambda: db, raising=False)

    # Avoid touching redis/s3 head cache in tests
    class _S3:
        def __init__(self): self.client = type("C", (), {})()
    monkeypatch.setattr(mod, "S3Client", _S3, raising=False)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")
    return app, TestClient(app)


def test_title_download_manifest_basic(monkeypatch):
    tid = uuid.uuid4()
    v = Variant(url_path=f"downloads/{tid}/movie.mp4")
    app, client = _mk_app(monkeypatch, variants=[v])

    r = client.get(f"/api/v1/titles/{tid}/download-manifest")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("title_id") == str(tid)
    assert isinstance(body.get("items"), list)


def test_episode_download_manifest_basic(monkeypatch):
    tid = uuid.uuid4()
    eid = uuid.uuid4()
    v = Variant(url_path=f"downloads/{tid}/{eid}/ep1.mp4")
    app, client = _mk_app(monkeypatch, variants=[v])

    r = client.get(f"/api/v1/titles/{tid}/episodes/{eid}/download-manifest")
    assert r.status_code == 200
    b = r.json()
    assert b.get("title_id") == str(tid) and b.get("episode_id") == str(eid)
