import importlib
import uuid
from datetime import datetime, timezone
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


class _FakeDB:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.commits = 0
        self.flushes = 0
        self.added = []
    async def execute(self, *_a, **_k):
        return _FakeResult(self.rows)
    async def commit(self):
        self.commits += 1
    async def flush(self):
        self.flushes += 1
    def add(self, obj):
        self.added.append(obj)


class Variant:
    def __init__(self, *, url_path: str, has_flag: bool = True, is_downloadable: bool = False):
        self.id = uuid.uuid4()
        self.url_path = url_path
        if has_flag:
            self.is_downloadable = is_downloadable


def _mk_app(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.admin.downloads")

    # No-op rate limit and gates
    async def _no_rate_limit(*_, **__): return None
    async def _ok(*_, **__): return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)
    monkeypatch.setattr(mod, "_ensure_admin", _ok, raising=False)
    monkeypatch.setattr(mod, "_ensure_mfa", _ok, raising=False)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1/admin")
    return app, mod


def test_toggle_downloadable_happy(monkeypatch):
    app, mod = _mk_app(monkeypatch)
    v = Variant(url_path="downloads/tt1/file.mp4", has_flag=True, is_downloadable=False)
    db = _FakeDB(rows=[v])
    monkeypatch.setattr(mod, "get_async_db", lambda: db, raising=False)

    c = TestClient(app)
    r = c.patch(f"/api/v1/admin/streams/{v.id}/toggle-downloadable")
    assert r.status_code == 200
    assert r.json().get("variant_id") == str(v.id)
    assert r.json().get("is_downloadable") is True


def test_title_downloads_inventory_simple_match(monkeypatch):
    app, mod = _mk_app(monkeypatch)
    tid = uuid.uuid4()
    v = Variant(url_path=f"downloads/{tid}/a.mp4")
    db = _FakeDB(rows=[v])
    monkeypatch.setattr(mod, "get_async_db", lambda: db, raising=False)

    # Fake S3 listing
    class _Client:
        def list_objects_v2(self, **kwargs):
            return {
                "Contents": [
                    {
                        "Key": f"downloads/{tid}/a.mp4",
                        "Size": 10,
                        "LastModified": datetime(2024, 1, 1, tzinfo=timezone.utc),
                        "ETag": "etag",
                    }
                ]
            }
    class _S3:
        def __init__(self): self.client = _Client(); self.bucket = "b"
    monkeypatch.setattr(mod, "S3Client", _S3, raising=False)

    c = TestClient(app)
    r = c.get(f"/api/v1/admin/titles/{tid}/downloads/inventory")
    assert r.status_code == 200
    body = r.json()
    assert body.get("title_id") == str(tid)
    assert body.get("counts", {}).get("matches") == 1


def test_register_title_download_created(monkeypatch):
    app, mod = _mk_app(monkeypatch)
    tid = uuid.uuid4()

    # Fake DB path: first Title exists, then no existing variant -> create
    class _Title:
        id = object()
    class _Asset:
        def __init__(self): self.id = uuid.uuid4(); self.storage_key = None

    created_variant = Variant(url_path=f"downloads/{tid}/v.mp4")

    async def _get_or_create_asset_for_title(db, title_id, storage_key):
        return _Asset()
    async def _upsert_variant(db, asset, payload):
        db.add(created_variant)
        await db.flush()
        return created_variant, True

    monkeypatch.setattr(mod, "_get_or_create_asset_for_title", _get_or_create_asset_for_title, raising=True)
    monkeypatch.setattr(mod, "_upsert_variant", _upsert_variant, raising=True)

    db = _FakeDB(rows=[_Title()])
    monkeypatch.setattr(mod, "get_async_db", lambda: db, raising=False)

    # S3 HEAD best-effort -> None; avoid real libs
    monkeypatch.setattr(mod, "_best_effort_s3_head", lambda key: None, raising=False)

    c = TestClient(app)
    r = c.post(
        f"/api/v1/admin/titles/{tid}/downloads/register",
        json={"storage_key": f"downloads/{tid}/v.mp4", "width": 1920, "height": 1080},
    )
    assert r.status_code in (200, 201)
    body = r.json()
    assert body.get("storage_key", "").startswith("downloads/")

