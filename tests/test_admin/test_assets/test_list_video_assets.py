# tests/test_admin/test_assets/test_list_video_assets.py

import uuid
from typing import Any, List, Optional, Tuple, Callable
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

# Import the actual route module (keeps mapped SQLAlchemy models intact)
from app.api.v1.routers.admin.assets import video as mod


# ─────────────────────────────────────────────────────────────────────────────
# Tiny async-session fake that returns canned rows for .execute()
# ─────────────────────────────────────────────────────────────────────────────

class _Scalars:
    def __init__(self, items: List[Any]): self._items = items
    def all(self): return self._items

class _Result:
    def __init__(self, items: List[Any]): self._items = items
    def scalars(self): return _Scalars(self._items)

class FakeDB:
    """Provide successive result chunks matching each .execute() call."""
    def __init__(self, chunks: List[List[Any]]):
        self._chunks = list(chunks)
        self.exec_calls: int = 0
        self.last_query = None

    async def execute(self, query, *_a, **_k):
        self.exec_calls += 1
        self.last_query = query
        return _Result(self._chunks.pop(0) if self._chunks else [])

# Simple row holder mirroring fields used by the route’s projection
class AssetRow:
    def __init__(
        self,
        *,
        id: Optional[uuid.UUID] = None,
        language: Optional[str] = None,
        storage_key: Optional[str] = None,
        is_primary: bool = False,
        metadata_json: Optional[dict] = None,
        cdn_url: Optional[str] = None,
        created_at: Optional[str] = None,  # keep JSON-serializable for JSONResponse
    ):
        self.id = id or uuid.uuid4()
        self.language = language
        self.storage_key = storage_key
        self.is_primary = is_primary
        self.metadata_json = metadata_json
        self.cdn_url = cdn_url
        self.created_at = created_at


# ─────────────────────────────────────────────────────────────────────────────
# App factory (bypasses rate limit, overrides DB + auth deps)
# ─────────────────────────────────────────────────────────────────────────────

async def _noop(*_a, **_k): return None
async def _raise_403(*_a, **_k): raise HTTPException(status_code=403, detail="Forbidden")
async def _raise_401(*_a, **_k): raise HTTPException(status_code=401, detail="MFA required")

class _User: id = uuid.uuid4()

def _mk_app(
    db: FakeDB,
    monkeypatch,
    *,
    ensure_admin=_noop,
    ensure_mfa=_noop,
) -> Tuple[FastAPI, TestClient]:
    # Disable rate limiting in tests (route uses @rate_limit("30/minute"))
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_TEST_BYPASS", "1")

    # Patch lazy-imported admin/MFA checks (the handler imports inside the function)
    monkeypatch.setattr("app.dependencies.admin.ensure_admin", ensure_admin, raising=False)
    monkeypatch.setattr("app.dependencies.admin.ensure_mfa", ensure_mfa, raising=False)

    app = FastAPI()
    app.include_router(mod.router)  # router already has prefix="/api/v1/admin"

    # Dependency overrides
    app.dependency_overrides[mod.get_async_db] = lambda: db
    app.dependency_overrides[mod.get_current_user] = lambda: _User()

    return app, TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_list_video_empty_returns_empty_array_and_no_store_headers(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[]])  # no assets for this title
    app, client = _mk_app(db, monkeypatch)

    r = client.get(f"/api/v1/admin/titles/{title_id}/video")
    assert r.status_code == 200
    assert r.json() == []

    # strict no-store headers via _json()
    assert r.headers.get("Cache-Control", "").startswith("no-store")
    assert r.headers.get("Pragma") == "no-cache"


def test_list_video_projects_compact_fields(monkeypatch):
    title_id = uuid.uuid4()
    rows = [
        AssetRow(language="en", storage_key="s3://bucket/a.mp4", is_primary=True,
                 metadata_json={"label": "Theatrical"}, cdn_url="https://cdn/a.mp4"),
        AssetRow(language="hi", storage_key="s3://bucket/b.mp4", is_primary=False,
                 metadata_json={"label": "Dub"}, cdn_url=None),
    ]
    db = FakeDB([rows])
    app, client = _mk_app(db, monkeypatch)

    r = client.get(f"/api/v1/admin/titles/{title_id}/video")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list) and len(data) == 2

    def expect(row: AssetRow) -> dict:
        return {
            "id": str(row.id),
            "language": row.language,
            "storage_key": row.storage_key,
            "is_primary": row.is_primary,
            "label": (row.metadata_json or {}).get("label"),
            "cdn_url": row.cdn_url,
            "created_at": row.created_at,
        }

    assert data[0] == expect(rows[0])
    assert data[1] == expect(rows[1])


def test_list_video_query_bounds_validation(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[]])
    app, client = _mk_app(db, monkeypatch)

    # limit below min → 422
    assert client.get(f"/api/v1/admin/titles/{title_id}/video?limit=0").status_code == 422
    # limit above max → 422
    assert client.get(f"/api/v1/admin/titles/{title_id}/video?limit=201").status_code == 422
    # offset negative → 422
    assert client.get(f"/api/v1/admin/titles/{title_id}/video?offset=-1").status_code == 422
    # valid upper bound passes
    assert client.get(f"/api/v1/admin/titles/{title_id}/video?limit=200&offset=0").status_code == 200


def test_list_video_requires_admin(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[]])
    app, client = _mk_app(db, monkeypatch, ensure_admin=_raise_403, ensure_mfa=_noop)

    r = client.get(f"/api/v1/admin/titles/{title_id}/video")
    assert r.status_code == 403
    assert r.json()["detail"] == "Forbidden"


def test_list_video_requires_mfa(monkeypatch):
    title_id = uuid.uuid4()
    db = FakeDB([[]])
    app, client = _mk_app(db, monkeypatch, ensure_admin=_noop, ensure_mfa=_raise_401)

    r = client.get(f"/api/v1/admin/titles/{title_id}/video")
    assert r.status_code == 401
    assert r.json()["detail"] == "MFA required"
