import importlib
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _mk_app(monkeypatch):
    mod = importlib.import_module("app.api.v1.routers.public.schedule")

    # No-op deps
    async def _no_rate_limit(*_, **__): return None
    async def _no_key(*_, **__): return None
    monkeypatch.setattr(mod, "rate_limit", _no_rate_limit, raising=False)
    monkeypatch.setattr(mod, "enforce_public_api_key", _no_key, raising=False)

    # Return a small schedule without touching DB
    from app.api.v1.routers.public.schedule import ScheduleResponse, ScheduleItem

    async def _fake_query(request, db, *, country, days, type_filter, only_worldwide, limit):
        return ScheduleResponse(items=[
            ScheduleItem(id="t1", type="MOVIE", name="X", slug="x", release_at=1700000000, region=(country or ""), is_worldwide=bool(only_worldwide), poster_url=None, trailer_url=None),
        ], total=1)

    monkeypatch.setattr(mod, "_query_upcoming", _fake_query, raising=True)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")
    return app, TestClient(app)


def test_upcoming_and_worldwide(monkeypatch):
    app, client = _mk_app(monkeypatch)

    r1 = client.get("/api/v1/schedule/upcoming?country=IN&days=7")
    assert r1.status_code == 200
    body1 = r1.json()
    assert body1.get("total") == 1
    assert isinstance(body1.get("items"), list)

    r2 = client.get("/api/v1/schedule/worldwide?days=14")
    assert r2.status_code == 200
    body2 = r2.json()
    assert body2.get("total") == 1

