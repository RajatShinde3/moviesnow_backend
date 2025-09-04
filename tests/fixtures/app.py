# tests/fixtures/app.py

"""
🧩 App Fixture:
- Builds test FastAPI app instance
- Injects test-specific DB session
- Returns HTTP client fixture for integration tests
"""

import pytest
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.middleware.cors import CORSMiddleware
from httpx import AsyncClient, ASGITransport
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_async_db
from tests.fixtures.db import get_override_get_db

# Routers to include
from app.api.v1.routers.auth import (
    signup, login, refresh_logout, account_deactivation,
    email_verification, password_reset, mfa, mfa_reset,
    account_deletion, reactivation, reauth, recovery_codes,
    trusted_devices, sessions, activity, credentials,
)

from app.api.v1.routers.admin.assets import (
    artwork, bulk, cdn_delivery, meta, video,
    streams, subtitles, trailers, uploads, validation,
)

from app.api.v1.routers.admin import (
    api_keys, auth, bundles, series, sessions as session_main, staff, 
    taxonomy, titles,
)
@pytest.fixture()
async def app(db_session: AsyncSession) -> FastAPI:
    """
    🧪 Creates an instance of the FastAPI app with test-specific DB session.
    """
    app = FastAPI()

    # 🔄 Add CORS (typically not needed in tests but matches production behavior)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ✅ Include all routers (simulates production)
    app.include_router(signup.router, prefix="/api/v1/auth")
    app.include_router(login.router, prefix="/api/v1/auth")
    app.include_router(refresh_logout.router, prefix="/api/v1/auth")
    app.include_router(account_deactivation.router, prefix="/api/v1/auth")
    app.include_router(email_verification.router, prefix="/api/v1/auth")
    app.include_router(password_reset.router, prefix="/api/v1/auth")
    app.include_router(mfa.router, prefix="/api/v1/auth")
    app.include_router(mfa_reset.router, prefix="/api/v1/auth")
    app.include_router(reauth.router, prefix="/api/v1/auth")
    app.include_router(recovery_codes.router, prefix="/api/v1/auth")
    app.include_router(account_deletion.router, prefix="/api/v1/auth")
    app.include_router(reactivation.router, prefix="/api/v1/auth")
    app.include_router(trusted_devices.router, prefix="/api/v1/auth")
    app.include_router(sessions.router, prefix="/api/v1/auth")
    app.include_router(activity.router, prefix="/api/v1/auth")
    app.include_router(credentials.router, prefix="/api/v1/auth")

    app.include_router(artwork.router, prefix="/api/v1/admin")
    app.include_router(bulk.router, prefix="/api/v1/admin")
    app.include_router(cdn_delivery.router, prefix="/api/v1/admin")
    app.include_router(meta.router, prefix="/api/v1/admin")
    app.include_router(streams.router, prefix="/api/v1/admin")
    app.include_router(subtitles.router, prefix="/api/v1/admin")
    app.include_router(trailers.router, prefix="/api/v1/admin")
    app.include_router(uploads.router, prefix="/api/v1/admin")
    app.include_router(validation.router, prefix="/api/v1/admin")
    app.include_router(video.router, prefix="/api/v1/admin")

    app.include_router(api_keys.router, prefix="/api/v1/admin")
    app.include_router(auth.router, prefix="/api/v1/admin")
    app.include_router(bundles.router, prefix="/api/v1/admin")
    app.include_router(series.router, prefix="/api/v1/admin")
    app.include_router(session_main.router, prefix="/api/v1/admin")
    app.include_router(staff.router, prefix="/api/v1/admin")
    app.include_router(taxonomy.router, prefix="/api/v1/admin")
    app.include_router(titles.router, prefix="/api/v1/admin")

    # 🔁 Override DB dependency with isolated test session
    app.dependency_overrides[get_async_db] = get_override_get_db(db_session)

    return app

class InjectOrgContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        x_org_id = request.headers.get("X-Org-ID")
        if x_org_id:
            request.state.org_id = x_org_id
        return await call_next(request)


@pytest.fixture()
async def async_client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """
    🌐 Provides an HTTP client for sending requests to the test app.
    Adds test-only middleware to simulate org context injection.
    """
    app.add_middleware(InjectOrgContextMiddleware)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
