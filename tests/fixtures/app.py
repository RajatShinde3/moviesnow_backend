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
from app.api.v1.courses import enrollment
from app.db.session import get_async_db
from tests.fixtures.db import get_override_get_db

# Routers to include
from app.api.v1.auth import (
    signup, login, refresh_logout, account_deactivation,
    email_verification, password_reset, mfa, mfa_reset,
    account_deletion, reactivation, reauth, recovery_codes,
    trusted_devices,
)
from app.api.v1.routes.orgs import (
    org_management, org_admin, org_audit, org_invite, org_member,
    org_settings, org_tokens
)
from app.api.v1.routes import organization
from app.api.v1 import (
    enterprise_profile, user_profile, org_user_profile
)
from app.api.v1.courses import (
    lessons, ordering, unlocks, graph, matrix, stats, 
    exports, categories, certificate, crud as courses_crud, enrollment, listing,
    search, views
)
from app.api.v1.courses.dashboards import user, org

from app.api.v1.lessons import (
    crud as lessons_crud, paths, progress, relations, unlocks
)

from app.api.v1.progress import progress as progress_crud

from app.api.v1.course.live import (
    analytics, security, sessions, feedback
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

    app.include_router(org_management.router, prefix="/api/v1/org")
    app.include_router(org_admin.router, prefix="/api/v1/org/admin")
    app.include_router(org_audit.router, prefix="/api/v1/org") 
    app.include_router(org_invite.router, prefix="/api/v1/org")
    app.include_router(org_member.router, prefix="/api/v1/org/member")
    app.include_router(org_settings.router, prefix="/api/v1/org/settings")
    app.include_router(org_tokens.router, prefix="/api/v1/org/token")
    app.include_router(organization.router, prefix="/api/v1/org")
    app.include_router(enterprise_profile.router, prefix="/api/v1/org/enterprise")
    app.include_router(user_profile.router, prefix="/api/v1/user")
    app.include_router(org_user_profile.router, prefix="/api/v1/org/user")
    app.include_router(courses_crud.router, prefix="/api/v1/courses")
    app.include_router(lessons.router, prefix="/api/v1/courses")
    app.include_router(enrollment.router, prefix="/api/v1/courses")
    app.include_router(unlocks.router, prefix="/api/v1/courses")
    app.include_router(ordering.router, prefix="/api/v1/courses")
    app.include_router(graph.router, prefix="/api/v1/courses")
    app.include_router(matrix.router, prefix="/api/v1/courses")
    app.include_router(stats.router, prefix="/api/v1/courses")
    app.include_router(exports.router, prefix="/api/v1/courses")
    app.include_router(categories.router, prefix="/api/v1/courses")
    app.include_router(certificate.router, prefix="/api/v1/courses")
    app.include_router(listing.router, prefix="/api/v1/courses")
    app.include_router(search.router, prefix="/api/v1/courses")
    app.include_router(views.router, prefix="/api/v1/courses")
    app.include_router(user.router, prefix="/api/v1/org/dashboard")
    app.include_router(org.router, prefix="/api/v1/dashboard")
    app.include_router(paths.router, prefix="/api/v1/lessons")
    app.include_router(progress.router, prefix="/api/v1/lessons")
    app.include_router(relations.router, prefix="/api/v1/lessons")
    app.include_router(lessons_crud.router, prefix="/api/v1/lessons")
    app.include_router(unlocks.router, prefix="/api/v1/lessons")
    app.include_router(progress_crud.router, prefix="/api/v1/progress")
    app.include_router(analytics.router, prefix="/api/v1/course/live/analytics")
    app.include_router(feedback.router, prefix="/api/v1/course/live/feedback")
    app.include_router(sessions.router, prefix="/api/v1/course/live/session")
    app.include_router(security.router, prefix="/api/v1/course/live/security")




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
