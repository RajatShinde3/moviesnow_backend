from __future__ import annotations

import pytest
from typing import Callable, Awaitable, Dict, Tuple, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.user import User
from app.core.security import create_access_token
from tests.utils.factory import create_user


# ─────────────────────────────────────────────────────────────
# 🔐 Token + Auth Fixtures (MoviesNow: no organizations)
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def user_with_token(db_session: AsyncSession) -> Callable[..., Awaitable[Tuple[User, str]]]:
    """
    Create (or reuse by email) a test user and return (user, jwt_token).
    """
    async def _create(**kwargs) -> Tuple[User, str]:
        email: Optional[str] = kwargs.get("email")
        user: Optional[User] = None

        if email:
            existing = (
                await db_session.execute(select(User).where(User.email == email))
            ).scalar_one_or_none()
            user = existing or await create_user(session=db_session, **kwargs)
        else:
            user = await create_user(session=db_session, **kwargs)

        await db_session.commit()
        await db_session.refresh(user)

        token = await create_access_token(user_id=str(user.id))
        return user, token

    return _create


@pytest.fixture
def user_with_headers(user_with_token) -> Callable[..., Awaitable[Tuple[User, Dict[str, str]]]]:
    """
    Same as user_with_token but returns (user, headers) with a Bearer token.
    """
    async def _create(**kwargs) -> Tuple[User, Dict[str, str]]:
        user, token = await user_with_token(**kwargs)
        return user, {"Authorization": f"Bearer {token}"}
    return _create


@pytest.fixture
async def superuser_token_headers(db_session: AsyncSession) -> Dict[str, str]:
    """
    Create a superuser and return ready-to-use Authorization headers.
    """
    user = await create_user(
        session=db_session,
        email="superadmin@example.com",
        full_name="Super Admin",
        is_superuser=True,
        is_verified=True,
        is_active=True,
    )
    await db_session.commit()
    await db_session.refresh(user)
    token = await create_access_token(user_id=str(user.id))
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def auth_headers() -> Callable[[User], Callable[[], Awaitable[Dict[str, str]]]]:
    """
    Returns a function that, given a User, yields headers with a fresh JWT.
    Usage:
        headers = await auth_headers(user)()
    """
    def _for(user: User):
        async def _headers() -> Dict[str, str]:
            token = await create_access_token(user_id=str(user.id))
            return {"Authorization": f"Bearer {token}"}
        return _headers
    return _for
