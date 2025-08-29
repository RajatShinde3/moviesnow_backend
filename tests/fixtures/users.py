from __future__ import annotations

import pytest
from uuid import uuid4
from datetime import datetime, timezone
from typing import Callable, Awaitable, Tuple, Optional

from pyotp import random_base32
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, get_password_hash
from app.db.models.user import User          
from tests.utils.factory import create_user  

# ──────────────────────────────────────────────────────────────
# 🧪 Factory: Create or Reuse Test User (by email)
# ──────────────────────────────────────────────────────────────
@pytest.fixture
def create_test_user(db_session: AsyncSession) -> Callable[..., Awaitable[User]]:
    """
    Create or fetch a test user by email (idempotent if email already exists).
    """
    async def _create(**kwargs) -> User:
        email = (kwargs.get("email") or f"test_{uuid4().hex}@example.com").lower()
        kwargs["email"] = email

        existing_user = (
            await db_session.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
        if existing_user:
            return existing_user

        user = await create_user(session=db_session, **kwargs)
        if user is None:
            raise RuntimeError("create_user returned None")
        await db_session.commit()
        await db_session.refresh(user)
        return user

    return _create


# ──────────────────────────────────────────────────────────────
# 🔑 Factory: Create Normal User with Token
# ──────────────────────────────────────────────────────────────
@pytest.fixture
def create_user_normal(db_session: AsyncSession) -> Callable[..., Awaitable[User]]:
    """
    Create a verified, active user and attach a convenient JWT at `user.token`.
    """
    async def _create_user(
        email: Optional[str] = None,
        password: str = "password",
        is_verified: bool = True,
    ) -> User:
        user = User(
            email=(email or f"testuser_{uuid4().hex[:8]}@example.com").lower(),
            hashed_password=get_password_hash(password),
            is_active=True,
            is_verified=is_verified,
            created_at=datetime.now(timezone.utc),
        )

        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Convenience for tests
        user.token = await create_access_token(user_id=str(user.id))  # ✅ ensure str
        return user

    return _create_user


# ──────────────────────────────────────────────────────────────
# 👑 Superadmin Fixture
# ──────────────────────────────────────────────────────────────
@pytest.fixture
async def superadmin_user(create_test_user: Callable[..., Awaitable[User]]) -> User:
    """
    Create (or reuse) a superuser for admin-path tests.
    """
    return await create_test_user(
        email="superadmin@example.com",
        full_name="Super Admin",
        is_superuser=True,
        is_verified=True,
        is_active=True,
    )


# ──────────────────────────────────────────────────────────────
# 🔐 MFA-Enabled User Fixture with Valid TOTP Secret
# ──────────────────────────────────────────────────────────────
@pytest.fixture
def mfa_user_with_token(db_session: AsyncSession) -> Callable[..., Awaitable[Tuple[User, str]]]:
    """
    Create an MFA-enabled user and return (user, jwt_token).
    Seeds a valid TOTP secret so tests can generate OTPs.
    """
    async def _create(**kwargs) -> Tuple[User, str]:
        kwargs.setdefault("mfa_enabled", True)
        kwargs.setdefault("totp_secret", random_base32())
        kwargs.setdefault("is_active", True)
        kwargs.setdefault("is_verified", True)

        user = await create_user(session=db_session, **kwargs)
        if user is None:
            raise RuntimeError("create_user returned None")
        await db_session.commit()
        await db_session.refresh(user)

        token = await create_access_token(
            user_id=str(user.id),           # ✅ ensure str
            mfa_authenticated=False,        # org-free token
        )
        return user, token

    return _create
