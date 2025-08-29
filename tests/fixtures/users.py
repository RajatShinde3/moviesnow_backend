import pytest
from uuid import uuid4
from datetime import datetime, timezone
from typing import Callable, Awaitable, Tuple
from pyotp import random_base32
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, get_password_hash
from app.db.models import User
from app.schemas.enums import OrgRole
from tests.utils.factory import create_user


# ──────────────────────────────────────────────────────────────
# 🧪 Factory: Create or Reuse Test User (by email)
# ──────────────────────────────────────────────────────────────
@pytest.fixture
def create_test_user(db_session: AsyncSession) -> Callable[..., Awaitable[User]]:
    """
    ✅ Factory Fixture: Create or retrieve a test user by email.

    - If the user with the given email exists, returns it.
    - Otherwise, creates a new one using the `create_user` utility.

    Returns:
        Async Callable that returns a `User` instance.
    """
    async def _create(**kwargs) -> User:
        email = kwargs.get("email") or f"test_{uuid4().hex}@example.com"
        kwargs["email"] = email
        result = await db_session.execute(select(User).where(User.email == email))
        existing_user = result.scalar_one_or_none()
        if existing_user:
            return existing_user

        user = await create_user(session=db_session, **kwargs)
        if user is None:
            raise Exception("⚠️ create_user returned None!")
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
    ✅ Factory Fixture: Create a verified test user with minimal setup.

    Returns:
        Async Callable that returns a `User` instance with a JWT token.
    """
    async def _create_user(
        email: str = None,
        password: str = "password",
        is_verified: bool = True,
    ) -> User:
        user = User(
            email=email or f"testuser_{uuid4().hex[:8]}@example.com",
            hashed_password=get_password_hash(password),
            is_active=True,
            is_verified=is_verified,
            created_at=datetime.now(timezone.utc),
        )

        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        # Add `token` for convenience in test usage
        user.token = await create_access_token(user_id=user.id)
        return user

    return _create_user


# ──────────────────────────────────────────────────────────────
# 👑 Superadmin Fixture
# ──────────────────────────────────────────────────────────────
@pytest.fixture
async def superadmin_user(create_test_user) -> User:
    """
    🚀 Superuser Fixture: Creates a user with elevated privileges for testing admin flows.

    Returns:
        `User` instance with `is_superuser=True`
    """
    return await create_test_user(
        email="superadmin@example.com",
        full_name="Super Admin",
        is_superuser=True,
    )


# ──────────────────────────────────────────────────────────────
# 🔐 MFA-Enabled User Fixture with Valid TOTP Secret
# ──────────────────────────────────────────────────────────────
@pytest.fixture
def mfa_user_with_token(db_session: AsyncSession) -> Callable[..., Awaitable[Tuple[User, str]]]:
    """
    🔐 Factory fixture for creating an MFA-enabled user and returning (user, token).

    Automatically sets a valid TOTP secret to allow OTP generation.
    """
    async def _create(**kwargs) -> Tuple[User, str]:
        kwargs.setdefault("mfa_enabled", True)
        kwargs.setdefault("totp_secret", random_base32())

        user = await create_user(session=db_session, **kwargs)
        await db_session.commit()
        await db_session.refresh(user)

        token = await create_access_token(
            user_id=user.id,
            mfa_authenticated=False,
            active_org=kwargs.get("active_org")
        )
        return user, token

    return _create
