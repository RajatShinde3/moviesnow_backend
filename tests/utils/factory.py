# tests/utils/factory.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.user import User
from app.core.security import get_password_hash
from tests.utils.faker import fake


async def create_user(
    session: AsyncSession,
    *,
    email: Optional[str] = None,
    password: str = "password",
    is_active: bool = True,
    is_verified: bool = True,
    is_superuser: bool = False,
    full_name: str = "Test User",
    **kwargs,
) -> User:
    """
    Create a test user (no organization context).

    Args:
        session: Async SQLAlchemy session.
        email: Optional explicit email; defaults to a faker value.
        password: Plain password to hash.
        is_active: Whether the user is active.
        is_verified: Whether the user's email is verified.
        is_superuser: Whether the user is a superuser.
        full_name: Display name.
        **kwargs: Extra fields to pass to the User model (for schema differences).

    Returns:
        The persisted User instance (refreshed).
    """
    user = User(
        id=uuid4(),
        email=email or fake.email(),
        full_name=full_name,
        hashed_password=get_password_hash(password),
        is_active=is_active,
        is_verified=is_verified,
        is_superuser=is_superuser,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        **kwargs,
    )

    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def create_superuser(
    session: AsyncSession,
    *,
    email: Optional[str] = None,
    password: str = "adminpass",
    full_name: str = "Admin User",
    **kwargs,
) -> User:
    """Create a verified, active superuser (no org context)."""
    return await create_user(
        session=session,
        email=email,
        password=password,
        full_name=full_name,
        is_superuser=True,
        is_verified=True,
        is_active=True,
        **kwargs,
    )


def make_email(prefix: str = "user") -> str:
    """
    Generate a unique, realistic-looking email address.

    Example: "user_a9d21b@example.com"
    """
    unique = uuid4().hex[:6]
    # Some faker builds expose free_email_domain; fall back if missing.
    domain = getattr(fake, "free_email_domain", lambda: "example.com")()
    return f"{prefix}_{unique}@{domain}"
