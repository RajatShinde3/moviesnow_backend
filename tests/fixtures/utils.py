import pytest
from datetime import datetime, timedelta, timezone

from app.db.models import OTP, User
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.fixture
def generate_test_otp(db_session: AsyncSession):
    """
    🔐 Fixture to generate a test OTP (One-Time Password) for a given user and purpose.

    Example:
        otp = await generate_test_otp(user, purpose="mfa_login")

    Args:
        user (User): The user for whom the OTP is generated.
        purpose (str): The OTP usage purpose (e.g., "delete_account", "mfa_login").
        code (str): The OTP code (default: "123456").

    Returns:
        OTP: The created OTP object.
    """

    async def _generate(
        user: User,
        purpose: str = "delete_account",
        code: str = "123456",
    ) -> OTP:
        otp = OTP(
            user_id=user.id,
            code=code,
            purpose=purpose,
            used=False,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        db_session.add(otp)
        await db_session.commit()
        await db_session.refresh(otp)
        return otp

    return _generate
