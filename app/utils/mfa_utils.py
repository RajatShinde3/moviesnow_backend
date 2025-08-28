# app/utils/mfa_utils.py

from jose import jwt, JWTError
from app.core.config import settings
import pyotp
from uuid import UUID
from app.core.security import generate_totp


def verify_mfa_token(token: str, user_id: UUID) -> bool:
    """
    Verifies the validity of a given MFA JWT token.

    - Ensures token is signed with the correct secret.
    - Checks that it contains the expected user ID.
    - Validates token type and mfa_pending status.

    Args:
        token (str): The MFA JWT token provided by the client.
        user_id (UUID): The expected user ID the token should contain.

    Returns:
        bool: True if valid and belongs to the correct user, else False.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY.get_secret_value(),
            algorithms=[settings.JWT_ALGORITHM],
        )
        return (
            str(payload.get("sub")) == str(user_id)
            and payload.get("type") == "mfa_token"  
            and payload.get("mfa_pending") is True
        )
    except JWTError:
        return False


def verify_totp(secret: str, code: str) -> bool:
    """
    Verifies a TOTP code against a shared secret using RFC 6238.

    Accepts ±1 time-step drift to avoid step-boundary flakes.
    """
    try:
        totp = generate_totp(secret)           # returns a pyotp.TOTP
        # Accept codes from the previous/next step to tolerate small clock skew.
        return totp.verify(code, valid_window=1)
    except Exception:
        return False
