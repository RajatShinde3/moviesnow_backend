import pytest
from datetime import timezone
from httpx import AsyncClient
from uuid import uuid4
from app.db.models.user import User
from app.schemas.auth import RegistrationVerifyRequest, AssertionVerifyRequest
from app.services.auth.webauthn_service import finish_registration, finish_assertion
from app.core.security import create_access_token
from datetime import datetime, timedelta
from jose import jwt
from app.core.config import settings
from app.db.models.webauthn import WebAuthnCredential
from app.db.session import get_async_db

BASE = "/api/v1/auth/webauthn"

# ────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────

async def create_webauthn_credential(user: User, credential_id: str) -> WebAuthnCredential:
    """
    Helper function to create and store a WebAuthn credential for a given user.
    This function simulates the creation of a passkey (credential) and stores
    it in the database.
    """
    async with get_async_db() as db:
        credential = WebAuthnCredential(
            id=str(uuid4()),
            user_id=user.id,
            credential_id=credential_id,
            public_key=b"public-key-example",
            sign_count=0,
            transports=["usb", "nfc"],
            aaguid="example-aaguid",
            nickname="Test Credential",
            created_at=datetime.now(timezone.utc),
            last_used_at=None,
        )
        db.add(credential)
        await db.commit()
    return credential


def create_reauth_token(user_id: str, session_id: str, mfa_authenticated: bool) -> str:
    """
    Creates a re-authentication (step-up) token for verifying sensitive operations.
    """
    expiration_time = datetime.utcnow() + timedelta(minutes=5)  
    claims = {
        "sub": user_id,
        "session_id": session_id,
        "mfa_authenticated": mfa_authenticated,
        "exp": expiration_time,
        "typ": "reauth",
    }

    reauth_token = jwt.encode(
        claims,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM,
    )

    return reauth_token


@pytest.fixture
async def bearer(create_test_user):
    """Generates a bearer token with proper headers."""
    user = await create_test_user(is_verified=True)
    headers = await get_bearer_headers(user)
    return headers

async def get_bearer_headers(user: User):
    """Helper function to generate bearer headers."""
    sid = str(uuid4())
    access_token = await create_access_token(user_id=user.id, session_id=sid)
    reauth_token = create_reauth_token(user_id=user.id, session_id=sid, mfa_authenticated=True)
    return {
        "Authorization": f"Bearer {access_token}",
        "X-Reauth": reauth_token,
    }

async def make_reauth_token(user_id: str, session_id: str, mfa: bool = False):
    """Generates a reauth token with necessary claims."""
    return create_reauth_token(user_id=user_id, session_id=session_id, mfa_authenticated=mfa)

# ────────────────────────────────────────────────────────────────
# TEST: POST /auth/webauthn/registration/options
# ────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_webauthn_registration_options(
    async_client: AsyncClient, bearer
):
    """Test WebAuthn registration options endpoint."""
    response = await async_client.post(
        f"{BASE}/registration/options", headers=bearer
    )

    assert response.status_code == 200
    assert "publicKey" in response.json()


# ────────────────────────────────────────────────────────────────
# TEST: POST /auth/webauthn/registration/verify
# ────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_webauthn_registration_verify(
    async_client: AsyncClient, bearer
):
    """Test WebAuthn registration verify endpoint."""
    payload = {
        "credential": {
            "id": "test-credential-id",
            "response": {"clientDataJSON": "test-data", "authenticatorData": "test-auth-data"},
        },
        "nickname": "Test Credential",
    }

    response = await async_client.post(
        f"{BASE}/registration/verify", json=payload, headers=bearer
    )

    assert response.status_code == 201
    assert "credential_id" in response.json()


# ────────────────────────────────────────────────────────────────
# TEST: POST /auth/webauthn/assertion/options
# ────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_webauthn_assertion_options(
    async_client: AsyncClient, bearer
):
    """Test WebAuthn assertion options endpoint."""
    response = await async_client.post(
        f"{BASE}/assertion/options", headers=bearer
    )

    assert response.status_code == 200
    assert "publicKey" in response.json()


# ────────────────────────────────────────────────────────────────
# TEST: POST /auth/webauthn/assertion/verify
# ────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_webauthn_assertion_verify(
    async_client: AsyncClient, bearer
):
    """Test WebAuthn assertion verify endpoint."""
    payload = {
        "credential": {
            "id": "test-credential-id",
            "response": {"clientDataJSON": "test-data", "authenticatorData": "test-auth-data"},
        }
    }

    response = await async_client.post(
        f"{BASE}/assertion/verify", json=payload, headers=bearer
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True, "user_id": "test-user-id", "credential_id": "test-credential-id"}


# ────────────────────────────────────────────────────────────────
# TEST: GET /auth/webauthn/credentials
# ────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_webauthn_credentials_list(
    async_client: AsyncClient, bearer
):
    """Test WebAuthn credentials list endpoint."""
    response = await async_client.get(
        f"{BASE}/credentials", headers=bearer
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


# ────────────────────────────────────────────────────────────────
# TEST: DELETE /auth/webauthn/credentials/{id}
# ────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_webauthn_credentials_delete(
    async_client: AsyncClient, bearer
):
    """Test WebAuthn credential deletion endpoint."""
    credential_id = str(uuid4())
    await create_webauthn_credential(User, credential_id)  # Helper function to create credentials

    response = await async_client.delete(
        f"{BASE}/credentials/{credential_id}", headers=bearer
    )

    assert response.status_code == 204


# ────────────────────────────────────────────────────────────────
# TEST: Step-Up Verification for Sensitive Operations (e.g., delete passkey)
# ────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_step_up_required_for_webauthn_operations(
    async_client: AsyncClient, bearer
):
    """Test if step-up verification is required for WebAuthn operations."""
    sid = str(uuid4())
    headers = (await bearer) | {"X-Reauth": make_reauth_token(user_id=User.id, session_id=sid, mfa=True)}

    response = await async_client.delete(
        f"{BASE}/credentials/{str(uuid4())}", headers=headers
    )

    assert response.status_code == 401  # Step-up required error


# ────────────────────────────────────────────────────────────────
# TEST: WebAuthn credential deletion without step-up
# ────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_webauthn_credential_delete_without_step_up(
    async_client: AsyncClient, bearer
):
    """Test WebAuthn credential deletion without step-up."""
    response = await async_client.delete(
        f"{BASE}/credentials/{str(uuid4())}", headers=bearer
    )

    assert response.status_code == 401  # Step-up required error


# ────────────────────────────────────────────────────────────────
# TEST: WebAuthn registration options - Step-up required
# ────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_webauthn_registration_options_step_up_required(
    async_client: AsyncClient, bearer
):
    """Test if step-up is required for WebAuthn registration options."""
    sid = str(uuid4())
    headers = (await bearer) | {"X-Reauth": make_reauth_token(user_id=User.id, session_id=sid, mfa=True)}

    response = await async_client.post(
        f"{BASE}/registration/options", headers=headers
    )

    assert response.status_code == 200
    assert "publicKey" in response.json()


# ────────────────────────────────────────────────────────────────
# TEST: WebAuthn registration verify - Step-up required
# ────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_webauthn_registration_verify_step_up_required(
    async_client: AsyncClient, bearer
):
    """Test if step-up is required for WebAuthn registration verify."""
    sid = str(uuid4())
    headers = (await bearer) | {"X-Reauth": make_reauth_token(user_id=User.id, session_id=sid, mfa=True)}

    payload = {
        "credential": {
            "id": "test-credential-id",
            "response": {"clientDataJSON": "test-data", "authenticatorData": "test-auth-data"},
        },
        "nickname": "Test Credential",
    }

    response = await async_client.post(
        f"{BASE}/registration/verify", json=payload, headers=headers
    )

    assert response.status_code == 201
    assert "credential_id" in response.json()






