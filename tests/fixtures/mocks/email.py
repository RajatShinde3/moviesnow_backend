import pytest
from datetime import datetime

@pytest.fixture(autouse=True)
def mock_send_emails(monkeypatch):
    async def mock_send_email(email: str, subject: str = "", body: str = ""):
        print(f"[MOCK EMAIL] To: {email}, Subject: {subject}")

    async def mock_send_verification_email(email: str, token: str): 
        print(f"[MOCK VERIFICATION EMAIL] To: {email}, Token: {token}")

    monkeypatch.setattr("app.utils.email_utils.send_verification_email", mock_send_verification_email)
    monkeypatch.setattr("app.core.email.send_org_creation_token_email", mock_send_email)
    monkeypatch.setattr("app.services.auth.signup_service.send_verification_email", mock_send_verification_email)
    monkeypatch.setattr("app.services.auth.resend_service.send_verification_email", mock_send_verification_email)
    monkeypatch.setattr("app.services.auth.account_service.send_reactivation_email", mock_send_verification_email)


    def mock_send_email_invitation(to: str, org_name: str, token: str):
        print(f"[MOCK INVITE EMAIL] To: {to}, Org: {org_name}, Token: {token}")
    monkeypatch.setattr("app.core.email.send_email_invitation", mock_send_email_invitation)

@pytest.fixture(autouse=True)
def mock_global_send_email(monkeypatch):
    def mock_send_email(to: str, subject: str, body: str, html: str | None = None):
        print(f"[MOCK EMAIL] To: {to}, Subject: {subject}")
    monkeypatch.setattr("app.core.email.send_email", mock_send_email)

@pytest.fixture(autouse=True)
def mock_superuser_token_email(monkeypatch):
    async def mock_send(to_email: str, org_name: str, token: str, expires_at: datetime):
        print(f"[MOCK SUPERUSER TOKEN EMAIL] To: {to_email}, Org: {org_name}, Token: {token}")
    monkeypatch.setattr("app.api.v1.routes.orgs.org_admin.send_superuser_token_confirmation_email", mock_send)

@pytest.fixture(autouse=True)
def mock_send_otp_email(monkeypatch):
    async def noop(email: str, otp: str): pass
    monkeypatch.setattr("app.api.v1.auth.account_deactivation.send_password_reset_otp", noop)
