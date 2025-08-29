import pytest

@pytest.fixture
def enterprise_full_profile_payload():
    return {
        "org_name": "TestOrg",
        "legal_name": "TestOrg Pvt Ltd",
        "overview": "We build AI stuff.",
        "mission": "Responsible AI",
        "vision": "AGI for good",
        "industry": "Artificial Intelligence",
        "linkedin": "https://linkedin.com/company/testorg",
        "contact_email": "contact@testorg.ai",
        "contact_phone": "+1-800-555-0199",
    }
