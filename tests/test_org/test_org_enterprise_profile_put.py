import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import EnterpriseProfile
from app.schemas.enums import OrgRole


@pytest.mark.anyio
async def test_update_enterprise_profile_success(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_user_with_token,
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    profile = EnterpriseProfile(
        organization_id=org.id,
        overview="Initial overview",
        contact_phone="123-456-7890",
        user_id=user.id,
    )
    db_session.add(profile)
    await db_session.commit()

    payload = {
        "overview": "Updated overview",
        "values": "Integrity,Innovation",
        "technologies": "Python,FastAPI",
    }

    res = await async_client.put(
        "/api/v1/org/enterprise/profile",
        headers=headers,
        json=payload,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["overview"] == "Updated overview"
    assert data["values"] == ["Integrity", "Innovation"]
    assert data["technologies"] == ["Python", "FastAPI"]

    updated = await db_session.get(EnterpriseProfile, profile.id)
    assert updated.overview == "Updated overview"
    assert updated.values == ["Integrity", "Innovation"]
    assert updated.technologies == ["Python", "FastAPI"]


@pytest.mark.anyio
async def test_update_enterprise_profile_forbidden_for_intern(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_user_with_token,
):
    user, headers, org = await org_user_with_token(role=OrgRole.INTERN)

    profile = EnterpriseProfile(
        organization_id=org.id,
        contact_phone="123-456-7890",
        user_id=user.id                          
    )
    db_session.add(profile)
    await db_session.commit()

    payload = {"overview": "Intern update attempt"}

    res = await async_client.put(
        "/api/v1/org/enterprise/profile",
        headers=headers,
        json=payload,
    )

    assert res.status_code == 403
    assert res.json()["detail"] == "Role 'OrgRole.INTERN' is not allowed to modify field 'overview'"


@pytest.mark.anyio
async def test_update_enterprise_profile_not_found(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_user_with_token,
):
    user, headers, org = await org_user_with_token(role=OrgRole.OWNER)

    # Don't create profile
    payload = {"overview": "Should fail"}

    res = await async_client.put(
        "/api/v1/org/enterprise/profile",
        headers=headers,
        json=payload,
    )

    assert res.status_code == 404
    assert res.json()["detail"] == "Enterprise profile not found."


@pytest.mark.anyio
async def test_update_enterprise_profile_parses_csv_fields_correctly(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org_user_with_token,
):
    user, headers, org = await org_user_with_token(role=OrgRole.ADMIN)

    profile = EnterpriseProfile(
        organization_id=org.id,
        contact_phone="123-456-7890", 
        user_id=user.id                           
    )
    db_session.add(profile)
    await db_session.commit()

    payload = {
        "values": "Integrity, Innovation,  Excellence ",
        "technologies": ["Python", " FastAPI "],
        "sectors": None,  # Should become []
    }

    res = await async_client.put(
        "/api/v1/org/enterprise/profile",
        headers=headers,
        json=payload,
    )
    assert res.status_code == 200
    data = res.json()

    assert data["values"] == ["Integrity", "Innovation", "Excellence"]
    assert data["technologies"] == ["Python", "FastAPI"]
    assert data["sectors"] == []
