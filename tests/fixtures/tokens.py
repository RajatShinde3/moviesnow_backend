# tests/fixtures/tokens.py

import pytest
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from sqlalchemy import select, update

from app.db.models import OrgCreationToken


@pytest.fixture
async def org_token_factory(db_session):
    """
    Create OrgCreationToken rows safely for tests.

    Defaults:
      - is_approved = False (so we don't trigger the approved-by/at check accidentally)
      - reuse_existing = True (idempotent: return existing unused token for the user)
    """

    async def _factory(
        *,
        user_id,
        org_name: str = "Test Org",
        is_approved: bool = False,
        approved_by=None,
        approved_at=None,
        is_used: bool = False,
        used_at=None,
        expires_at=None,
        org_description=None,
        org_metadata=None,
        token: str | None = None,
        reuse_existing: bool = True,
        rotate: bool = False,
    ):
        now = datetime.now(timezone.utc)

        # Reuse/rotate logic (optional; keep if you already have it)
        if reuse_existing and not is_used:
            existing = (
                await db_session.execute(
                    select(OrgCreationToken)
                    .where(OrgCreationToken.user_id == user_id, OrgCreationToken.is_used.is_(False))
                    .limit(1)
                )
            ).scalars().first()
            if existing:
                return existing

        if rotate:
            await db_session.execute(
                update(OrgCreationToken)
                .where(OrgCreationToken.user_id == user_id, OrgCreationToken.is_used.is_(False))
                .values(is_used=True, used_at=now)
            )

        # Satisfy approval constraint if requested
        if is_approved:
            approved_by = approved_by or user_id
            approved_at = approved_at or now

        # Stamp used_at if flagged used
        if is_used and used_at is None:
            used_at = now

        # If caller asked for an expiry in the past, we can't insert it directly,
        # because created_at is set on insert. Insert with a safe future expiry first.
        wants_past_expiry = expires_at is not None and expires_at < now
        initial_expires = expires_at if (expires_at and not wants_past_expiry) else (now + timedelta(minutes=10))

        obj = OrgCreationToken(
            token=token or uuid4().hex,
            user_id=user_id,
            org_name=org_name,
            org_description=org_description,
            org_metadata=org_metadata or {},
            is_approved=is_approved,
            approved_by=approved_by,
            approved_at=approved_at,
            is_used=is_used,
            used_at=used_at,
            expires_at=initial_expires,
        )

        db_session.add(obj)
        await db_session.commit()
        await db_session.refresh(obj)

        # If the test wanted a past expiry, update it now to >= created_at but < now
        if wants_past_expiry:
            safe_past = max(obj.created_at, expires_at)  # keep >= created_at
            obj.expires_at = safe_past
            await db_session.commit()
            await db_session.refresh(obj)

        return obj
    # return the factory callable
    return _factory
