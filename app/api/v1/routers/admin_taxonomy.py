
"""
Admin Taxonomy & Credits
========================

Genres (taxonomy) and Credits endpoints for admin with MFA enforcement.
Practices: SlowAPI rate limits, admin+MFA checks, Redis idempotency for create,
row-level locking for updates, sensitive cache headers, and audit logs.
"""

from typing import Optional, List, Dict
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update, delete, and_, func, insert, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import rate_limit
from app.core.jwt import decode_token
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.db.models.user import User
from app.db.models.genre import Genre
from app.db.models.title import Title
from app.db.models.credit import Credit
from app.security_headers import set_sensitive_cache
from app.db.models.compliance import Certification, ContentAdvisory
from app.schemas.enums import CertificationSystem, AdvisoryKind, AdvisorySeverity
from app.services.audit_log_service import log_audit_event


router = APIRouter(tags=["Admin Taxonomy & Credits"])


def _is_admin(user: User) -> bool:
    try:
        from app.schemas.enums import OrgRole
        return getattr(user, "role", None) in {OrgRole.ADMIN, OrgRole.SUPERUSER}
    except Exception:
        return bool(getattr(user, "is_superuser", False))


async def _ensure_admin(user: User) -> None:
    if not _is_admin(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")


async def _ensure_mfa(request: Request) -> None:
    try:
        claims = await decode_token(request.headers.get("Authorization", "").split(" ")[-1], expected_types=["access"], verify_revocation=True)
        if not bool(claims.get("mfa_authenticated")):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MFA required")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token")


# ───────────────────────── Genres ─────────────────────────

class GenreCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    slug: str = Field(..., min_length=1, max_length=96)
    description: Optional[str] = None
    parent_id: Optional[UUID] = None
    is_active: bool = True
    display_order: Optional[int] = None


class GenrePatchIn(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=80)
    slug: Optional[str] = Field(None, min_length=1, max_length=96)
    description: Optional[str] = None
    parent_id: Optional[UUID] = None
    is_active: Optional[bool] = None
    display_order: Optional[int] = Field(None, ge=0)


def _ser_genre(g: Genre) -> Dict[str, object]:
    return {
        "id": str(g.id),
        "name": g.name,
        "slug": g.slug,
        "description": g.description,
        "parent_id": str(g.parent_id) if g.parent_id else None,
        "is_active": bool(g.is_active),
        "display_order": g.display_order,
        "created_at": getattr(g, "created_at", None),
    }


@router.post("/genres", summary="Create genre (Idempotency-Key supported)")
@rate_limit("10/minute")
async def create_genre(
    payload: GenreCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:genres:create:{payload.slug}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    g = Genre(
        name=payload.name,
        slug=payload.slug,
        description=payload.description,
        parent_id=payload.parent_id,
        is_active=payload.is_active,
        display_order=payload.display_order,
    )
    db.add(g)
    await db.flush(); await db.commit()
    try:
        await db.refresh(g)
    except Exception:
        pass
    body = _ser_genre(g)
    await log_audit_event(db, user=current_user, action="GENRES_CREATE", status="SUCCESS", request=request, meta_data={"id": body["id"], "slug": g.slug})
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    return body


@router.get("/genres", summary="List genres (filters; paginate)")
@rate_limit("30/minute")
async def list_genres(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    q: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    stmt = select(Genre)
    if q:
        s = q.strip().lower()
        stmt = stmt.where(or_(func.lower(Genre.name).contains(s), func.lower(Genre.slug).contains(s)))
    if is_active is not None:
        stmt = stmt.where(Genre.is_active == bool(is_active))
    stmt = stmt.order_by(Genre.display_order.asc().nulls_last(), Genre.name.asc()).offset(offset).limit(limit)
    rows = (await db.execute(stmt)).scalars().all() or []
    return [_ser_genre(g) for g in rows]


@router.patch("/genres/{genre_id}", summary="Patch genre")
@rate_limit("10/minute")
async def patch_genre(
    genre_id: UUID,
    payload: GenrePatchIn,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    g = (await db.execute(select(Genre).where(Genre.id == genre_id).with_for_update())).scalar_one_or_none()
    if not g:
        raise HTTPException(status_code=404, detail="Genre not found")
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No changes provided")
    for k, v in updates.items():
        setattr(g, k, v)
    await db.flush(); await db.commit()
    await log_audit_event(db, user=current_user, action="GENRES_PATCH", status="SUCCESS", request=request, meta_data={"id": str(genre_id), "fields": list(updates.keys())})
    return _ser_genre(g)


@router.delete("/genres/{genre_id}", summary="Delete genre")
@rate_limit("10/minute")
async def delete_genre(
    genre_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    await db.execute(delete(Genre).where(Genre.id == genre_id))
    await db.commit()
    await log_audit_event(db, user=current_user, action="GENRES_DELETE", status="SUCCESS", request=request, meta_data={"id": str(genre_id)})
    return {"message": "Genre deleted"}


@router.post("/titles/{title_id}/genres/{genre_id}", summary="Attach genre to title")
@rate_limit("10/minute")
async def attach_genre(
    title_id: UUID,
    genre_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    g = (await db.execute(select(Genre).where(Genre.id == genre_id))).scalar_one_or_none()
    if not t or not g:
        raise HTTPException(status_code=404, detail="Title or Genre not found")
    # Use Title.genres relationship via insert to association table to avoid loading collections
    try:
        await db.execute(insert(Title.genres.property.secondary).values(title_id=title_id, genre_id=genre_id))  # type: ignore
        await db.commit()
    except Exception:
        # Already attached or constraint error
        pass
    await log_audit_event(db, user=current_user, action="TITLES_GENRE_ATTACH", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "genre_id": str(genre_id)})
    return {"message": "Attached"}


@router.delete("/titles/{title_id}/genres/{genre_id}", summary="Detach genre from title")
@rate_limit("10/minute")
async def detach_genre(
    title_id: UUID,
    genre_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    try:
        await db.execute(delete(Title.genres.property.secondary).where(  # type: ignore
            Title.genres.property.secondary.c.title_id == title_id,      # type: ignore
            Title.genres.property.secondary.c.genre_id == genre_id,      # type: ignore
        ))
        await db.commit()
    except Exception:
        pass
    await log_audit_event(db, user=current_user, action="TITLES_GENRE_DETACH", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "genre_id": str(genre_id)})
    return {"message": "Detached"}


# ───────────────────────── Credits ─────────────────────────

class CreditCreateIn(BaseModel):
    person_id: UUID
    kind: str
    role: str
    character_name: Optional[str] = None
    billing_order: Optional[int] = Field(None, ge=0)
    credited_as: Optional[str] = None
    is_uncredited: bool = False
    is_voice: bool = False
    is_guest: bool = False
    is_cameo: bool = False


class CreditPatchIn(BaseModel):
    character_name: Optional[str] = None
    billing_order: Optional[int] = Field(None, ge=0)
    credited_as: Optional[str] = None
    is_uncredited: Optional[bool] = None
    is_voice: Optional[bool] = None
    is_guest: Optional[bool] = None
    is_cameo: Optional[bool] = None


def _ser_credit(c: Credit) -> Dict[str, object]:
    return {
        "id": str(c.id),
        "person_id": str(c.person_id),
        "kind": str(getattr(c, "kind", None)),
        "role": str(getattr(c, "role", None)),
        "character_name": c.character_name,
        "billing_order": c.billing_order,
        "credited_as": c.credited_as,
        "is_uncredited": bool(c.is_uncredited),
        "is_voice": bool(c.is_voice),
        "is_guest": bool(c.is_guest),
        "is_cameo": bool(c.is_cameo),
        "created_at": getattr(c, "created_at", None),
    }


@router.post("/titles/{title_id}/credits", summary="Create title credit")
@rate_limit("10/minute")
async def create_title_credit(
    title_id: UUID,
    payload: CreditCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")
    c = Credit(
        title_id=title_id,
        person_id=payload.person_id,
        kind=payload.kind,
        role=payload.role,
        character_name=payload.character_name,
        billing_order=payload.billing_order,
        credited_as=payload.credited_as,
        is_uncredited=payload.is_uncredited,
        is_voice=payload.is_voice,
        is_guest=payload.is_guest,
        is_cameo=payload.is_cameo,
    )
    db.add(c)
    await db.flush(); await db.commit()
    try:
        await db.refresh(c)
    except Exception:
        pass
    await log_audit_event(db, user=current_user, action="CREDITS_CREATE", status="SUCCESS", request=request, meta_data={"credit_id": str(c.id), "title_id": str(title_id)})
    return _ser_credit(c)


@router.get("/titles/{title_id}/credits", summary="List title credits")
@rate_limit("30/minute")
async def list_title_credits(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    kind: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    stmt = select(Credit).where(Credit.title_id == title_id)
    if kind:
        stmt = stmt.where(func.lower(Credit.kind) == kind.lower())
    if role:
        stmt = stmt.where(func.lower(Credit.role) == role.lower())
    stmt = stmt.order_by(Credit.billing_order.asc().nulls_last(), Credit.created_at.asc()).offset(offset).limit(limit)
    rows = (await db.execute(stmt)).scalars().all() or []
    return [_ser_credit(c) for c in rows]


@router.patch("/credits/{credit_id}", summary="Patch credit flags/fields")
@rate_limit("10/minute")
async def patch_credit(
    credit_id: UUID,
    payload: CreditPatchIn,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    c = (await db.execute(select(Credit).where(Credit.id == credit_id).with_for_update())).scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Credit not found")
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No changes provided")
    for k, v in updates.items():
        setattr(c, k, v)
    await db.flush(); await db.commit()
    await log_audit_event(db, user=current_user, action="CREDITS_PATCH", status="SUCCESS", request=request, meta_data={"credit_id": str(credit_id), "fields": list(updates.keys())})
    return _ser_credit(c)


@router.delete("/credits/{credit_id}", summary="Delete credit")
@rate_limit("10/minute")
async def delete_credit(
    credit_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    await db.execute(delete(Credit).where(Credit.id == credit_id))
    await db.commit()
    await log_audit_event(db, user=current_user, action="CREDITS_DELETE", status="SUCCESS", request=request, meta_data={"credit_id": str(credit_id)})
    return {"message": "Credit deleted"}


# ───────────────────────── Compliance & Content Flags ─────────────────────────

class BlockIn(BaseModel):
    regions: List[str] = Field(..., description="ISO-3166-1 alpha-2 country codes")
    system: CertificationSystem = CertificationSystem.OTHER
    rating_code: Optional[str] = Field(None, description="Board-specific rating code (e.g., '18', 'PG-13')")
    min_age: Optional[int] = Field(None, ge=0, le=21)
    notes: Optional[str] = None
    unpublish: bool = False


@router.post("/titles/{title_id}/block", summary="Apply region/age gate (certifications); optional unpublish")
@rate_limit("10/minute")
async def compliance_block_title(
    title_id: UUID,
    payload: BlockIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")

    # Set prior current certs for region/system to non-current, then insert new certs
    regions = [r.strip().upper() for r in (payload.regions or []) if r and r.strip()]
    if not regions:
        raise HTTPException(status_code=400, detail="No regions provided")

    for region in regions:
        await db.execute(
            update(Certification)
            .where(Certification.title_id == title_id, Certification.region == region, Certification.system == payload.system, Certification.is_current == True)  # noqa: E712
            .values(is_current=False)
        )
        c = Certification(
            title_id=title_id,
            region=region,
            system=payload.system,
            rating_code=payload.rating_code or (str(payload.min_age) if payload.min_age is not None else "BLOCK"),
            age_min=payload.min_age,
            meaning=payload.notes,
            is_current=True,
            source="admin_block",
        )
        db.add(c)

    if payload.unpublish and getattr(t, "is_published", False):
        t.is_published = False

    await db.flush(); await db.commit()
    await log_audit_event(db, user=current_user, action="COMPLIANCE_BLOCK", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "regions": regions, "unpublish": payload.unpublish})
    return {"message": "Compliance block applied", "regions": regions, "unpublish": payload.unpublish}


class DMCAIn(BaseModel):
    reason: Optional[str] = None
    source_url: Optional[str] = None
    unpublish: bool = True


@router.post("/titles/{title_id}/dmca", summary="DMCA takedown & unpublish")
@rate_limit("6/minute")
async def compliance_dmca_takedown(
    title_id: UUID,
    payload: DMCAIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")

    # Unpublish and add a strong advisory flag (global) for internal tracking
    if payload.unpublish and getattr(t, "is_published", False):
        t.is_published = False

    adv = ContentAdvisory(
        title_id=title_id,
        kind=AdvisoryKind.OTHER,
        severity=AdvisorySeverity.SEVERE,
        language="en",
        notes=payload.reason or "DMCA takedown",
        tags={"dmca": True, "source_url": payload.source_url} if payload.source_url else {"dmca": True},
        is_active=True,
        source="dmca_admin",
    )
    db.add(adv)
    await db.flush(); await db.commit()
    await log_audit_event(db, user=current_user, action="COMPLIANCE_DMCA", status="SUCCESS", request=request, meta_data={"title_id": str(title_id)})
    return {"message": "Takedown applied"}


@router.get("/compliance/flags", summary="Enumerations for compliance flags")
@rate_limit("60/minute")
async def compliance_flags(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Dict[str, List[str]]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    return {
        "certification_systems": [c.name for c in CertificationSystem],
        "advisory_kinds": [k.name for k in AdvisoryKind],
        "advisory_severities": [s.name for s in AdvisorySeverity],
    }
