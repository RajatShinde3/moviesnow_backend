
"""
Admin Titles Management (Org-free)
==================================

Endpoints (admin + MFA enforced):
- POST /admin/titles                      : Create title (Idempotency-Key supported)
- GET  /admin/titles                      : Search/list with filters, sort, paginate
- GET  /admin/titles/{title_id}           : Fetch single title
- PATCH /admin/titles/{title_id}          : Partial update (safe fields)
- POST /admin/titles/{title_id}/publish   : Mark title published
- POST /admin/titles/{title_id}/unpublish : Mark title unpublished
- DELETE /admin/titles/{title_id}         : Hard delete (cascades managed by DB)

Practices
---------
- SlowAPI per-route rate limits
- Admin + MFA check via access token claim
- Redis idempotency for create using Idempotency-Key header
- Redis distributed locks + DB row-level `FOR UPDATE` for mutations
- No-store cache headers and best-effort audit logs
"""

from typing import List, Dict, Optional
from uuid import UUID
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update, delete, and_, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import rate_limit
from app.core.jwt import decode_token
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.db.models.user import User
from app.db.models.title import Title
from app.schemas.enums import TitleType, TitleStatus
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event


router = APIRouter(tags=["Admin Titles"])


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


class TitleCreateIn(BaseModel):
    type: TitleType
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=1, max_length=255)
    original_name: Optional[str] = Field(None, max_length=255)
    status: Optional[TitleStatus] = None
    release_year: Optional[int] = None
    overview: Optional[str] = None
    tagline: Optional[str] = None


class TitlePatchIn(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    original_name: Optional[str] = Field(None, max_length=255)
    slug: Optional[str] = Field(None, min_length=1, max_length=255)
    status: Optional[TitleStatus] = None
    release_year: Optional[int] = None
    release_date: Optional[date] = None
    end_date: Optional[date] = None
    runtime_minutes: Optional[int] = None
    overview: Optional[str] = None
    tagline: Optional[str] = None


def _serialize_title(t: Title) -> Dict[str, object]:
    return {
        "id": str(t.id),
        "type": str(getattr(t, "type", None)),
        "status": str(getattr(t, "status", None)),
        "name": getattr(t, "name", None),
        "original_name": getattr(t, "original_name", None),
        "slug": getattr(t, "slug", None),
        "is_published": bool(getattr(t, "is_published", False)),
        "release_year": getattr(t, "release_year", None),
        "release_date": getattr(t, "release_date", None),
        "end_date": getattr(t, "end_date", None),
        "popularity_score": getattr(t, "popularity_score", None),
        "rating_average": getattr(t, "rating_average", None),
        "rating_count": getattr(t, "rating_count", None),
        "created_at": getattr(t, "created_at", None),
        "updated_at": getattr(t, "updated_at", None),
    }


@router.post("/titles", response_model=Dict[str, object], summary="Create title (Idempotency-Key supported)")
@rate_limit("10/minute")
async def create_title(
    payload: TitleCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # Idempotency: replay if snapshot exists
    idem_key_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:titles:create:{idem_key_hdr}" if idem_key_hdr else None
    if idem_key:
        try:
            snap = await redis_wrapper.idempotency_get(idem_key)
            if snap:
                return snap  # type: ignore[return-value]
        except Exception:
            pass

    # Persist
    t = Title(
        type=payload.type,
        name=payload.name,
        slug=payload.slug,
        original_name=payload.original_name,
        status=payload.status or TitleStatus.ANNOUNCED,
        release_year=payload.release_year,
        overview=payload.overview,
        tagline=payload.tagline,
    )
    db.add(t)
    await db.flush()
    await db.commit()
    try:
        await db.refresh(t)
    except Exception:
        pass

    body = _serialize_title(t)
    await log_audit_event(db, user=current_user, action="TITLES_CREATE", status="SUCCESS", request=request, meta_data={"id": body["id"], "slug": t.slug})
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    return body


@router.get("/titles", response_model=List[Dict[str, object]], summary="List titles (filters/sort/paginate)")
@rate_limit("30/minute")
async def list_titles(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    type: Optional[TitleType] = Query(None),
    status_: Optional[TitleStatus] = Query(None, alias="status"),
    is_published: Optional[bool] = Query(None),
    q: Optional[str] = Query(None, description="Search name/slug contains (CI)")
    ,
    sort: Optional[str] = Query("-created_at", description="Sort field, prefix '-' for desc: created_at,popularity,rating"),
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response, seconds=0)

    conds = []
    if type:
        conds.append(Title.type == type)
    if status_:
        conds.append(Title.status == status_)
    if is_published is not None:
        conds.append(Title.is_published == bool(is_published))
    if q:
        s = q.strip().lower()
        conds.append(or_(func.lower(Title.name).contains(s), func.lower(Title.slug).contains(s)))

    stmt = select(Title)
    if conds:
        stmt = stmt.where(and_(*conds))

    # Sorting
    if sort:
        desc = sort.startswith("-")
        key = sort.lstrip("-")
        col = {
            "created_at": Title.created_at,
            "popularity": Title.popularity_score,
            "rating": Title.rating_average,
            "release_year": Title.release_year,
        }.get(key, Title.created_at)
        stmt = stmt.order_by(col.desc() if desc else col.asc())

    stmt = stmt.offset(offset).limit(limit)
    rows = (await db.execute(stmt)).scalars().all() or []
    return [_serialize_title(t) for t in rows]


@router.get("/titles/{title_id}", response_model=Dict[str, object], summary="Get title by id")
@rate_limit("30/minute")
async def get_title(
    title_id: UUID,
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
    return _serialize_title(t)


@router.patch("/titles/{title_id}", response_model=Dict[str, object], summary="Patch title (safe fields)")
@rate_limit("10/minute")
async def patch_title(
    title_id: UUID,
    payload: TitlePatchIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    async with redis_wrapper.lock(f"lock:admin_titles:patch:{title_id}", timeout=10, blocking_timeout=3):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")
        updates = payload.model_dump(exclude_unset=True)
        if not updates:
            raise HTTPException(status_code=400, detail="No changes provided")
        for k, v in updates.items():
            setattr(t, k, v)
        await db.flush(); await db.commit()
        await log_audit_event(db, user=current_user, action="TITLES_PATCH", status="SUCCESS", request=request, meta_data={"id": str(title_id), "fields": list(updates.keys())})
        return _serialize_title(t)


@router.post("/titles/{title_id}/publish", response_model=Dict[str, object], summary="Publish title")
@rate_limit("5/minute")
async def publish_title(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    async with redis_wrapper.lock(f"lock:admin_titles:publish:{title_id}", timeout=10, blocking_timeout=3):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")
        if getattr(t, "is_published", False):
            return {"message": "Already published"}
        t.is_published = True
        await db.flush(); await db.commit()
        await log_audit_event(db, user=current_user, action="TITLES_PUBLISH", status="SUCCESS", request=request, meta_data={"id": str(title_id)})
        return {"message": "Published"}


@router.post("/titles/{title_id}/unpublish", response_model=Dict[str, object], summary="Unpublish title")
@rate_limit("5/minute")
async def unpublish_title(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    async with redis_wrapper.lock(f"lock:admin_titles:unpublish:{title_id}", timeout=10, blocking_timeout=3):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")
        if not getattr(t, "is_published", False):
            return {"message": "Already unpublished"}
        t.is_published = False
        await db.flush(); await db.commit()
        await log_audit_event(db, user=current_user, action="TITLES_UNPUBLISH", status="SUCCESS", request=request, meta_data={"id": str(title_id)})
        return {"message": "Unpublished"}


@router.delete("/titles/{title_id}", response_model=Dict[str, object], summary="Hard delete title")
@rate_limit("5/minute")
async def delete_title(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    await db.execute(delete(Title).where(Title.id == title_id))
    await db.commit()
    await log_audit_event(db, user=current_user, action="TITLES_DELETE", status="SUCCESS", request=request, meta_data={"id": str(title_id)})
    return {"message": "Title deleted"}

