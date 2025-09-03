"""
MoviesNow · Admin Titles Management (Org-free)
==============================================

Endpoints (ADMIN/SUPERUSER + MFA)
---------------------------------
- POST   /admin/titles                       : Create title (Idempotency-Key supported)
- GET    /admin/titles                       : Search/list with filters, sort, paginate
- GET    /admin/titles/{title_id}            : Fetch single title
- PATCH  /admin/titles/{title_id}            : Partial update (safe fields)
- POST   /admin/titles/{title_id}/publish    : Mark title published (idempotent)
- POST   /admin/titles/{title_id}/unpublish  : Mark title unpublished (idempotent)
- DELETE /admin/titles/{title_id}            : Hard delete (DB cascades)

Ops & Security Practices
------------------------
- SlowAPI per-route rate limits
- ADMIN/SUPERUSER + `mfa_authenticated` guard on access token
- Redis idempotency snapshots for create via Idempotency-Key header
- Redis distributed locks + DB row-level `FOR UPDATE` for mutations
- Sensitive cache-control on responses carrying tokens or admin data
- Pre-flight slug uniqueness checks -> 409 CONFLICT (defensive, even if DB also enforces)
- Best-effort structured audit logs (never blocks business flow)
"""

from __future__ import annotations

from typing import List, Dict, Optional
from uuid import UUID
from datetime import date, datetime

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
from app.db.models.availability import Availability
from app.schemas.enums import TitleType, TitleStatus, TerritoryMode, DistributionKind, DeviceClass
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event
from app.dependencies.admin import (
    is_admin as _is_admin,
    ensure_admin as _ensure_admin,
    ensure_mfa as _ensure_mfa,
)


router = APIRouter(tags=["Admin Titles"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Helpers
# ─────────────────────────────────────────────────────────────────────────────
 


async def _slug_exists(db: AsyncSession, slug: str, *, exclude_id: Optional[UUID] = None) -> bool:
    stmt = select(Title.id).where(func.lower(Title.slug) == slug.strip().lower())
    if exclude_id:
        stmt = stmt.where(Title.id != exclude_id)
    return (await db.execute(stmt)).scalar_one_or_none() is not None


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
        "deleted_at": getattr(t, "deleted_at", None),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 📦 Schemas
# ─────────────────────────────────────────────────────────────────────────────
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


# ─────────────────────────────────────────────────────────────────────────────
# ➕ Create title (Idempotency-Key supported)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/titles", response_model=Dict[str, object], summary="Create title (Idempotency-Key supported)")
@rate_limit("10/minute")
async def create_title(
    payload: TitleCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    # ── [Step 0] Security + cache hardening ─────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # ── [Step 1] Idempotency replay (best-effort) ───────────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:titles:create:{idem_hdr}" if idem_hdr else None
    if idem_key:
        try:
            snap = await redis_wrapper.idempotency_get(idem_key)
            if snap:
                return snap  # type: ignore[return-value]
        except Exception:
            pass

    # ── [Step 2] Slug uniqueness guard (defensive 409) ─────────────────────
    if await _slug_exists(db, payload.slug):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Slug already exists")

    # ── [Step 3] Persist ────────────────────────────────────────────────────
    t = Title(
        type=payload.type,
        name=payload.name.strip(),
        slug=payload.slug.strip(),
        original_name=(payload.original_name or None),
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
    await log_audit_event(db, user=current_user, action="TITLES_CREATE", status="SUCCESS", request=request,
                          meta_data={"id": body["id"], "slug": t.slug})

    # ── [Step 4] Idempotency snapshot ───────────────────────────────────────
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    return body


# ─────────────────────────────────────────────────────────────────────────────
# 📚 List titles (filters/sort/paginate)
# ─────────────────────────────────────────────────────────────────────────────
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
    q: Optional[str] = Query(None, description="Search name/slug contains (case-insensitive)"),
    sort: Optional[str] = Query(
        "-created_at",
        description="Sort field (prefix '-' for desc). One of: created_at, popularity, rating, release_year",
    ),
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


# ─────────────────────────────────────────────────────────────────────────────
# 🔎 Get single title
# ─────────────────────────────────────────────────────────────────────────────
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
    set_sensitive_cache(response, seconds=0)

    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")
    return _serialize_title(t)


# ─────────────────────────────────────────────────────────────────────────────
# ✏️ Patch title (safe fields + slug conflict check)
# ─────────────────────────────────────────────────────────────────────────────
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
    set_sensitive_cache(response)

    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No changes provided")
    if "slug" in updates and await _slug_exists(db, str(updates["slug"]), exclude_id=title_id):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Slug already exists")

    async with redis_wrapper.lock(f"lock:admin_titles:patch:{title_id}", timeout=10, blocking_timeout=3):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")
        for k, v in updates.items():
            setattr(t, k, v)
        await db.flush(); await db.commit()

    await log_audit_event(db, user=current_user, action="TITLES_PATCH", status="SUCCESS", request=request,
                          meta_data={"id": str(title_id), "fields": list(updates.keys())})
    return _serialize_title(t)


# ─────────────────────────────────────────────────────────────────────────────
# 🚀 Publish / 📴 Unpublish (idempotent)
# ─────────────────────────────────────────────────────────────────────────────
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
    set_sensitive_cache(response)

    async with redis_wrapper.lock(f"lock:admin_titles:publish:{title_id}", timeout=10, blocking_timeout=3):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")
        if getattr(t, "is_published", False):
            return {"message": "Already published"}
        t.is_published = True
        await db.flush(); await db.commit()

    await log_audit_event(db, user=current_user, action="TITLES_PUBLISH", status="SUCCESS", request=request,
                          meta_data={"id": str(title_id)})
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
    set_sensitive_cache(response)

    async with redis_wrapper.lock(f"lock:admin_titles:unpublish:{title_id}", timeout=10, blocking_timeout=3):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")
        if not getattr(t, "is_published", False):
            return {"message": "Already unpublished"}
        t.is_published = False
        await db.flush(); await db.commit()

    await log_audit_event(db, user=current_user, action="TITLES_UNPUBLISH", status="SUCCESS", request=request,
                          meta_data={"id": str(title_id)})
    return {"message": "Unpublished"}


# ─────────────────────────────────────────────────────────────────────────────
# 🗑️ Hard delete
# ─────────────────────────────────────────────────────────────────────────────
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
    set_sensitive_cache(response)

    async with redis_wrapper.lock(f"lock:admin_titles:delete:{title_id}", timeout=10, blocking_timeout=3):
        await db.execute(delete(Title).where(Title.id == title_id))
        await db.commit()

    await log_audit_event(db, user=current_user, action="TITLES_DELETE", status="SUCCESS", request=request,
                          meta_data={"id": str(title_id)})
    return {"message": "Title deleted"}


# ---- Soft delete / restore (recycle bin) ------------------------------------
@router.post("/titles/{title_id}/soft-delete", summary="Soft-delete a title (recycle bin)")
@rate_limit("5/minute")
async def soft_delete_title(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    async with redis_wrapper.lock(f"lock:admin_titles:soft_delete:{title_id}", timeout=10, blocking_timeout=3):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")
        if getattr(t, "deleted_at", None) is not None:
            return {"message": "Already deleted"}
        await db.execute(update(Title).where(Title.id == title_id).values(deleted_at=func.now()))
        await db.commit()
    await log_audit_event(db, user=current_user, action="TITLES_DELETE_SOFT", status="SUCCESS", request=request,
                          meta_data={"id": str(title_id)})
    return {"message": "Soft-deleted"}


@router.post("/titles/{title_id}/restore", summary="Restore a soft-deleted title")
@rate_limit("5/minute")
async def restore_title(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    async with redis_wrapper.lock(f"lock:admin_titles:restore:{title_id}", timeout=10, blocking_timeout=3):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")
        if getattr(t, "deleted_at", None) is None:
            return {"message": "Already active"}
        await db.execute(update(Title).where(Title.id == title_id).values(deleted_at=None))
        await db.commit()
    await log_audit_event(db, user=current_user, action="TITLES_RESTORE", status="SUCCESS", request=request,
                          meta_data={"id": str(title_id)})
    return {"message": "Restored"}


# ---- Availability endpoints --------------------------------------------------
class AvailabilityWindowIn(BaseModel):
    window_start: datetime
    window_end: Optional[datetime] = None
    territory_mode: TerritoryMode = TerritoryMode.GLOBAL
    countries: Optional[List[str]] = None
    distribution: Optional[List[DistributionKind]] = None
    device_classes: Optional[List[DeviceClass]] = None
    rights: Optional[Dict[str, object]] = None


class AvailabilitySetIn(BaseModel):
    windows: List[AvailabilityWindowIn]


def _ser_availability(a: Availability) -> Dict[str, object]:
    return {
        "id": str(getattr(a, "id", "")),
        "window_start": getattr(a, "window_start", None),
        "window_end": getattr(a, "window_end", None),
        "territory_mode": str(getattr(a, "territory_mode", None)),
        "countries": getattr(a, "countries", None),
        "distribution": getattr(a, "distribution", None),
        "device_classes": getattr(a, "device_classes", None),
        "rights": getattr(a, "rights", None),
    }


@router.get("/titles/{title_id}/availability", summary="Get availability windows for a title")
@rate_limit("30/minute")
async def get_title_availability(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, object]]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response, seconds=0)

    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")
    rows = (await db.execute(select(Availability).where(Availability.title_id == title_id).order_by(Availability.window_start.asc()))).scalars().all() or []
    return [_ser_availability(a) for a in rows]


@router.put("/titles/{title_id}/availability", summary="Replace availability windows for a title")
@rate_limit("10/minute")
async def put_title_availability(
    title_id: UUID,
    payload: AvailabilitySetIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    async with redis_wrapper.lock(f"lock:admin_titles:availability:{title_id}", timeout=15, blocking_timeout=5):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")
        if getattr(t, "deleted_at", None) is not None:
            raise HTTPException(status_code=409, detail="Title is deleted; restore before changing availability")

        await db.execute(delete(Availability).where(Availability.title_id == title_id))
        for w in payload.windows:
            a = Availability(
                title_id=title_id,
                window_start=w.window_start,
                window_end=w.window_end,
                territory_mode=w.territory_mode,
                countries=(w.countries or None),
                distribution=(w.distribution or None),
                device_classes=(w.device_classes or None),
                rights=(w.rights or None),
            )
            db.add(a)
        await db.flush(); await db.commit()

    await log_audit_event(db, user=current_user, action="TITLES_AVAILABILITY_SET", status="SUCCESS", request=request,
                          meta_data={"id": str(title_id), "windows": len(payload.windows)})
    return {"message": "Availability updated", "count": len(payload.windows)}
