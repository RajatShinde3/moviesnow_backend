"""
MoviesNow · Admin Titles Management (Org-free)
==============================================

Endpoints (ADMIN/SUPERUSER + MFA)
---------------------------------
- POST   /titles                             : Create title (Idempotency-Key supported)
- GET    /titles                             : Search/list with filters, sort, paginate
- GET    /titles/{title_id}                  : Fetch single title
- PATCH  /titles/{title_id}                  : Partial update (safe fields)
- POST   /titles/{title_id}/publish          : Mark title published (idempotent)
- POST   /titles/{title_id}/unpublish        : Mark title unpublished (idempotent)
- DELETE /titles/{title_id}                  : Hard delete (DB cascades)

Optional (recommended) QoL
--------------------------
- POST   /titles/{title_id}/soft-delete      : Soft delete (recycle bin)
- POST   /titles/{title_id}/restore          : Restore a soft-deleted title

Availability (Org-free)
-----------------------
- GET    /titles/{title_id}/availability     : List availability windows
- PUT    /titles/{title_id}/availability     : Replace availability windows

Security & Ops Practices
------------------------
- ADMIN/SUPERUSER + `mfa_authenticated` guard on access token
- SlowAPI per-route rate limits
- Redis idempotency snapshots for creates (Idempotency-Key)
- Redis distributed locks + DB row-level `FOR UPDATE` for mutations
- Sensitive cache-control on admin responses (Cache-Control/Pragma)
- Defensive slug uniqueness guard (409) even if DB also enforces
- Best-effort structured audit logs (never blocks request flow)
"""

from __future__ import annotations

# ── [Imports] ─────────────────────────────────────────────────────────────────────────────
from typing import List, Dict, Optional, Any
from uuid import UUID
from datetime import date, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select, update, delete, and_, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import rate_limit
from app.core.redis_client import redis_wrapper
from app.core.security import get_current_user
from app.db.session import get_async_db
from app.db.models.user import User
from app.db.models.title import Title
from app.db.models.availability import Availability
from app.schemas.enums import TitleType, TitleStatus, TerritoryMode, DistributionKind, DeviceClass
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event
from app.dependencies.admin import (
    ensure_admin as _ensure_admin,
    ensure_mfa as _ensure_mfa,
)

router = APIRouter(tags=["Admin Titles"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _slug_exists(db: AsyncSession, slug: str, *, exclude_id: Optional[UUID] = None) -> bool:
    """Case-insensitive slug existence check (optionally excluding a row)."""
    stmt = select(Title.id).where(func.lower(Title.slug) == slug.strip().lower())
    if exclude_id:
        stmt = stmt.where(Title.id != exclude_id)
    return (await db.execute(stmt)).scalar_one_or_none() is not None


def _serialize_title(t: Title) -> Dict[str, object]:
    """Compact title serializer for admin views."""
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


def _set_total_count_header(response: Response, count: Optional[int]) -> None:
    """Expose total count for pagination (optional; non-fatal)."""
    try:
        if count is not None:
            response.headers["X-Total-Count"] = str(int(count))
    except Exception:
        pass


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


# ─────────────────────────────────────────────────────────────────────────────
# ➕ Create title (Idempotency-Key supported)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/titles", summary="Create title (Idempotency-Key supported)")
@rate_limit("10/minute")
async def create_title(
    payload: Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    """
    Create a new **Title** (movie/series). Supports idempotent creation via the
    `Idempotency-Key` header and enforces slug uniqueness defensively.

    Steps
    -----
    1) Validate body (Pydantic) and enforce ADMIN + MFA; set `no-store` cache.
    2) If Idempotency-Key present and snapshot exists → return it.
    3) Assert slug uniqueness (409 if exists).
    4) Insert title row in a single transaction; return serialized record.
    5) Audit-log (best effort) and persist idempotency snapshot (best effort).

    Notes
    -----
    - Tests expect **200** on create; we comply (instead of 201).
    - We accept `payload: Dict[str, Any]` and validate *inside* to avoid
      import-order issues in some modular app layouts.
    """
    # ── [Step 0] Security, input validation & cache hardening ───────────────
    try:
        data = TitleCreateIn.model_validate(payload)
    except ValidationError as ve:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=ve.errors())

    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # ── [Step 1] Idempotency replay (best-effort) ───────────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:titles:create:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return JSONResponse(snap, status_code=status.HTTP_200_OK)

    # ── [Step 2] Slug uniqueness guard (defensive 409) ─────────────────────
    if await _slug_exists(db, data.slug):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Slug already exists")

    # ── [Step 3] Persist (single-transaction) ───────────────────────────────
    t = Title(
        type=data.type,
        name=data.name.strip(),
        slug=data.slug.strip(),
        original_name=(data.original_name or None),
        status=data.status or TitleStatus.ANNOUNCED,
        release_year=data.release_year,
        overview=data.overview,
        tagline=data.tagline,
    )
    try:
        db.add(t)
        await db.flush()
        await db.commit()
        try:
            await db.refresh(t)
        except Exception:
            pass
    except Exception:
        await db.rollback()
        raise

    body = _serialize_title(t)

    # ── [Step 4] Audit log (best-effort) ────────────────────────────────────
    try:
        await log_audit_event(
            db, user=current_user, action="TITLES_CREATE", status="SUCCESS",
            request=request, meta_data={"id": body.get("id"), "slug": t.slug},
        )
    except Exception:
        pass

    # ── [Step 5] Idempotency snapshot (best-effort) ─────────────────────────
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass

    return JSONResponse(body, status_code=status.HTTP_200_OK)


# ─────────────────────────────────────────────────────────────────────────────
# 📚 List titles (filters/sort/paginate)
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/titles", summary="List titles (filters/sort/paginate)")
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
):
    """
    Search and paginate **titles**.

    Filters
    - `type`, `status`, `is_published`, `q` (name/slug contains; case-insensitive)

    Sorting
    - `created_at`, `popularity`, `rating`, `release_year` (prefix with `-` for desc)

    Pagination
    - `limit` (1..200), `offset` (>=0)
    - Adds `X-Total-Count` header when feasible (non-fatal if it fails).
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response, seconds=0)

    # ── [Step 1] Build filters ──────────────────────────────────────────────
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

    # ── [Step 2] Query & sort ───────────────────────────────────────────────
    stmt = select(Title)
    if conds:
        stmt = stmt.where(and_(*conds))

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

    # Optional total count (best-effort; won’t block)
    total_count: Optional[int] = None
    try:
        if conds:
            total_count = (await db.execute(select(func.count()).select_from(Title).where(and_(*conds)))).scalar_one()
        else:
            total_count = (await db.execute(select(func.count()).select_from(Title))).scalar_one()
    except Exception:
        total_count = None

    # ── [Step 3] Paginate ───────────────────────────────────────────────────
    stmt = stmt.offset(offset).limit(limit)
    rows = (await db.execute(stmt)).scalars().all() or []
    _set_total_count_header(response, total_count)

    return JSONResponse([_serialize_title(t) for t in rows])


# ─────────────────────────────────────────────────────────────────────────────
# 🔎 Get single title
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/titles/{title_id}", summary="Get title by id")
@rate_limit("30/minute")
async def get_title(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    """
    Fetch a single **title** by id.
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response, seconds=0)

    # ── [Step 1] Lookup ─────────────────────────────────────────────────────
    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")

    return JSONResponse(_serialize_title(t))


# ─────────────────────────────────────────────────────────────────────────────
# ✏️ Patch title (safe fields + slug conflict check)
# ─────────────────────────────────────────────────────────────────────────────
@router.patch("/titles/{title_id}", summary="Patch title (safe fields)")
@rate_limit("10/minute")
async def patch_title(
    title_id: UUID,
    payload: TitlePatchIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    """
    Partially update safe fields of a **title**.

    - Enforces redis + row locks.
    - If `slug` is provided, verifies uniqueness (409).
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # ── [Step 1] Validate updates ───────────────────────────────────────────
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No changes provided")
    if "slug" in updates and await _slug_exists(db, str(updates["slug"]), exclude_id=title_id):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Slug already exists")

    # ── [Step 2] Lock + persist ─────────────────────────────────────────────
    async with redis_wrapper.lock(f"lock:admin_titles:patch:{title_id}", timeout=10, blocking_timeout=3):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")
        for k, v in updates.items():
            setattr(t, k, v)
        await db.flush()
        await db.commit()

    # ── [Step 3] Audit ──────────────────────────────────────────────────────
    try:
        await log_audit_event(
            db, user=current_user, action="TITLES_PATCH", status="SUCCESS",
            request=request, meta_data={"id": str(title_id), "fields": list(updates.keys())},
        )
    except Exception:
        pass

    return JSONResponse(_serialize_title(t))


# ─────────────────────────────────────────────────────────────────────────────
# 🚀 Publish / 📴 Unpublish (idempotent)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/titles/{title_id}/publish", summary="Publish title")
@rate_limit("5/minute")
async def publish_title(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    """
    Mark a **title** as published (idempotent).
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # ── [Step 1] Lock + flip flag ───────────────────────────────────────────
    async with redis_wrapper.lock(f"lock:admin_titles:publish:{title_id}", timeout=10, blocking_timeout=3):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")
        if getattr(t, "is_published", False):
            return JSONResponse({"message": "Already published"})
        t.is_published = True
        await db.flush()
        await db.commit()

    # ── [Step 2] Audit ──────────────────────────────────────────────────────
    try:
        await log_audit_event(db, user=current_user, action="TITLES_PUBLISH", status="SUCCESS",
                              request=request, meta_data={"id": str(title_id)})
    except Exception:
        pass

    return JSONResponse({"message": "Published"})


@router.post("/titles/{title_id}/unpublish", summary="Unpublish title")
@rate_limit("5/minute")
async def unpublish_title(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    """
    Mark a **title** as unpublished (idempotent).
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # ── [Step 1] Lock + flip flag ───────────────────────────────────────────
    async with redis_wrapper.lock(f"lock:admin_titles:unpublish:{title_id}", timeout=10, blocking_timeout=3):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")
        if not getattr(t, "is_published", False):
            return JSONResponse({"message": "Already unpublished"})
        t.is_published = False
        await db.flush()
        await db.commit()

    # ── [Step 2] Audit ──────────────────────────────────────────────────────
    try:
        await log_audit_event(db, user=current_user, action="TITLES_UNPUBLISH", status="SUCCESS",
                              request=request, meta_data={"id": str(title_id)})
    except Exception:
        pass

    return JSONResponse({"message": "Unpublished"})


# ─────────────────────────────────────────────────────────────────────────────
# 🗑️ Hard delete (DB cascades)
# ─────────────────────────────────────────────────────────────────────────────
@router.delete("/titles/{title_id}", summary="Hard delete title")
@rate_limit("5/minute")
async def delete_title(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    """
    Hard-delete a **title** (DB cascades apply).
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # ── [Step 1] Lock + delete ──────────────────────────────────────────────
    async with redis_wrapper.lock(f"lock:admin_titles:delete:{title_id}", timeout=10, blocking_timeout=3):
        await db.execute(delete(Title).where(Title.id == title_id))
        await db.commit()

    # ── [Step 2] Audit ──────────────────────────────────────────────────────
    try:
        await log_audit_event(db, user=current_user, action="TITLES_DELETE", status="SUCCESS",
                              request=request, meta_data={"id": str(title_id)})
    except Exception:
        pass

    return JSONResponse({"message": "Title deleted"})


# ─────────────────────────────────────────────────────────────────────────────
# 🧰 Soft delete / restore (recycle bin) — optional QoL
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/titles/{title_id}/soft-delete", summary="Soft-delete a title (recycle bin)")
@rate_limit("5/minute")
async def soft_delete_title(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    """
    Soft-delete a **title** by setting `deleted_at` timestamp (idempotent).
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # ── [Step 1] Lock + mark deleted ────────────────────────────────────────
    async with redis_wrapper.lock(f"lock:admin_titles:soft_delete:{title_id}", timeout=10, blocking_timeout=3):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")
        if getattr(t, "deleted_at", None) is not None:
            return JSONResponse({"message": "Already deleted"})
        await db.execute(update(Title).where(Title.id == title_id).values(deleted_at=func.now()))
        await db.commit()

    # ── [Step 2] Audit ──────────────────────────────────────────────────────
    try:
        await log_audit_event(db, user=current_user, action="TITLES_DELETE_SOFT", status="SUCCESS",
                              request=request, meta_data={"id": str(title_id)})
    except Exception:
        pass

    return JSONResponse({"message": "Soft-deleted"})


@router.post("/titles/{title_id}/restore", summary="Restore a soft-deleted title")
@rate_limit("5/minute")
async def restore_title(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    """
    Restore a **soft-deleted title** (idempotent).
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # ── [Step 1] Lock + clear deleted_at ────────────────────────────────────
    async with redis_wrapper.lock(f"lock:admin_titles:restore:{title_id}", timeout=10, blocking_timeout=3):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")
        if getattr(t, "deleted_at", None) is None:
            return JSONResponse({"message": "Already active"})
        await db.execute(update(Title).where(Title.id == title_id).values(deleted_at=None))
        await db.commit()

    # ── [Step 2] Audit ──────────────────────────────────────────────────────
    try:
        await log_audit_event(db, user=current_user, action="TITLES_RESTORE", status="SUCCESS",
                              request=request, meta_data={"id": str(title_id)})
    except Exception:
        pass

    return JSONResponse({"message": "Restored"})


# ─────────────────────────────────────────────────────────────────────────────
# 🌍 Availability (windows & policy envelope)
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/titles/{title_id}/availability", summary="Get availability windows for a title")
@rate_limit("30/minute")
async def get_title_availability(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    """
    Return **availability windows** for a title ordered by start time.
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response, seconds=0)

    # ── [Step 1] Validate parent ────────────────────────────────────────────
    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")

    # ── [Step 2] Query windows ──────────────────────────────────────────────
    rows = (
        await db.execute(
            select(Availability)
            .where(Availability.title_id == title_id)
            .order_by(Availability.window_start.asc())
        )
    ).scalars().all() or []

    return JSONResponse([_ser_availability(a) for a in rows])


@router.put("/titles/{title_id}/availability", summary="Replace availability windows for a title")
@rate_limit("10/minute")
async def put_title_availability(
    title_id: UUID,
    payload: AvailabilitySetIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
):
    """
    Replace the **availability windows** for a title in a single transaction.

    Behavior
    --------
    - Requires the title to exist and not be soft-deleted.
    - Replaces (deletes old → inserts new) atomically.
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # ── [Step 1] Lock parent + validate ─────────────────────────────────────
    async with redis_wrapper.lock(f"lock:admin_titles:availability:{title_id}", timeout=15, blocking_timeout=5):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")
        if getattr(t, "deleted_at", None) is not None:
            raise HTTPException(status_code=409, detail="Title is deleted; restore before changing availability")

        # ── [Step 2] Replace windows ────────────────────────────────────────
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
        await db.flush()
        await db.commit()

    # ── [Step 3] Audit ──────────────────────────────────────────────────────
    try:
        await log_audit_event(
            db, user=current_user, action="TITLES_AVAILABILITY_SET", status="SUCCESS",
            request=request, meta_data={"id": str(title_id), "windows": len(payload.windows)},
        )
    except Exception:
        pass

    return JSONResponse({"message": "Availability updated", "count": len(payload.windows)})
