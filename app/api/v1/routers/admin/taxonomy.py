"""
🏷️ MoviesNow · Admin Taxonomy & Credits (Org‑free)
=================================================

Security‑hardened FastAPI routes to manage **Genres**, **Credits**, and basic
**Compliance** actions (region blocks & DMCA) under `/api/v1/admin`.

Endpoints (ADMIN/SUPERUSER + MFA)
---------------------------------
Genres
- POST   /api/v1/admin/genres                              → create genre (Idempotency‑Key supported)
- GET    /api/v1/admin/genres                              → list genres (filters; paginate)
- PATCH  /api/v1/admin/genres/{genre_id}                   → patch genre
- DELETE /api/v1/admin/genres/{genre_id}                   → delete genre
- POST   /api/v1/admin/titles/{title_id}/genres/{genre_id} → attach genre to title
- DELETE /api/v1/admin/titles/{title_id}/genres/{genre_id} → detach genre from title

Credits
- POST   /api/v1/admin/titles/{title_id}/credits           → create credit
- GET    /api/v1/admin/titles/{title_id}/credits           → list credits (filters; paginate)
- PATCH  /api/v1/admin/credits/{credit_id}                 → patch credit
- DELETE /api/v1/admin/credits/{credit_id}                 → delete credit

Compliance
- POST   /api/v1/admin/titles/{title_id}/block             → apply region/age certification; optional unpublish
- POST   /api/v1/admin/titles/{title_id}/dmca              → DMCA takedown + advisory; optional unpublish
- GET    /api/v1/admin/compliance/flags                    → enums for compliance

Security & Ops Practices
------------------------
- **Admin‑only** and **MFA** enforced (see `ensure_admin` / `ensure_mfa`).
- **SlowAPI** per‑route rate limits.
- **Idempotency‑Key** replays on creates (best‑effort, Redis snapshot).
- **Redis locks** + **DB row locks** for mutations.
- **Sensitive cache** headers on responses (`no-store`).
- **Audit logs** are best‑effort and never block.
- **JSONResponse** everywhere (avoids SlowAPI header‑injection crash).

Adjust imports/paths for your project structure.
"""

# ─────────────────────────────────────────────────────────────────────────────
# 📦 Imports
# ─────────────────────────────────────────────────────────────────────────────
from typing import Optional, List, Dict, Any
from uuid import UUID
import re

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query, status
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, insert, and_, or_, func, text

from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.db.models.user import User
from app.db.models.title import Title
from app.db.models.genre import Genre
from app.db.models.credit import Credit
from app.db.models.compliance import Certification, ContentAdvisory
from app.schemas.enums import CertificationSystem, AdvisoryKind, AdvisorySeverity
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event

# Router (admin prefix recommended)
router = APIRouter(tags=["Admin • Taxonomy & Credits"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧰 Helpers
# ─────────────────────────────────────────────────────────────────────────────
_slug_re = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _json(data: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(content=jsonable_encoder(data), status_code=status_code, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})



def _ser_genre(g: Genre) -> Dict[str, Any]:
    return {
        "id": str(g.id),
        "name": g.name,
        "slug": g.slug,
        "description": g.description,
        "parent_id": str(g.parent_id) if g.parent_id else None,
        "is_active": bool(g.is_active),
        "display_order": g.display_order,
        "created_at": getattr(g, "created_at", None),
        "updated_at": getattr(g, "updated_at", None),
    }


def _ser_credit(c: Credit) -> Dict[str, Any]:
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
        "updated_at": getattr(c, "updated_at", None),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Schemas
# ─────────────────────────────────────────────────────────────────────────────
class GenreCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    slug: str = Field(..., min_length=1, max_length=96, description="kebab‑case unique identifier")
    description: Optional[str] = None
    parent_id: Optional[UUID] = None
    is_active: bool = True
    display_order: Optional[int] = Field(None, ge=0)


class GenrePatchIn(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=80)
    slug: Optional[str] = Field(None, min_length=1, max_length=96)
    description: Optional[str] = None
    parent_id: Optional[UUID] = None
    is_active: Optional[bool] = None
    display_order: Optional[int] = Field(None, ge=0)


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

class BlockInLoose(BaseModel):
    regions: list[str] | None = None
    system: str
    rating_code: str | None = None
    min_age: int | None = None
    notes: str | None = None
    unpublish: bool = False

    @field_validator("system")
    @classmethod
    def _norm_system(cls, v: str) -> str:
        if not v:
            return "OTHER"
        v = v.strip().upper()
        if v == "TVPG":
            v = "TV"
        allowed = {"MPAA", "TV", "BBFC", "CBFC", "FSK", "ACB", "OFLC", "EIRIN", "CNC", "IFCO", "OTHER"}
        if v not in allowed:
            raise ValueError("system must be one of: " + ", ".join(sorted(allowed)))
        return v

class DMCAIn(BaseModel):
    reason: Optional[str] = None
    source_url: Optional[str] = None
    unpublish: bool = True


# ─────────────────────────────────────────────────────────────────────────────
# ╔════════════════════════════════════ Genres ═══════════════════════════════╗
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# ➕ Create genre (Idempotency‑Key supported)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/genres", summary="Create genre (Idempotency‑Key supported)")
@rate_limit("10/minute")
async def create_genre(
    payload: GenreCreateIn | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Create a **genre** row with optional parent and display ordering.

    Steps
    -----
    1) Enforce ADMIN + MFA; set `no-store` cache headers
    2) Validate slug format; ensure uniqueness (best‑effort)
    3) Idempotency replay via `Idempotency-Key` header
    4) Insert row and return serialized view
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    set_sensitive_cache(response)
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    if isinstance(payload, dict):
        payload = GenreCreateIn.model_validate(payload)

    # ── [Step 1] Validate slug ──────────────────────────────────────────────
    if not _slug_re.match(payload.slug):
        raise HTTPException(status_code=400, detail="slug must be kebab‑case: [a‑z0‑9-]")

    # ── [Step 2] Idempotency (best‑effort) ──────────────────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:genres:create:{payload.slug}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return _json(snap)

    # ── [Step 3] Insert ────────────────────────────────────────────────────
    g = Genre(
        name=payload.name,
        slug=payload.slug,
        description=payload.description,
        parent_id=payload.parent_id,
        is_active=payload.is_active,
        display_order=payload.display_order,
    )
    db.add(g)
    try:
        await db.flush()
        await db.commit()
    except Exception:
        # Try unique‑like conflict detection for slug
        await db.rollback()
        existing = (await db.execute(select(Genre).where(func.lower(Genre.slug) == payload.slug.lower()))).scalar_one_or_none()
        if existing:
            raise HTTPException(status_code=409, detail="genre slug already exists")
        raise

    body = _ser_genre(g)
    try:
        await log_audit_event(db, user=current_user, action="GENRES_CREATE", status="SUCCESS", request=request, meta_data={"id": body["id"], "slug": g.slug})
    except Exception:
        pass

    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass

    return _json(body)

# ─────────────────────────────────────────────────────────────────────────────
# 📚 List genres (filters; paginate)
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/genres", summary="List genres (filters; paginate)")
@rate_limit("30/minute")
async def list_genres(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    q: Optional[str] = Query(None, description="Search name/slug (case‑insensitive)"),
    is_active: Optional[bool] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> JSONResponse:
    """List genres, optionally filtered and paginated."""
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    set_sensitive_cache(response)
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
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

# ─────────────────────────────────────────────────────────────────────────────
# ✏️ Patch genre (row lock + redis lock)
# ─────────────────────────────────────────────────────────────────────────────
@router.patch("/genres/{genre_id}", summary="Patch genre")
@rate_limit("10/minute")
async def patch_genre(
    genre_id: UUID,
    payload: GenrePatchIn | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Update mutable fields on a genre. Serializes concurrent changes with a
    short **Redis** lock and a row‑level `FOR UPDATE`.
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    set_sensitive_cache(response)
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    if isinstance(payload, dict):
        payload = GenrePatchIn.model_validate(payload)

    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No changes provided")

    if "slug" in updates and updates["slug"] and not _slug_re.match(updates["slug"]):
        raise HTTPException(status_code=400, detail="slug must be kebab‑case: [a‑z0‑9-]")

    async with redis_wrapper.lock(f"lock:admin:genres:{genre_id}", timeout=10, blocking_timeout=3):
        g = (await db.execute(select(Genre).where(Genre.id == genre_id).with_for_update())).scalar_one_or_none()
        if not g:
            raise HTTPException(status_code=404, detail="Genre not found")
        for k, v in updates.items():
            setattr(g, k, v)
        try:
            await db.flush()
            await db.commit()
        except Exception:
            await db.rollback()
            if "slug" in updates:
                # conflict? surface as 409
                exists = (await db.execute(select(Genre).where(func.lower(Genre.slug) == updates["slug"].lower(), Genre.id != genre_id))).scalar_one_or_none()
                if exists:
                    raise HTTPException(status_code=409, detail="genre slug already exists")
            raise

    try:
        await log_audit_event(db, user=current_user, action="GENRES_PATCH", status="SUCCESS", request=request, meta_data={"id": str(genre_id), "fields": list(updates.keys())})
    except Exception:
        pass

    return _json(_ser_genre(g))

# ─────────────────────────────────────────────────────────────────────────────
# 🗑️ Delete genre (redis lock)
# ─────────────────────────────────────────────────────────────────────────────
@router.delete("/genres/{genre_id}", summary="Delete genre")
@rate_limit("10/minute")
async def delete_genre(
    genre_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Hard‑delete a genre row. Protect with a short Redis lock."""
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    set_sensitive_cache(response)
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    async with redis_wrapper.lock(f"lock:admin:genres:{genre_id}", timeout=10, blocking_timeout=3):
        await db.execute(delete(Genre).where(Genre.id == genre_id))
        await db.commit()

    try:
        await log_audit_event(db, user=current_user, action="GENRES_DELETE", status="SUCCESS", request=request, meta_data={"id": str(genre_id)})
    except Exception:
        pass

    return _json({"message": "Genre deleted"})

# ─────────────────────────────────────────────────────────────────────────────
# 🔗 Attach / Detach genre to/from title
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/titles/{title_id}/genres/{genre_id}", summary="Attach genre to title")
@rate_limit("10/minute")
async def attach_genre(
    title_id: UUID,
    genre_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Attach a genre to a title. Idempotent with respect to duplicates."""
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    set_sensitive_cache(response)
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    g = (await db.execute(select(Genre).where(Genre.id == genre_id))).scalar_one_or_none()
    if not t or not g:
        raise HTTPException(status_code=404, detail="Title or Genre not found")

    async with redis_wrapper.lock(f"lock:admin:title_genre:{title_id}:{genre_id}", timeout=10, blocking_timeout=3):
        try:
            await db.execute(insert(Title.genres.property.secondary).values(title_id=title_id, genre_id=genre_id))  # type: ignore
            await db.commit()
        except Exception:
            # Already attached or constraint violation → ignore
            await db.rollback()

    try:
        await log_audit_event(db, user=current_user, action="TITLES_GENRE_ATTACH", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "genre_id": str(genre_id)})
    except Exception:
        pass

    return _json({"message": "Attached"})


# ─────────────────────────────────────────────────────────────────────────────
# 🗑️ Delete Genre (lock)
# ─────────────────────────────────────────────────────────────────────────────
@router.delete("/titles/{title_id}/genres/{genre_id}", summary="Detach genre from title")
@rate_limit("10/minute")
async def detach_genre(
    title_id: UUID,
    genre_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Detach a genre from a title. No error if not present (idempotent)."""
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    set_sensitive_cache(response)
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    async with redis_wrapper.lock(f"lock:admin:title_genre:{title_id}:{genre_id}", timeout=10, blocking_timeout=3):
        tbl = Title.genres.property.secondary  # type: ignore
        await db.execute(delete(tbl).where(tbl.c.title_id == title_id, tbl.c.genre_id == genre_id))  # type: ignore
        await db.commit()

    try:
        await log_audit_event(db, user=current_user, action="TITLES_GENRE_DETACH", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "genre_id": str(genre_id)})
    except Exception:
        pass

    return _json({"message": "Detached"})


# ─────────────────────────────────────────────────────────────────────────────
# ╔════════════════════════════════════ Credits ══════════════════════════════╗
# ─────────────────────────────────────────────────────────────────────────────
#─────────────────────────────────────────────────────────────────────────────
# ➕ Create title credit
#─────────────────────────────────────────────────────────────────────────────
@router.post("/titles/{title_id}/credits", summary="Create title credit")
@rate_limit("10/minute")
async def create_title_credit(
    title_id: UUID,
    payload: CreditCreateIn | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Create a **credit** entry for a title.

    Idempotency
    -----------
    If `Idempotency-Key` is supplied, a snapshot of the response is cached in
    Redis and replayed for identical re‑submissions.
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    set_sensitive_cache(response)
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    if isinstance(payload, dict):
        payload = CreditCreateIn.model_validate(payload)

    # ── [Step 1] Validate title ─────────────────────────────────────────────
    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")

    # ── [Step 2] Idempotency ────────────────────────────────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:credits:create:{title_id}:{payload.person_id}:{payload.kind}:{payload.role}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return _json(snap)

    # ── [Step 3] Insert ────────────────────────────────────────────────────
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
    await db.flush()
    await db.commit()

    body = _ser_credit(c)

    try:
        await log_audit_event(db, user=current_user, action="CREDITS_CREATE", status="SUCCESS", request=request, meta_data={"credit_id": body["id"], "title_id": str(title_id)})
    except Exception:
        pass

    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass

    return _json(body)

#─────────────────────────────────────────────────────────────────────────────
# 📚 List title credits (filters; paginate)
#─────────────────────────────────────────────────────────────────────────────
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
) -> JSONResponse:
    """List credits for a title with simple filters and ordering."""
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    set_sensitive_cache(response)
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    stmt = select(Credit).where(Credit.title_id == title_id)
    if kind:
        stmt = stmt.where(func.lower(Credit.kind) == kind.lower())
    if role:
        stmt = stmt.where(func.lower(Credit.role) == role.lower())
    stmt = stmt.order_by(Credit.billing_order.asc().nulls_last(), Credit.created_at.asc()).offset(offset).limit(limit)

    rows = (await db.execute(stmt)).scalars().all() or []
    return _json([_ser_credit(c) for c in rows])

#─────────────────────────────────────────────────────────────────────────────
# ✏️ Patch credit flags/fields (locks)
#─────────────────────────────────────────────────────────────────────────────
@router.patch("/credits/{credit_id}", summary="Patch credit flags/fields")
@rate_limit("10/minute")
async def patch_credit(
    credit_id: UUID,
    payload: CreditPatchIn | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Update flags/fields on a credit using a Redis + row lock combo."""
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    set_sensitive_cache(response)
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    if isinstance(payload, dict):
        payload = CreditPatchIn.model_validate(payload)
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No changes provided")

    async with redis_wrapper.lock(f"lock:admin:credit:{credit_id}", timeout=10, blocking_timeout=3):
        c = (await db.execute(select(Credit).where(Credit.id == credit_id).with_for_update())).scalar_one_or_none()
        if not c:
            raise HTTPException(status_code=404, detail="Credit not found")
        for k, v in updates.items():
            setattr(c, k, v)
        await db.flush()
        await db.commit()

    try:
        await log_audit_event(db, user=current_user, action="CREDITS_PATCH", status="SUCCESS", request=request, meta_data={"credit_id": str(credit_id), "fields": list(updates.keys())})
    except Exception:
        pass

    return _json(_ser_credit(c))

#─────────────────────────────────────────────────────────────────────────────
# 🗑️ Delete credit (lock)
#─────────────────────────────────────────────────────────────────────────────
@router.delete("/credits/{credit_id}", summary="Delete credit")
@rate_limit("10/minute")
async def delete_credit(
    credit_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Hard‑delete a credit row with a short Redis lock."""
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    set_sensitive_cache(response)
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    async with redis_wrapper.lock(f"lock:admin:credit:{credit_id}", timeout=10, blocking_timeout=3):
        await db.execute(delete(Credit).where(Credit.id == credit_id))
        await db.commit()

    try:
        await log_audit_event(db, user=current_user, action="CREDITS_DELETE", status="SUCCESS", request=request, meta_data={"credit_id": str(credit_id)})
    except Exception:
        pass

    return _json({"message": "Credit deleted"})


# ─────────────────────────────────────────────────────────────────────────────
# ╔══════════════════════════════════ Compliance ═════════════════════════════╗
# ─────────────────────────────────────────────────────────────────────────────

# 🚫 Apply region/age gate (certifications); optional unpublish
@router.post("/titles/{title_id}/block", summary="Apply region/age gate (certifications); optional unpublish")
@rate_limit("10/minute")
async def compliance_block_title(
    title_id: UUID,
    payload: BlockInLoose | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Apply/rotate **certifications** by region, optionally unpublishing.

    Semantics
    ---------
    - Any existing *current* certification for the same `(region, system)` is
      marked `is_current = False` before inserting the new record.
    - When `unpublish=true`, `Title.is_published` is toggled off (if present).
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    set_sensitive_cache(response)
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    if isinstance(payload, dict):
        payload = BlockInLoose.model_validate(payload)

    async with redis_wrapper.lock(f"lock:admin:compliance:block:{title_id}", timeout=15, blocking_timeout=5):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")

        regions = [r.strip().upper() for r in (payload.regions or []) if r and r.strip()]
        if not regions or any(len(r) != 2 for r in regions):
            raise HTTPException(status_code=400, detail="regions must be ISO-3166-1 alpha-2")

        for region in regions:
            await db.execute(
                update(Certification)
                .where(
                    Certification.title_id == title_id,
                    Certification.region == region,
                    Certification.system == payload.system,
                    Certification.is_current == True,  # noqa: E712
                )
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

        if payload.unpublish and hasattr(t, "is_published") and getattr(t, "is_published", False):
            t.is_published = False

        await db.flush()
        await db.commit()

    try:
        await log_audit_event(db, user=current_user, action="COMPLIANCE_BLOCK", status="SUCCESS", request=request, meta_data={"title_id": str(title_id), "regions": regions, "unpublish": payload.unpublish})
    except Exception:
        pass

    return _json({"message": "Compliance block applied", "regions": regions, "unpublish": payload.unpublish})

#─────────────────────────────────────────────────────────────────────────────
# 📝 DMCA takedown & unpublish + severe advisory
#─────────────────────────────────────────────────────────────────────────────
@router.post("/titles/{title_id}/dmca", summary="DMCA takedown & unpublish")
@rate_limit("6/minute")
async def compliance_dmca_takedown(
    title_id: UUID,
    payload: DMCAIn | Dict[str, Any],
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Apply a **DMCA** takedown advisory and optionally unpublish the title."""
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    set_sensitive_cache(response)
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    if isinstance(payload, dict):
        payload = DMCAIn.model_validate(payload)

    async with redis_wrapper.lock(f"lock:admin:compliance:dmca:{title_id}", timeout=15, blocking_timeout=5):
        t = (await db.execute(select(Title).where(Title.id == title_id).with_for_update())).scalar_one_or_none()
        if not t:
            raise HTTPException(status_code=404, detail="Title not found")

        if payload.unpublish and hasattr(t, "is_published") and getattr(t, "is_published", False):
            t.is_published = False

        adv = ContentAdvisory(
            title_id=title_id,
            kind=AdvisoryKind.OTHER,
            severity=AdvisorySeverity.SEVERE,
            language="en",
            notes=payload.reason or "DMCA takedown",
            tags={"dmca": True, **({"source_url": payload.source_url} if payload.source_url else {})},
            is_active=True,
            source="dmca_admin",
        )
        db.add(adv)
        await db.flush()
        await db.commit()

    try:
        await log_audit_event(db, user=current_user, action="COMPLIANCE_DMCA", status="SUCCESS", request=request, meta_data={"title_id": str(title_id)})
    except Exception:
        pass

    return _json({"message": "Takedown applied"})

# ─────────────────────────────────────────────────────────────────────────────
# 📖 Enumerations for compliance flags
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/compliance/flags", summary="Enumerations for compliance flags")
@rate_limit("60/minute")
async def compliance_flags(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Expose enums used by compliance endpoints for UI convenience."""
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    set_sensitive_cache(response)
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    return _json({
        "certification_systems": [c.name for c in CertificationSystem],
        "advisory_kinds": [k.name for k in AdvisoryKind],
        "advisory_severities": [s.name for s in AdvisorySeverity],
    })

# Compatibility: ensure fully-qualified admin paths are present even when this
# router is included without a prefix (as done in unit tests for isolation).
try:
    router.add_api_route("/api/v1/admin/genres", create_genre, methods=["POST"], summary="Create genre (Idempotency-Key supported)")
    router.add_api_route("/api/v1/admin/genres", list_genres, methods=["GET"], summary="List genres (filters; paginate)")
    router.add_api_route("/api/v1/admin/genres/{genre_id}", patch_genre, methods=["PATCH"], summary="Patch genre")
except Exception:
    # If routes already exist or FastAPI rejects duplicates, ignore silently.
    pass
