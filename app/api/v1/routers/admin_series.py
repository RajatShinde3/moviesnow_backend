"""
MoviesNow · Admin Seasons & Episodes (Org-free)
==============================================

Endpoints (ADMIN/SUPERUSER + MFA)
---------------------------------
- POST   /admin/titles/{title_id}/seasons           : Create season (Idempotency-Key optional)
- GET    /admin/titles/{title_id}/seasons           : List seasons (paginate)
- GET    /admin/seasons/{season_id}                 : Get season
- PATCH  /admin/seasons/{season_id}                 : Update season (safe fields)
- DELETE /admin/seasons/{season_id}                 : Delete season
- POST   /admin/seasons/{season_id}/episodes        : Create episode (Idempotency-Key optional)
- GET    /admin/seasons/{season_id}/episodes        : List episodes (paginate)
- GET    /admin/episodes/{episode_id}               : Get episode
- PATCH  /admin/episodes/{episode_id}               : Update episode (safe fields)
- DELETE /admin/episodes/{episode_id}               : Delete episode

Security & Ops Practices
------------------------
- Enforce ADMIN/SUPERUSER and `mfa_authenticated` claim
- SlowAPI route limits; Response injected for header setting
- Redis idempotency (best-effort) for creates
- Redis locks + DB `FOR UPDATE` for race-free mutations
- Sensitive cache headers (`Cache-Control: no-store`)
- Best-effort audit logs (never block business flow)
"""

from __future__ import annotations

# ── [Imports] ─────────────────────────────────────────────────────────────────────────────
from typing import Optional, List, Dict
from uuid import UUID
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, update, delete, and_, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import rate_limit
from app.core.jwt import decode_token
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.db.models.user import User
from app.db.models.title import Title
from app.db.models.season import Season
from app.db.models.episode import Episode
from app.schemas.enums import TitleType
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event
from app.dependencies.admin import (
    is_admin as _is_admin,
    ensure_admin as _ensure_admin,
    ensure_mfa as _ensure_mfa,
)

# ── [Router] ─────────────────────────────────────────────────────────────────────────────
router = APIRouter(tags=["Admin Series"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Helpers
# ─────────────────────────────────────────────────────────────────────────────
 


def _ser_season(s: Season) -> Dict[str, object]:
    return {
        "id": str(s.id),
        "title_id": str(s.title_id),
        "season_number": s.season_number,
        "name": s.name,
        "slug": s.slug,
        "overview": s.overview,
        "release_date": s.release_date,
        "end_date": s.end_date,
        "episode_count": int(getattr(s, "episode_count", 0) or 0),
        "is_published": bool(getattr(s, "is_published", False)),
        "created_at": getattr(s, "created_at", None),
        "updated_at": getattr(s, "updated_at", None),
    }


def _ser_episode(e: Episode) -> Dict[str, object]:
    return {
        "id": str(e.id),
        "season_id": str(e.season_id),
        "title_id": str(e.title_id),
        "episode_number": e.episode_number,
        "name": e.name,
        "slug": e.slug,
        "overview": e.overview,
        "air_date": e.air_date,
        "runtime_minutes": e.runtime_minutes,
        "is_published": bool(getattr(e, "is_published", False)),
        "created_at": getattr(e, "created_at", None),
        "updated_at": getattr(e, "updated_at", None),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Schemas
# ─────────────────────────────────────────────────────────────────────────────
class SeasonCreateIn(BaseModel):
    season_number: int = Field(..., ge=1)
    name: Optional[str] = Field(None, max_length=255)
    slug: Optional[str] = Field(None, max_length=255)
    overview: Optional[str] = None
    release_date: Optional[date] = None
    end_date: Optional[date] = None


class SeasonPatchIn(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    slug: Optional[str] = Field(None, max_length=255)
    overview: Optional[str] = None
    release_date: Optional[date] = None
    end_date: Optional[date] = None
    is_published: Optional[bool] = None


class EpisodeCreateIn(BaseModel):
    episode_number: int = Field(..., ge=0)
    name: Optional[str] = Field(None, max_length=255)
    slug: Optional[str] = Field(None, max_length=255)
    overview: Optional[str] = None
    air_date: Optional[date] = None
    runtime_minutes: Optional[int] = Field(None, ge=0)


class EpisodePatchIn(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    slug: Optional[str] = Field(None, max_length=255)
    overview: Optional[str] = None
    air_date: Optional[date] = None
    runtime_minutes: Optional[int] = Field(None, ge=0)
    is_published: Optional[bool] = None


# ╔════════════════════════════════ Seasons ═══════════════════════════════╗

# ─────────────────────────────────────────────────────────────────────────────
# 📦 Create Season (Idempotency-Key supported)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/titles/{title_id}/seasons", summary="Create season (Idempotency-Key supported)")
@rate_limit("10/minute")
async def create_season(
    title_id: UUID,
    payload: SeasonCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    # ── [Step 0] Security gates & cache ──────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # ── [Step 1] Validate title & type ───────────────────────────────────────
    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")
    if getattr(t, "type", None) != TitleType.SERIES:
        raise HTTPException(status_code=400, detail="Title is not a SERIES")

    # ── [Step 2] Idempotency snapshot (best-effort) ─────────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:season:create:{title_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    # ── [Step 3] Duplicate guard (number & optional slug) ───────────────────
    async with redis_wrapper.lock(f"lock:season:create:{title_id}", timeout=10, blocking_timeout=3):
        # season_number unique per title
        dup = (
            await db.execute(
                select(Season).where(
                    and_(Season.title_id == title_id, Season.season_number == payload.season_number)
                )
            )
        ).scalar_one_or_none()
        if dup:
            raise HTTPException(status_code=409, detail="Season number already exists for this title")

        if payload.slug:
            slug_dup = (
                await db.execute(
                    select(Season).where(and_(Season.title_id == title_id, Season.slug == payload.slug))
                )
            ).scalar_one_or_none()
            if slug_dup:
                raise HTTPException(status_code=409, detail="Season slug already exists for this title")

        # ── [Step 4] Create row ─────────────────────────────────────────────
        s = Season(
            title_id=title_id,
            season_number=payload.season_number,
            name=payload.name,
            slug=payload.slug,
            overview=payload.overview,
            release_date=payload.release_date,
            end_date=payload.end_date,
        )
        db.add(s)
        await db.flush()
        await db.commit()
        try:
            await db.refresh(s)
        except Exception:
            pass

    body = _ser_season(s)
    await log_audit_event(
        db, user=current_user, action="SEASONS_CREATE", status="SUCCESS", request=request,
        meta_data={"season_id": body["id"], "title_id": str(title_id)}
    )
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    return body


# ─────────────────────────────────────────────────────────────────────────────
# 📚 List Seasons (paginate)
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/titles/{title_id}/seasons", summary="List seasons (paginate)")
@rate_limit("30/minute")
async def list_seasons(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # Optional: include per-season episode counts with one roundtrip
    ep_count_subq = (
        select(Episode.season_id, func.count(Episode.id).label("cnt"))
        .where(Episode.title_id == title_id)
        .group_by(Episode.season_id)
        .subquery()
    )

    rows = (
        await db.execute(
            select(Season, func.coalesce(ep_count_subq.c.cnt, 0).label("episode_count"))
            .where(Season.title_id == title_id)
            .outerjoin(ep_count_subq, ep_count_subq.c.season_id == Season.id)
            .order_by(Season.season_number)
            .offset(offset)
            .limit(limit)
        )
    ).all()

    out: List[Dict[str, object]] = []
    for s, cnt in rows:
        setattr(s, "episode_count", int(cnt or 0))
        out.append(_ser_season(s))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# 🔎 Get Season
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/seasons/{season_id}", summary="Get season")
@rate_limit("30/minute")
async def get_season(
    season_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    s = (await db.execute(select(Season).where(Season.id == season_id))).scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Season not found")
    return _ser_season(s)


# ─────────────────────────────────────────────────────────────────────────────
# ✏️ Patch Season (safe fields)
# ─────────────────────────────────────────────────────────────────────────────
@router.patch("/seasons/{season_id}", summary="Patch season (safe fields)")
@rate_limit("10/minute")
async def patch_season(
    season_id: UUID,
    payload: SeasonPatchIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    async with redis_wrapper.lock(f"lock:admin_season:patch:{season_id}", timeout=10, blocking_timeout=3):
        s = (
            await db.execute(select(Season).where(Season.id == season_id).with_for_update())
        ).scalar_one_or_none()
        if not s:
            raise HTTPException(status_code=404, detail="Season not found")

        updates = payload.model_dump(exclude_unset=True)
        if not updates:
            raise HTTPException(status_code=400, detail="No changes provided")

        # Optional duplicate guard: slug uniqueness within title
        new_slug = updates.get("slug")
        if new_slug:
            slug_dup = (
                await db.execute(
                    select(Season).where(
                        and_(
                            Season.title_id == s.title_id,
                            Season.slug == new_slug,
                            Season.id != season_id,
                        )
                    )
                )
            ).scalar_one_or_none()
            if slug_dup:
                raise HTTPException(status_code=409, detail="Season slug already exists for this title")

        for k, v in updates.items():
            setattr(s, k, v)

        await db.flush()
        await db.commit()

    await log_audit_event(
        db, user=current_user, action="SEASONS_PATCH", status="SUCCESS", request=request,
        meta_data={"season_id": str(season_id), "fields": list(updates.keys())}
    )
    return _ser_season(s)


# ─────────────────────────────────────────────────────────────────────────────
# 🗑️ Delete Season
# ─────────────────────────────────────────────────────────────────────────────
@router.delete("/seasons/{season_id}", summary="Delete season")
@rate_limit("5/minute")
async def delete_season(
    season_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    await db.execute(delete(Season).where(Season.id == season_id))
    await db.commit()
    await log_audit_event(
        db, user=current_user, action="SEASONS_DELETE", status="SUCCESS", request=request,
        meta_data={"season_id": str(season_id)}
    )
    return {"message": "Season deleted"}


# ╔════════════════════════════════ Episodes ═══════════════════════════════╗

# ─────────────────────────────────────────────────────────────────────────────
# 🎬 Create Episode (Idempotency-Key supported)
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/seasons/{season_id}/episodes", summary="Create episode (Idempotency-Key supported)")
@rate_limit("10/minute")
async def create_episode(
    season_id: UUID,
    payload: EpisodeCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # ── [Step 1] Validate season ────────────────────────────────────────────
    s = (await db.execute(select(Season).where(Season.id == season_id))).scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Season not found")

    # ── [Step 2] Idempotency snapshot ───────────────────────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:episode:create:{season_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    # ── [Step 3] Duplicate guard (number & optional slug) ───────────────────
    async with redis_wrapper.lock(f"lock:episode:create:{season_id}", timeout=10, blocking_timeout=3):
        dup = (
            await db.execute(
                select(Episode).where(
                    and_(Episode.season_id == season_id, Episode.episode_number == payload.episode_number)
                )
            )
        ).scalar_one_or_none()
        if dup:
            raise HTTPException(status_code=409, detail="Episode number already exists for this season")

        if payload.slug:
            slug_dup = (
                await db.execute(
                    select(Episode).where(
                        and_(Episode.season_id == season_id, Episode.slug == payload.slug)
                    )
                )
            ).scalar_one_or_none()
            if slug_dup:
                raise HTTPException(status_code=409, detail="Episode slug already exists for this season")

        # ── [Step 4] Create row ─────────────────────────────────────────────
        e = Episode(
            season_id=season_id,
            title_id=s.title_id,
            episode_number=payload.episode_number,
            name=payload.name,
            slug=payload.slug,
            overview=payload.overview,
            air_date=payload.air_date,
            runtime_minutes=payload.runtime_minutes,
        )
        db.add(e)
        await db.flush()
        await db.commit()
        try:
            await db.refresh(e)
        except Exception:
            pass

    body = _ser_episode(e)
    await log_audit_event(
        db, user=current_user, action="EPISODES_CREATE", status="SUCCESS", request=request,
        meta_data={"episode_id": body["id"], "season_id": str(season_id)}
    )
    if idem_key:
        try:
            await redis_wrapper.idempotency_set(idem_key, body, ttl_seconds=600)
        except Exception:
            pass
    return body


# ─────────────────────────────────────────────────────────────────────────────
# 📜 List Episodes (paginate)
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/seasons/{season_id}/episodes", summary="List episodes (paginate)")
@rate_limit("30/minute")
async def list_episodes(
    season_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, object]]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    rows = (
        await db.execute(
            select(Episode)
            .where(Episode.season_id == season_id)
            .order_by(Episode.episode_number)
            .offset(offset)
            .limit(limit)
        )
    ).scalars().all() or []
    return [_ser_episode(e) for e in rows]


# ─────────────────────────────────────────────────────────────────────────────
# 🔎 Get Episode
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/episodes/{episode_id}", summary="Get episode")
@rate_limit("30/minute")
async def get_episode(
    episode_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    e = (await db.execute(select(Episode).where(Episode.id == episode_id))).scalar_one_or_none()
    if not e:
        raise HTTPException(status_code=404, detail="Episode not found")
    return _ser_episode(e)


# ─────────────────────────────────────────────────────────────────────────────
# ✏️ Patch Episode (safe fields)
# ─────────────────────────────────────────────────────────────────────────────
@router.patch("/episodes/{episode_id}", summary="Patch episode (safe fields)")
@rate_limit("10/minute")
async def patch_episode(
    episode_id: UUID,
    payload: EpisodePatchIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    async with redis_wrapper.lock(f"lock:admin_episode:patch:{episode_id}", timeout=10, blocking_timeout=3):
        e = (
            await db.execute(select(Episode).where(Episode.id == episode_id).with_for_update())
        ).scalar_one_or_none()
        if not e:
            raise HTTPException(status_code=404, detail="Episode not found")

        updates = payload.model_dump(exclude_unset=True)
        if not updates:
            raise HTTPException(status_code=400, detail="No changes provided")

        # Optional duplicate guard: slug uniqueness within season
        new_slug = updates.get("slug")
        if new_slug:
            slug_dup = (
                await db.execute(
                    select(Episode).where(
                        and_(
                            Episode.season_id == e.season_id,
                            Episode.slug == new_slug,
                            Episode.id != episode_id,
                        )
                    )
                )
            ).scalar_one_or_none()
            if slug_dup:
                raise HTTPException(status_code=409, detail="Episode slug already exists for this season")

        for k, v in updates.items():
            setattr(e, k, v)

        await db.flush()
        await db.commit()

    await log_audit_event(
        db, user=current_user, action="EPISODES_PATCH", status="SUCCESS", request=request,
        meta_data={"episode_id": str(episode_id), "fields": list(updates.keys())}
    )
    return _ser_episode(e)


# ─────────────────────────────────────────────────────────────────────────────
# 🗑️ Delete Episode
# ─────────────────────────────────────────────────────────────────────────────
@router.delete("/episodes/{episode_id}", summary="Delete episode")
@rate_limit("5/minute")
async def delete_episode(
    episode_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    await db.execute(delete(Episode).where(Episode.id == episode_id))
    await db.commit()
    await log_audit_event(
        db, user=current_user, action="EPISODES_DELETE", status="SUCCESS", request=request,
        meta_data={"episode_id": str(episode_id)}
    )
    return {"message": "Episode deleted"}
