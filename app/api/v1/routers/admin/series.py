"""
MoviesNow · Admin Seasons & Episodes (Org-free)
==============================================

Production-grade Admin APIs to manage Seasons and Episodes under a SERIES
title. These endpoints assume an org-free environment but still enforce
strict administrative controls, concurrency safety, and cache hardening.

Endpoints (ADMIN/SUPERUSER + MFA)
---------------------------------
Seasons
- POST   /admin/titles/{title_id}/seasons           : Create season (Idempotency-Key optional)
- GET    /admin/titles/{title_id}/seasons           : List seasons (paginate; includes episode_count)
- GET    /admin/seasons/{season_id}                 : Get season
- PATCH  /admin/seasons/{season_id}                 : Update season (safe fields)
- DELETE /admin/seasons/{season_id}                 : Delete season

Episodes
- POST   /admin/seasons/{season_id}/episodes        : Create episode (Idempotency-Key optional)
- GET    /admin/seasons/{season_id}/episodes        : List episodes (paginate)
- GET    /admin/episodes/{episode_id}               : Get episode
- PATCH  /admin/episodes/{episode_id}               : Update episode (safe fields)
- DELETE /admin/episodes/{episode_id}               : Delete episode

Security & Operational Hardening
--------------------------------
- ADMIN/SUPERUSER role + MFA (`mfa_authenticated=True`) enforced on all routes.
- Sensitive cache headers on responses (no-store, no-cache), especially for admin data.
- Per-route SlowAPI rate limits (burst control and abuse prevention).
- Create endpoints are **best-effort idempotent** via `Idempotency-Key`.
- Redis distributed locks + DB `FOR UPDATE` to prevent race conditions.
- Defensive duplicate guards (season/episode number and slug uniqueness per parent).
- Structured audit logging (best-effort, never blocks request flow).

Conventions
-----------
- Handlers return `200 OK` on successful create to align with existing E2E tests.
- Input models are validated via Pydantic; patch models allow sparse updates.
- Slugs/names are accepted as provided but are trimmed server-side before persist.
"""


# ── [Imports] ─────────────────────────────────────────────────────────────────────────────
from typing import Optional, List, Dict
from uuid import UUID
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, update, delete, and_, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import rate_limit
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
    ensure_admin as _ensure_admin,
    ensure_mfa as _ensure_mfa,
)

# ── [Router] ─────────────────────────────────────────────────────────────────────────────
router = APIRouter(tags=["Admin • Series"])


# ─────────────────────────────────────────────────────────────────────────────
# 🧩 Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _trim(s: Optional[str]) -> Optional[str]:
    return s.strip() if isinstance(s, str) else s


def _ser_season(s: Season) -> Dict[str, object]:
    """Serialize a Season ORM row to a stable, API-facing dict."""
    return {
        "id": str(s.id),
        "title_id": str(s.title_id),
        "season_number": s.season_number,
        "name": _trim(s.name),
        "slug": _trim(s.slug),
        "overview": s.overview,
        "release_date": s.release_date,
        "end_date": s.end_date,
        "episode_count": int(getattr(s, "episode_count", 0) or 0),
        "is_published": bool(getattr(s, "is_published", False)),
        "created_at": getattr(s, "created_at", None),
        "updated_at": getattr(s, "updated_at", None),
    }


def _ser_episode(e: Episode) -> Dict[str, object]:
    """Serialize an Episode ORM row to a stable, API-facing dict."""
    return {
        "id": str(e.id),
        "season_id": str(e.season_id),
        "title_id": str(e.title_id),
        "episode_number": e.episode_number,
        "name": _trim(e.name),
        "slug": _trim(e.slug),
        "overview": e.overview,
        "air_date": e.air_date,
        "runtime_minutes": e.runtime_minutes,
        "is_published": bool(getattr(e, "is_published", False)),
        "created_at": getattr(e, "created_at", None),
        "updated_at": getattr(e, "updated_at", None),
    }


async def _ensure_series_title(db: AsyncSession, title_id: UUID) -> Title:
    """Load a Title and ensure it is of type SERIES."""
    t = (await db.execute(select(Title).where(Title.id == title_id))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Title not found")
    if getattr(t, "type", None) != TitleType.SERIES:
        raise HTTPException(status_code=400, detail="Title is not a SERIES")
    return t


# ─────────────────────────────────────────────────────────────────────────────
# 🧾 Schemas
# ─────────────────────────────────────────────────────────────────────────────

class SeasonCreateIn(BaseModel):
    """Payload to create a season under a SERIES title."""
    season_number: int = Field(..., ge=1, description="1-based season number")
    name: Optional[str] = Field(None, max_length=255, description="Optional display name")
    slug: Optional[str] = Field(None, max_length=255, description="Optional URL slug (unique within title)")
    overview: Optional[str] = Field(None, description="Short synopsis for the season")
    release_date: Optional[date] = Field(None, description="First air/release date")
    end_date: Optional[date] = Field(None, description="Final air date if concluded")


class SeasonPatchIn(BaseModel):
    """Sparse update for season fields (safe set)."""
    name: Optional[str] = Field(None, max_length=255)
    slug: Optional[str] = Field(None, max_length=255)
    overview: Optional[str] = None
    release_date: Optional[date] = None
    end_date: Optional[date] = None
    is_published: Optional[bool] = None


class EpisodeCreateIn(BaseModel):
    """Payload to create an episode under a season."""
    episode_number: int = Field(..., ge=0, description="0-based or 1-based depending on editorial policy")
    name: Optional[str] = Field(None, max_length=255)
    slug: Optional[str] = Field(None, max_length=255, description="Optional URL slug (unique within season)")
    overview: Optional[str] = None
    air_date: Optional[date] = None
    runtime_minutes: Optional[int] = Field(None, ge=0, description="Duration in minutes")


class EpisodePatchIn(BaseModel):
    """Sparse update for episode fields (safe set)."""
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
@router.post(
    "/titles/{title_id}/seasons",
    summary="Create season (Idempotency-Key supported)",
    response_model=Dict[str, object],
)
@rate_limit("10/minute")
async def create_season(
    title_id: UUID,
    payload: SeasonCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """
    Create a new Season for a given SERIES title.

    Steps
    -----
    0) Security gates (ADMIN + MFA) and response cache hardening.
    1) Ensure the parent title exists and is of type SERIES.
    2) Idempotency replay (best-effort) via `Idempotency-Key`.
    3) Concurrency-safe duplicate guards (number and slug within title).
    4) Persist season (single transaction).
    5) Audit & optional idempotency snapshot.
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    # ── [Step 1] Validate title & type ───────────────────────────────────────
    await _ensure_series_title(db, title_id)

    # ── [Step 2] Idempotency snapshot (best-effort) ─────────────────────────
    idem_hdr = request.headers.get("Idempotency-Key")
    idem_key = f"idemp:admin:season:create:{title_id}:{idem_hdr}" if idem_hdr else None
    if idem_key:
        snap = await redis_wrapper.idempotency_get(idem_key)
        if snap:
            return snap  # type: ignore[return-value]

    # ── [Step 3] Duplicate guard (number & optional slug) ───────────────────
    async with redis_wrapper.lock(f"lock:season:create:{title_id}", timeout=10, blocking_timeout=3):
        # Unique season_number within title
        dup = (
            await db.execute(
                select(Season).where(and_(Season.title_id == title_id, Season.season_number == payload.season_number))
            )
        ).scalar_one_or_none()
        if dup:
            raise HTTPException(status_code=409, detail="Season number already exists for this title")

        new_slug = _trim(payload.slug)
        if new_slug:
            slug_dup = (
                await db.execute(
                    select(Season).where(and_(Season.title_id == title_id, Season.slug == new_slug))
                )
            ).scalar_one_or_none()
            if slug_dup:
                raise HTTPException(status_code=409, detail="Season slug already exists for this title")

        # ── [Step 4] Create row ─────────────────────────────────────────────
        s = Season(
            title_id=title_id,
            season_number=payload.season_number,
            name=_trim(payload.name),
            slug=new_slug,
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

    # ── [Step 5] Audit & optional idempotent snapshot ───────────────────────
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
@router.get(
    "/titles/{title_id}/seasons",
    summary="List seasons (paginate)",
    response_model=List[Dict[str, object]],
)
@rate_limit("30/minute")
async def list_seasons(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(20, ge=1, le=200, description="Max rows to return"),
    offset: int = Query(0, ge=0, description="Rows to skip"),
) -> List[Dict[str, object]]:
    """
    Return seasons for a title, including an `episode_count` per season.

    Notes
    -----
    - Uses a subquery to avoid N+1 count queries.
    - Sorted by `season_number` ascending.
    """
    # ── [Step 0] Security & cache ───────────────────────────────────────────
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response, seconds=0)

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
            .order_by(Season.season_number.asc())
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
@router.get("/seasons/{season_id}", summary="Get season", response_model=Dict[str, object])
@rate_limit("30/minute")
async def get_season(
    season_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """
    Fetch a single season by id.
    """
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response, seconds=0)

    s = (await db.execute(select(Season).where(Season.id == season_id))).scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Season not found")
    return _ser_season(s)


# ─────────────────────────────────────────────────────────────────────────────
# ✏️ Patch Season (safe fields)
# ─────────────────────────────────────────────────────────────────────────────
@router.patch("/seasons/{season_id}", summary="Patch season (safe fields)", response_model=Dict[str, object])
@rate_limit("10/minute")
async def patch_season(
    season_id: UUID,
    payload: SeasonPatchIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """
    Update a season with a sparse payload.

    Steps
    -----
    0) Security & cache.
    1) Row lock season.
    2) Validate uniqueness for `slug` within title (if provided).
    3) Persist updates.
    4) Audit.
    """
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    async with redis_wrapper.lock(f"lock:admin_season:patch:{season_id}", timeout=10, blocking_timeout=3):
        s = (await db.execute(select(Season).where(Season.id == season_id).with_for_update())).scalar_one_or_none()
        if not s:
            raise HTTPException(status_code=404, detail="Season not found")

        updates = payload.model_dump(exclude_unset=True)
        if not updates:
            raise HTTPException(status_code=400, detail="No changes provided")

        # Optional duplicate guard: slug uniqueness within title
        new_slug = _trim(updates.get("slug"))
        if new_slug:
            slug_dup = (
                await db.execute(
                    select(Season).where(
                        and_(Season.title_id == s.title_id, Season.slug == new_slug, Season.id != season_id)
                    )
                )
            ).scalar_one_or_none()
            if slug_dup:
                raise HTTPException(status_code=409, detail="Season slug already exists for this title")
            updates["slug"] = new_slug

        # Normalize string fields
        if "name" in updates:
            updates["name"] = _trim(updates["name"])

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
@router.delete("/seasons/{season_id}", summary="Delete season", response_model=Dict[str, object])
@rate_limit("5/minute")
async def delete_season(
    season_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """
    Hard-delete a season by id.

    Notes
    -----
    - DB-level ON DELETE constraints/cascades will determine whether children
      (episodes) are removed automatically or the delete fails; surface errors
      via standard 409/500 mappings upstack if you implement them.
    """
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
@router.post(
    "/seasons/{season_id}/episodes",
    summary="Create episode (Idempotency-Key supported)",
    response_model=Dict[str, object],
)
@rate_limit("10/minute")
async def create_episode(
    season_id: UUID,
    payload: EpisodeCreateIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """
    Create a new Episode for a given season.

    Steps
    -----
    0) Security & cache.
    1) Validate season exists.
    2) Idempotency replay (best-effort).
    3) Concurrency-safe duplicate guards (episode_number and slug within season).
    4) Persist episode (single transaction); `title_id` derived from season.
    5) Audit & optional idempotency snapshot.
    """
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

        new_slug = _trim(payload.slug)
        if new_slug:
            slug_dup = (
                await db.execute(
                    select(Episode).where(and_(Episode.season_id == season_id, Episode.slug == new_slug))
                )
            ).scalar_one_or_none()
            if slug_dup:
                raise HTTPException(status_code=409, detail="Episode slug already exists for this season")

        # ── [Step 4] Create row ─────────────────────────────────────────────
        e = Episode(
            season_id=season_id,
            title_id=s.title_id,
            episode_number=payload.episode_number,
            name=_trim(payload.name),
            slug=new_slug,
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

    # ── [Step 5] Audit & optional idempotent snapshot ───────────────────────
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
@router.get(
    "/seasons/{season_id}/episodes",
    summary="List episodes (paginate)",
    response_model=List[Dict[str, object]],
)
@rate_limit("30/minute")
async def list_episodes(
    season_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(20, ge=1, le=200, description="Max rows to return"),
    offset: int = Query(0, ge=0, description="Rows to skip"),
) -> List[Dict[str, object]]:
    """
    Return episodes for a season ordered by `episode_number` ascending.
    """
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response, seconds=0)

    rows = (
        await db.execute(
            select(Episode)
            .where(Episode.season_id == season_id)
            .order_by(Episode.episode_number.asc())
            .offset(offset)
            .limit(limit)
        )
    ).scalars().all() or []
    return [_ser_episode(e) for e in rows]


# ─────────────────────────────────────────────────────────────────────────────
# 🔎 Get Episode
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/episodes/{episode_id}", summary="Get episode", response_model=Dict[str, object])
@rate_limit("30/minute")
async def get_episode(
    episode_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """
    Fetch a single episode by id.
    """
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response, seconds=0)

    e = (await db.execute(select(Episode).where(Episode.id == episode_id))).scalar_one_or_none()
    if not e:
        raise HTTPException(status_code=404, detail="Episode not found")
    return _ser_episode(e)


# ─────────────────────────────────────────────────────────────────────────────
# ✏️ Patch Episode (safe fields)
# ─────────────────────────────────────────────────────────────────────────────
@router.patch("/episodes/{episode_id}", summary="Patch episode (safe fields)", response_model=Dict[str, object])
@rate_limit("10/minute")
async def patch_episode(
    episode_id: UUID,
    payload: EpisodePatchIn,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """
    Update an episode with a sparse payload.

    Steps
    -----
    0) Security & cache.
    1) Row lock episode.
    2) Validate slug uniqueness within the season (if provided).
    3) Persist updates.
    4) Audit.
    """
    await _ensure_admin(current_user)
    await _ensure_mfa(request)
    set_sensitive_cache(response)

    async with redis_wrapper.lock(f"lock:admin_episode:patch:{episode_id}", timeout=10, blocking_timeout=3):
        e = (await db.execute(select(Episode).where(Episode.id == episode_id).with_for_update())).scalar_one_or_none()
        if not e:
            raise HTTPException(status_code=404, detail="Episode not found")

        updates = payload.model_dump(exclude_unset=True)
        if not updates:
            raise HTTPException(status_code=400, detail="No changes provided")

        # Optional duplicate guard: slug uniqueness within season
        new_slug = _trim(updates.get("slug"))
        if new_slug:
            slug_dup = (
                await db.execute(
                    select(Episode).where(and_(Episode.season_id == e.season_id, Episode.slug == new_slug, Episode.id != episode_id))
                )
            ).scalar_one_or_none()
            if slug_dup:
                raise HTTPException(status_code=409, detail="Episode slug already exists for this season")
            updates["slug"] = new_slug

        if "name" in updates:
            updates["name"] = _trim(updates["name"])

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
@router.delete("/episodes/{episode_id}", summary="Delete episode", response_model=Dict[str, object])
@rate_limit("5/minute")
async def delete_episode(
    episode_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, object]:
    """
    Hard-delete an episode by id.
    """
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
