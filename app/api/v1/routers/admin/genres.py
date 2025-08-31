from __future__ import annotations

"""
Admin: Additional Genre operations

Adds a safe delete-by-slug endpoint with optional force-detach behavior.
Keeps parity with existing admin taxonomy routes while offering slug-based delete.
"""

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query
from sqlalchemy import select, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.core.redis_client import redis_wrapper
from app.db.session import get_async_db
from app.db.models.user import User
from app.db.models.genre import Genre
from app.security_headers import set_sensitive_cache
from app.services.audit_log_service import log_audit_event


router = APIRouter(tags=["Admin Genres"])


def _is_admin(user: User) -> bool:
    try:
        from app.schemas.enums import OrgRole
        return getattr(user, "role", None) in {OrgRole.ADMIN, OrgRole.SUPERUSER}
    except Exception:
        return bool(getattr(user, "is_superuser", False))


async def _ensure_admin(user: User) -> None:
    if not _is_admin(user):
        raise HTTPException(status_code=403, detail="Insufficient permissions")


@router.delete("/genres/{slug}", summary="Delete a genre by slug (safety checks)")
@rate_limit("10/minute")
async def delete_genre_by_slug(
    slug: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    force: bool = Query(False, description="Force delete: detach from titles then delete"),
) -> Dict[str, str]:
    await _ensure_admin(current_user)
    set_sensitive_cache(response)

    g = (await db.execute(select(Genre).where(func.lower(Genre.slug) == slug.strip().lower()))).scalar_one_or_none()
    if not g:
        raise HTTPException(status_code=404, detail="Genre not found")

    try:
        attached = len(getattr(g, "titles", []) or [])
    except Exception:
        attached = 0

    if attached and not force:
        raise HTTPException(status_code=409, detail="Genre attached to titles; pass force=true to detach and delete")

    async with redis_wrapper.lock(f"lock:admin:genre_delete:{slug.lower()}", timeout=10, blocking_timeout=3):
        if attached and force:
            try:
                tbl = Genre.titles.property.secondary  # type: ignore
                await db.execute(delete(tbl).where(tbl.c.genre_id == g.id))  # type: ignore
            except Exception:
                pass
        await db.execute(delete(Genre).where(Genre.id == g.id))
        await db.commit()

    await log_audit_event(db, user=current_user, action="GENRE_DELETE", status="SUCCESS", request=request,
                          meta_data={"slug": slug, "force": force, "attached": attached})
    return {"message": "Deleted"}


__all__ = ["router"]

