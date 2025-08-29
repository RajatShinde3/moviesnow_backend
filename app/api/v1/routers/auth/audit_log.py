# app/api/v1/admin/audit_logs.py
from __future__ import annotations

"""
Admin Audit Log API — hardened, production‑grade (MoviesNow, org‑free)
=====================================================================

What this module provides
-------------------------
- **Admin‑only** listing of audit logs with rich filters.
- **Keyset (cursor) pagination** using `occurred_at` + `id` (stable, fast).
- **Sensitive response headers** (`no-store`) to prevent caching of PII.

Pagination
----------
- Query accepts optional `cursor` in the form `"<ISO-8601 timestamp>|<uuid>"`.
- Results are ordered **descending** by `occurred_at` then `id`.
- When more results exist, the API sets `X-Next-Cursor` response header for the
  next request.

Security
--------
- Enforces an admin gate: `is_admin` **or** `is_superuser` **or** roles contains
  `"admin"`. Adjust to your schema as needed.
- Applies `Cache-Control: no-store`.
- Handles `metadata_json` safely; never evals arbitrary strings.
"""

from datetime import datetime
from typing import List, Optional, Tuple
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status, Request
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.db.models.audit_log import AuditLog
from app.db.models.user import User
from app.db.session import get_async_db
from app.schemas.audit import AuditLogOut
from app.security_headers import set_sensitive_cache

router = APIRouter(prefix="/audit-logs", tags=["Admin Audit Logs"])  # admin scope


# ─────────────────────────────────────────────────────────────
# 🔧 Helpers
# ─────────────────────────────────────────────────────────────

def _is_admin(user: User) -> bool:
    """Best‑effort admin check supporting multiple flags/shapes.

    Adjust to your schema (e.g., is_admin / is_superuser / roles).
    """
    return bool(
        getattr(user, "is_admin", False)
        or getattr(user, "is_superuser", False)
        or ("admin" in (getattr(user, "roles", []) or []))
    )


def _parse_iso8601(ts: str) -> datetime:
    # Accept trailing 'Z' and offsets
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def _parse_cursor(cursor: str) -> Tuple[datetime, UUID]:
    """Parse a cursor of the form `"<ISO>|<uuid>"`.

    Returns `(timestamp, uuid)` and raises `ValueError` on errors.
    """
    ts_str, id_str = cursor.split("|", 1)
    ts = _parse_iso8601(ts_str)
    return ts, UUID(id_str)


def _make_cursor(ts: datetime, id_val: UUID) -> str:
    return f"{ts.isoformat()}|{id_val}"


# ─────────────────────────────────────────────────────────────
# 📜 List audit logs (admin‑only, keyset pagination)
# ─────────────────────────────────────────────────────────────
@router.get("/audit", response_model=List[AuditLogOut], summary="List audit logs (admin‑only)")
@rate_limit("60/minute")
async def list_audit_logs(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    user_id: Optional[UUID] = Query(None, description="Filter by user UUID"),
    action: Optional[str] = Query(None, description="Filter by audit action"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by audit status (SUCCESS, FAILURE)"),
    start_time: Optional[datetime] = Query(None, description="Filter logs after this timestamp (inclusive)"),
    end_time: Optional[datetime] = Query(None, description="Filter logs before this timestamp (inclusive)"),
    limit: int = Query(100, ge=1, le=500, description="Max logs to return"),
    cursor: Optional[str] = Query(None, description='Pagination cursor: "<ISO-8601>|<uuid>"'),
    current_user: User = Depends(get_current_user),
) -> List[AuditLogOut]:
    """Retrieve filtered audit logs (admin‑only) with **keyset pagination**.

    Filters use AND semantics. Results are ordered by `occurred_at DESC, id DESC`.
    If more results are available after `limit`, `X-Next-Cursor` header is set.
    """
    # Security: admin gate
    if not _is_admin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access forbidden")

    # Sensitive content — disable caches
    set_sensitive_cache(response)

    stmt = select(AuditLog)

    # Dynamic filters
    if user_id:
        stmt = stmt.filter(AuditLog.user_id == user_id)
    if action:
        stmt = stmt.filter(AuditLog.action == action)
    if status_filter:
        stmt = stmt.filter(AuditLog.status == status_filter)
    if start_time:
        stmt = stmt.filter(AuditLog.occurred_at >= start_time)
    if end_time:
        stmt = stmt.filter(AuditLog.occurred_at <= end_time)

    # Order: newest first
    stmt = stmt.order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())

    # Keyset pagination
    if cursor:
        try:
            ts_cursor, id_cursor = _parse_cursor(cursor)
            stmt = stmt.filter(
                or_(
                    AuditLog.occurred_at < ts_cursor,
                    and_(AuditLog.occurred_at == ts_cursor, AuditLog.id < id_cursor),
                )
            )
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid cursor")

    # Fetch limit + 1 to detect more pages
    result = await db.execute(stmt.limit(limit + 1))
    rows = result.scalars().all()

    has_more = len(rows) > limit
    rows = rows[:limit]

    if has_more and rows:
        last = rows[-1]
        response.headers["X-Next-Cursor"] = _make_cursor(last.occurred_at, last.id)

    # Map to schema; handle JSON/JSONB gracefully
    out: List[AuditLogOut] = []
    for log in rows:
        meta = getattr(log, "metadata_json", None)
        out.append(
            AuditLogOut(
                id=log.id,
                user_id=log.user_id,
                action=log.action,
                status=log.status,
                timestamp=log.occurred_at,
                ip_address=getattr(log, "ip_address", None),
                user_agent=getattr(log, "user_agent", None),
                meta_data=meta,
                request_id=getattr(log, "request_id", None),
            )
        )

    return out


__all__ = ["router", "list_audit_logs"]
