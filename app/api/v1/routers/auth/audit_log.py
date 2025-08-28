from __future__ import annotations

"""
Admin Audit Log API — hardened, production‑grade
===============================================

What this module provides
-------------------------
- **Admin‑only** listing of audit logs with rich filters.
- **Keyset (cursor) pagination** using ``timestamp`` + ``id`` (stable, fast).
- **Sensitive response headers** (no‑store) to prevent caching of PII.
- Optional Redis rate limiting on this admin endpoint (easy to add later).

How pagination works
--------------------
- Request accepts optional ``cursor`` query param in the form ``"<ISO-8601 timestamp>|<uuid>"``.
- Results are ordered **descending** by ``timestamp`` then ``id``.
- When more results exist, the API sets ``X-Next-Cursor`` response header you can
  pass back on the next call to continue.

Security notes
--------------
- Enforces an admin gate: ``is_admin`` **or** ``is_superuser`` **or** member of
  a role list containing ``"admin"``. Adjust as needed for your project.
- Applies ``Cache-Control: no-store`` to responses.
- Parses ``meta_data`` JSON safely; never evals arbitrary strings.
"""

from datetime import datetime
import json
from typing import List, Optional, Tuple
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_user
from app.db.models.audit_log import AuditLog
from app.db.models.user import User
from app.db.session import get_async_db
from app.schemas.audit import AuditLogOut
from app.security_headers import set_sensitive_cache

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"]) 


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


def _parse_cursor(cursor: str) -> Tuple[datetime, str]:
    """Parse a cursor of the form ``"<ISO>|<uuid>"``.

    Returns a tuple ``(timestamp, id_str)`` and raises ``ValueError`` on errors.
    """
    ts_str, id_str = cursor.split("|", 1)
    ts = datetime.fromisoformat(ts_str)
    # UUID validation; keep id as string for DB compare to avoid dialect quirks
    UUID(id_str)
    return ts, id_str


def _make_cursor(ts: datetime, id_str: str) -> str:
    return f"{ts.isoformat()}|{id_str}"


# ─────────────────────────────────────────────────────────────
# 📜 List audit logs (admin‑only, keyset pagination)
# ─────────────────────────────────────────────────────────────
@router.get("/audit", response_model=List[AuditLogOut])
async def list_audit_logs(
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    user_id: Optional[str] = Query(None, description="Filter by user UUID"),
    action: Optional[str] = Query(None, description="Filter by audit action"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by audit status (SUCCESS, FAILURE)"),
    start_time: Optional[datetime] = Query(None, description="Filter logs after this timestamp (inclusive)"),
    end_time: Optional[datetime] = Query(None, description="Filter logs before this timestamp (inclusive)"),
    limit: int = Query(100, ge=1, le=500, description="Max logs to return"),
    cursor: Optional[str] = Query(None, description='Pagination cursor: "<ISO-8601>|<uuid>"'),
    current_user: User = Depends(get_current_user),
) -> List[AuditLogOut]:
    """Retrieve filtered audit logs (admin‑only) with keyset pagination.

    Filters are combined with AND semantics. Results are ordered by
    ``timestamp DESC, id DESC``. If more results are available after ``limit``,
    the response will include an ``X-Next-Cursor`` header you can use to fetch
    the next page.
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
        stmt = stmt.filter(AuditLog.timestamp >= start_time)
    if end_time:
        stmt = stmt.filter(AuditLog.timestamp <= end_time)

    # Keyset pagination: timestamp/id DESC; apply cursor if provided
    stmt = stmt.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())

    if cursor:
        try:
            ts_cursor, id_cursor = _parse_cursor(cursor)
            # (ts, id) < (ts_cursor, id_cursor) in DESC order → older rows
            stmt = stmt.filter(
                or_(
                    AuditLog.timestamp < ts_cursor,
                    and_(AuditLog.timestamp == ts_cursor, AuditLog.id < id_cursor),
                )
            )
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid cursor")

    # Fetch limit + 1 to detect if there's another page
    result = await db.execute(stmt.limit(limit + 1))
    rows = result.scalars().all()

    has_more = len(rows) > limit
    rows = rows[:limit]

    if has_more and rows:
        last = rows[-1]
        response.headers["X-Next-Cursor"] = _make_cursor(last.timestamp, str(last.id))

    # Map to schema; parse meta_data JSON if stored as str
    out: List[AuditLogOut] = []
    for log in rows:
        meta = log.meta_data
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except json.JSONDecodeError:
                meta = None
        out.append(
            AuditLogOut(
                id=log.id,
                user_id=log.user_id,
                action=log.action,
                status=log.status,
                timestamp=log.timestamp,
                ip_address=getattr(log, "ip_address", None),
                user_agent=getattr(log, "user_agent", None),
                meta_data=meta,
                request_id=getattr(log, "request_id", None),
            )
        )

    return out


__all__ = ["router", "list_audit_logs"]
