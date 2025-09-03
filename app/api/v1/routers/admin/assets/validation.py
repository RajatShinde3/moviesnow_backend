"""
🧪 MoviesNow · Admin Media Policy Validation
===========================================

Cross‑cutting, read‑only validation for a **title's** media setup: stream tiers,
subtitle defaults, and download metadata completeness.

Route (1)
---------
- GET /api/v1/admin/titles/{title_id}/validate-media → Run non‑destructive checks and return issues

Security & Operations
---------------------
- **Admin‑only** + **MFA** enforcement
- **SlowAPI** per‑route rate limit
- **Sensitive cache headers** (`no-store`) for results
- Explicit `JSONResponse` (works with SlowAPI header injection)

Result Shape
------------
{"issues": [
  {"severity": "error|warning", "code": "MISSING_TIER|...", ...},
  ...
]}

Adjust imports for your project tree if needed.
"""
from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# 📦 Imports
# ─────────────────────────────────────────────────────────────────────────────
from typing import Dict, List, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.limiter import rate_limit
from app.core.security import get_current_user
from app.db.session import get_async_db
from app.db.models.user import User
from app.db.models.media_asset import MediaAsset
from app.db.models.stream_variant import StreamVariant
from app.db.models.subtitle import Subtitle
from app.schemas.enums import MediaAssetKind, StreamProtocol, StreamTier
from app.security_headers import set_sensitive_cache

router = APIRouter(tags=["Admin • Validation & QA"])


def _json(data: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(data, status_code=status_code, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


# ─────────────────────────────────────────────────────────────────────────────
# ✅ Validate media policy for a title
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/titles/{title_id}/validate-media", summary="Validate media policy for a title")
@rate_limit("30/minute")
async def validate_media_policy(
    title_id: UUID,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Run non‑destructive checks against streaming and download policy.

    Checks
    ------
    - Exactly 3 **streamable** HLS tiers (480/720/1080) with **one** per tier.
    - No audio‑only rows marked as streamable.
    - Streamable rows must use protocol **HLS**.
    - Download‑type assets have `bytes_size` and `checksum_sha256`.
    - Subtitle defaults/forced do **not** conflict per language.

    Returns a compact list of `issues` (empty list means 👍).
    """
    # ── [Step 0] Cache hardening ─────────────────────────────────────────────
    set_sensitive_cache(response)

    # ── [Step 1] AuthZ + MFA ────────────────────────────────────────────────
    from app.dependencies.admin import ensure_admin as _ensure_admin, ensure_mfa as _ensure_mfa
    await _ensure_admin(current_user)
    await _ensure_mfa(request)

    issues: List[Dict[str, Any]] = []

    # ── [Step 2] Stream variants (expect exactly one per tier P480/P720/P1080)
    rows = (
        await db.execute(
            select(StreamVariant).where(StreamVariant.media_asset.has(MediaAsset.title_id == title_id))
        )
    ).scalars().all()

    streamable = [r for r in rows if getattr(r, "is_streamable", False)]
    tiers: Dict[str, List[str]] = {}
    per_asset_tier: Dict[tuple[str, str], int] = {}

    for r in streamable:
        t = getattr(r, "stream_tier", None)
        if t is None:
            issues.append({"severity": "error", "code": "STREAMABLE_NO_TIER", "id": str(r.id)})
            continue
        t_key = str(t.value if hasattr(t, "value") else t)
        tiers.setdefault(t_key, []).append(str(r.id))
        key = (str(getattr(r, "media_asset_id", "")), t_key)
        per_asset_tier[key] = per_asset_tier.get(key, 0) + 1
        if getattr(r, "is_audio_only", False):
            issues.append({"severity": "error", "code": "STREAMABLE_AUDIO_ONLY", "id": str(r.id)})
        if getattr(r, "protocol", None) != StreamProtocol.HLS:
            issues.append({"severity": "warning", "code": "STREAMABLE_NOT_HLS", "id": str(r.id)})

    for required in (StreamTier.P480, StreamTier.P720, StreamTier.P1080):
        key = required.value if hasattr(required, "value") else str(required)
        if key not in tiers:
            issues.append({"severity": "error", "code": "MISSING_TIER", "tier": key})
        elif len(tiers[key]) != 1:
            issues.append({"severity": "error", "code": "MULTI_TIER", "tier": key, "count": len(tiers[key])})

    for (asset_id, tier), count in per_asset_tier.items():
        if count > 1:
            issues.append({"severity": "error", "code": "DUP_STREAMABLE_PER_ASSET_TIER", "asset_id": asset_id, "tier": tier, "count": count})

    # ── [Step 3] Download assets completeness
    d_assets = (
        await db.execute(
            select(MediaAsset).where(
                MediaAsset.title_id == title_id,
                MediaAsset.kind.in_([MediaAssetKind.DOWNLOAD, MediaAssetKind.ORIGINAL, MediaAssetKind.VIDEO]),
            )
        )
    ).scalars().all()

    for a in d_assets:
        if getattr(a, "bytes_size", None) is None:
            issues.append({"severity": "warning", "code": "DOWNLOAD_SIZE_MISSING", "asset_id": str(a.id)})
        if not (getattr(a, "checksum_sha256", "") or "").strip():
            issues.append({"severity": "warning", "code": "DOWNLOAD_SHA_MISSING", "asset_id": str(a.id)})

    # ── [Step 4] Subtitle defaults / forced uniqueness per language
    subs = (
        await db.execute(select(Subtitle).where(Subtitle.title_id == title_id, Subtitle.active == True))  # noqa: E712
    ).scalars().all()

    from collections import defaultdict

    def_by_lang: Dict[str, int] = defaultdict(int)
    forced_by_lang: Dict[str, int] = defaultdict(int)

    for s in subs:
        if getattr(s, "is_default", False):
            def_by_lang[s.language] += 1
        if getattr(s, "is_forced", False):
            forced_by_lang[s.language] += 1

    for lang, c in def_by_lang.items():
        if c > 1:
            issues.append({"severity": "error", "code": "SUBTITLE_MULTI_DEFAULT", "language": lang, "count": c})
    for lang, c in forced_by_lang.items():
        if c > 1:
            issues.append({"severity": "error", "code": "SUBTITLE_MULTI_FORCED", "language": lang, "count": c})

    return _json({"issues": issues})
