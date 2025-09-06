from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# 🌐 Public · JWKS (.well-known/jwks.json)
# ─────────────────────────────────────────────────────────────────────────────
"""
Serve the public JSON Web Key Set (JWKS) used by clients to verify signatures.

Highlights
----------
• Strong ETag (quoted SHA-256 over canonical JSON) + conditional GET (304).
• CDN-friendly caching: public, max-age + s-maxage, SWR for edge friendliness.
• Minimal hardening headers (nosniff) and a stable, minified, sorted JSON body.
"""

from typing import Any, Optional
import hashlib
import json
import os

from fastapi import APIRouter, Request, Response, status

from app.services.jwks_service import get_public_jwks

router = APIRouter(tags=["Public · JWKS"])

# ─────────────────────────────────────────────────────────────────────────────
# ⚙️ Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _compute_etag(payload: Any) -> str:
    """Strong ETag: quoted SHA-256 of canonical (sorted/minified) JSON."""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"\"{hashlib.sha256(raw).hexdigest()}\""


def _parse_inm(value: Optional[str]) -> list[str]:
    """Parse If-None-Match into a list of opaque validator strings."""
    if not value:
        return []
    return [p.strip() for p in value.split(",") if p.strip()]


# ╔════════════════════════════════ Route: Public JWKS ═══════════════════════╗
# ║ 🔑📜  GET /.well-known/jwks.json                                          ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
@router.get(
    "/.well-known/jwks.json",
    summary="Public JWKS (JSON Web Key Set)",
    responses={
        200: {"description": "OK"},
        304: {"description": "Not Modified"},
    },
)
async def jwks(request: Request) -> Response:
    """
    Return the current public JWKS used by clients to verify signatures.

    Caching
    -------
    • Strong ETag with conditional GET (304 on match).
    • `Cache-Control: public, max-age=..., s-maxage=..., stale-while-revalidate=30`.
    """
    data = await get_public_jwks()
    body = json.dumps(data, sort_keys=True, separators=(",", ":"))
    etag = _compute_etag(data)

    inm = _parse_inm(request.headers.get("If-None-Match") or request.headers.get("if-none-match"))
    ttl = int(os.getenv("JWKS_CACHE_TTL", "60") or 60)

    base_headers = {
        "ETag": etag,
        "Cache-Control": f"public, max-age={ttl}, s-maxage={ttl}, stale-while-revalidate=30",
        "Vary": "Accept, If-None-Match",
        "X-Content-Type-Options": "nosniff",
    }

    if "*" in inm or etag in inm:
        # 304: no body, but include validators + cache headers
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, media_type="application/json", headers=base_headers)

    return Response(content=body, media_type="application/json", headers=base_headers)


__all__ = ["router"]
