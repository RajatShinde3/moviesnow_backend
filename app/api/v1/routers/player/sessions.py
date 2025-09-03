
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ MoviesNow · Player Telemetry                                             ║
# ║                                                                          ║
# ║ Endpoints (public + optional API key):                                   ║
# ║  - POST /player/sessions/start             → Start session (201)         ║
# ║  - POST /player/sessions/{id}/heartbeat    → QoE heartbeat (202)         ║
# ║  - POST /player/sessions/{id}/pause        → Pause event (202)           ║
# ║  - POST /player/sessions/{id}/resume       → Resume event (202)          ║
# ║  - POST /player/sessions/{id}/seek         → Seek event (202)            ║
# ║  - POST /player/sessions/{id}/complete     → Mark completed (202)        ║
# ║  - POST /player/sessions/{id}/error        → Error event (202)           ║
# ║  - GET  /player/sessions/{id}              → Session summary (200)       ║
# ╠──────────────────────────────────────────────────────────────────────────╣
# ║ Security & Ops                                                           
# ║  - Optional `X-API-Key` enforcement (if configured).                      
# ║  - All routes rate-limited via dependency.                                
# ║  - Responses are `Cache-Control: no-store` (telemetry is user-specific).  
# ║  - Start is idempotent if `Idempotency-Key` header is provided.          
# ║  - PII minimization: hash IP/UA unless explicitly enabled via env.       
# ║  - Neutral errors; repository exceptions don’t leak internals.           
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Player telemetry endpoints (start/heartbeat/pause/resume/seek/complete/error).

All endpoints are rate-limited and optionally gated behind a public API key.
Session data is stored via a pluggable repository (in-memory by default).
"""

import hashlib
import os
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status

from app.api.http_utils import (
    enforce_public_api_key,
    get_client_ip,
    json_no_store,
    rate_limit,
    sanitize_title_id,
)
from app.core.cache import TTLMap
from app.repositories.player import get_player_repository
from app.schemas.player import (
    CompleteInput,
    ErrorInput,
    HeartbeatInput,
    SeekInput,
    SessionSummary,
    StartSessionInput,
    StartSessionResponse,
)

# ─────────────────────────────────────────────────────────────────────────────
# Router
# ─────────────────────────────────────────────────────────────────────────────

router = APIRouter(
    prefix="/player/sessions",
    tags=["Playback"],
    responses={
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
        429: {"description": "Too Many Requests"},
        500: {"description": "Internal Server Error"},
    },
)

# ─────────────────────────────────────────────────────────────────────────────
# Config & helpers
# ─────────────────────────────────────────────────────────────────────────────

# In-memory, best-effort idempotency cache (10 min TTL per key)
_idem_cache = TTLMap(maxsize=16384)

def _bool_env(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.lower() in {"1", "true", "yes", "y"}

def _no_store_202() -> Response:
    """Return a 202 with `Cache-Control: no-store`."""
    resp = Response(status_code=status.HTTP_202_ACCEPTED)
    resp.headers["Cache-Control"] = "no-store"
    return resp

def _hash(value: str, *, salt_env: str = "PII_HASH_SALT") -> str:
    salt = os.environ.get(salt_env, "moviesnow:pii_salt")
    return hashlib.sha256(f"{salt}|{value}".encode("utf-8")).hexdigest()

def _anon_id_from_request(request: Request) -> str:
    """
    Derive a stable anonymous identifier.

    Default: sha256(ip|ua) with salt (no raw PII persisted).
    """
    ua = request.headers.get("user-agent") or request.headers.get("User-Agent") or ""
    ip = get_client_ip(request) or ""
    return _hash(f"{ip}|{ua}")[:32]

def _ip_fields_for_storage(request: Request) -> Dict[str, str]:
    """
    Decide how to persist network identifiers based on env:

    - TELEMETRY_STORE_RAW_IP=true → store `ip`
    - otherwise → store `ip_hash`
    """
    ip = get_client_ip(request) or ""
    if _bool_env("TELEMETRY_STORE_RAW_IP", False):
        return {"ip": ip}
    return {"ip_hash": _hash(ip)}

def _ua_fields_for_storage(request: Request) -> Dict[str, str]:
    """
    Decide how to persist user-agent based on env:

    - TELEMETRY_STORE_UA=true (default) → store `ua`
    - otherwise → store `ua_hash`
    """
    ua = request.headers.get("user-agent") or request.headers.get("User-Agent") or ""
    if _bool_env("TELEMETRY_STORE_UA", True):
        return {"ua": ua}
    return {"ua_hash": _hash(ua)}

def _validate_session_id() -> Path:
    """
    Constrain path param for session ids (defensive).
    Adjust regex/lengths to match your generator.
    """
    return Path(..., pattern=r"^[A-Za-z0-9_\-]{8,72}$", description="Playback session id")


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/start",
    response_model=StartSessionResponse,
    status_code=201,
    summary="Start a new playback session",
)
def start_session(
    request: Request,
    body: StartSessionInput,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Start a new playback session.

    Security
    --------
    - Auth: trusts `TELEMETRY_USER_ID_HEADER` (default `x-user-id`) when present.
      If missing and `ALLOW_ANON_TELEMETRY` is false → 401.
    - Idempotency: if `Idempotency-Key` is provided, identical retries will
      replay the same 201 response for 10 minutes.

    Steps
    -----
    1) Resolve user or anonymous identity
    2) Sanitize `title_id`
    3) Persist session via repository
    4) Return 201 with `no-store`
    """
    # (1) Resolve identity
    allow_anon = _bool_env("ALLOW_ANON_TELEMETRY", False)
    user_id_header = os.environ.get("TELEMETRY_USER_ID_HEADER", "x-user-id")
    user_id: Optional[str] = request.headers.get(user_id_header) or None
    if not user_id and not allow_anon:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Idempotency (best-effort)
    idem_key = request.headers.get("Idempotency-Key")
    if idem_key:
        cached = _idem_cache.get(f"player:start:{idem_key}")
        if cached:
            # Return stored response as-is (already no-store)
            return json_no_store(cached, status_code=201)

    # (2) Sanitize title id
    tid = sanitize_title_id(body.title_id)

    # (3) Persist session
    repo = get_player_repository()
    try:
        rec = repo.start_session(
            user_id=user_id,
            anon_id=None if user_id else _anon_id_from_request(request),
            title_id=tid,
            quality=body.quality.value,
            device=(body.device.dict(exclude_none=True) if body.device else {}),
            playback={
                "type": body.playback_type or "stream",
                "position_sec": body.position_sec or 0.0,
                **_ip_fields_for_storage(request),
                **_ua_fields_for_storage(request),
                "network": body.network.dict(exclude_none=True) if body.network else {},
            },
        )
    except Exception:
        # Neutral internal error
        raise HTTPException(status_code=500, detail="Could not start session")

    # (4) Build response model (keep schema contract)
    payload = StartSessionResponse(
        id=rec["id"],
        title_id=rec["title_id"],
        user_id=rec.get("user_id"),
        anon_id=rec.get("anon_id"),
        created_at=rec["created_at"],
        status=rec["status"],
    ).dict()

    # Store idempotency snapshot
    if idem_key:
        _idem_cache.set(f"player:start:{idem_key}", payload, ttl=600)

    return json_no_store(payload, status_code=201)


@router.post(
    "/{session_id}/heartbeat",
    status_code=202,
    summary="Send playback heartbeat with QoE metrics",
)
def heartbeat(
    session_id: str = _validate_session_id(),
    body: HeartbeatInput = ...,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Send playback heartbeat with QoE metrics.

    Notes
    -----
    - Returns `202 Accepted`; body is empty.
    - Server adds no-store to prevent caching.
    """
    repo = get_player_repository()
    try:
        ok = repo.heartbeat(session_id, body.dict(exclude_none=True))
    except Exception:
        raise HTTPException(status_code=500, detail="Could not record heartbeat")
    if not ok:
        raise HTTPException(status_code=404, detail="Session not found")
    return _no_store_202()


@router.post(
    "/{session_id}/pause",
    status_code=202,
    summary="Record a pause event",
)
def pause(
    session_id: str = _validate_session_id(),
    body: HeartbeatInput = ...,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Record a pause event (with position).

    Steps
    -----
    1) Build event payload
    2) Append to session timeline
    3) Return 202 (no-store)
    """
    repo = get_player_repository()
    payload: Dict = body.dict(exclude_none=True)
    payload["event"] = "pause"
    payload["playing"] = False
    try:
        ok = repo.append_event(session_id, "pause", payload)
    except Exception:
        raise HTTPException(status_code=500, detail="Could not record pause")
    if not ok:
        raise HTTPException(status_code=404, detail="Session not found")
    return _no_store_202()


@router.post(
    "/{session_id}/resume",
    status_code=202,
    summary="Record a resume event",
)
def resume(
    session_id: str = _validate_session_id(),
    body: HeartbeatInput = ...,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Record a resume event (with position).

    Steps
    -----
    1) Build event payload
    2) Append to session timeline
    3) Return 202 (no-store)
    """
    repo = get_player_repository()
    payload: Dict = body.dict(exclude_none=True)
    payload["event"] = "resume"
    payload["playing"] = True
    try:
        ok = repo.append_event(session_id, "resume", payload)
    except Exception:
        raise HTTPException(status_code=500, detail="Could not record resume")
    if not ok:
        raise HTTPException(status_code=404, detail="Session not found")
    return _no_store_202()


@router.post(
    "/{session_id}/seek",
    status_code=202,
    summary="Record a seek event",
)
def seek(
    session_id: str = _validate_session_id(),
    body: SeekInput = ...,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Record a seek event.

    Returns
    -------
    202 Accepted
    """
    repo = get_player_repository()
    try:
        ok = repo.append_event(session_id, "seek", body.dict(exclude_none=True))
    except Exception:
        raise HTTPException(status_code=500, detail="Could not record seek")
    if not ok:
        raise HTTPException(status_code=404, detail="Session not found")
    return _no_store_202()


@router.post(
    "/{session_id}/complete",
    status_code=202,
    summary="Mark a playback session as completed",
)
def complete(
    session_id: str = _validate_session_id(),
    body: CompleteInput = ...,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Mark a playback session as completed (aggregates final stats).

    Returns
    -------
    202 Accepted
    """
    repo = get_player_repository()
    try:
        ok = repo.complete(session_id, body.dict(exclude_none=True))
    except Exception:
        raise HTTPException(status_code=500, detail="Could not complete session")
    if not ok:
        raise HTTPException(status_code=404, detail="Session not found")
    return _no_store_202()


@router.post(
    "/{session_id}/error",
    status_code=202,
    summary="Report a player error",
)
def error(
    session_id: str = _validate_session_id(),
    body: ErrorInput = ...,
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Report a player error (kept on session as `last_error`).

    Notes
    -----
    - Consider server-side truncation/normalization in repository to avoid
      unbounded payload sizes or sensitive data leakage.
    """
    repo = get_player_repository()
    try:
        ok = repo.append_event(session_id, "error", body.dict(exclude_none=True))
    except Exception:
        raise HTTPException(status_code=500, detail="Could not record error")
    if not ok:
        raise HTTPException(status_code=404, detail="Session not found")
    return _no_store_202()


@router.get(
    "/{session_id}",
    response_model=SessionSummary,
    summary="Return a playback session summary",
)
def get_session(
    session_id: str = _validate_session_id(),
    _rl=Depends(rate_limit),
    _key=Depends(enforce_public_api_key),
):
    """
    Return a playback session summary.

    Caching
    -------
    - `no-store` to prevent caching of user-specific telemetry.
    """
    repo = get_player_repository()
    try:
        rec = repo.get_session(session_id)
    except Exception:
        raise HTTPException(status_code=500, detail="Could not fetch session")
    if not rec:
        raise HTTPException(status_code=404, detail="Session not found")
    return json_no_store(SessionSummary(**rec).dict())
