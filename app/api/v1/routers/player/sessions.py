from __future__ import annotations

import hashlib
import os
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response

from app.api.http_utils import enforce_public_api_key, get_client_ip, json_no_store, rate_limit, sanitize_title_id
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


router = APIRouter(prefix="/player/sessions", tags=["Playback"], responses={404: {"description": "Not found"}})


def _anon_id_from_request(request: Request) -> str:
    ua = request.headers.get("user-agent") or request.headers.get("User-Agent") or ""
    ip = get_client_ip(request)
    raw = f"{ip}|{ua}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


@router.post("/start", response_model=StartSessionResponse, status_code=201)
def start_session(request: Request, body: StartSessionInput, _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Start a new playback session.

    - Associates session with a user id from a trusted header (configurable) or an anonymous id, depending on `ALLOW_ANON_TELEMETRY`.
    - Records basic device/network context for analytics.
    - Returns a session id for subsequent telemetry events.
    """
    allow_anon = os.environ.get("ALLOW_ANON_TELEMETRY") in {"1", "true", "True"}
    user_id_header = os.environ.get("TELEMETRY_USER_ID_HEADER", "x-user-id")
    user_id = request.headers.get(user_id_header) or None
    if not user_id and not allow_anon:
        raise HTTPException(status_code=401, detail="Authentication required")

    tid = sanitize_title_id(body.title_id)
    repo = get_player_repository()
    rec = repo.start_session(
        user_id=user_id,
        anon_id=None if user_id else _anon_id_from_request(request),
        title_id=tid,
        quality=body.quality.value,
        device=(body.device.dict(exclude_none=True) if body.device else {}),
        playback={
            "type": body.playback_type or "stream",
            "position_sec": body.position_sec or 0.0,
            "ip": get_client_ip(request),
            "ua": request.headers.get("user-agent") or request.headers.get("User-Agent"),
            "network": body.network.dict(exclude_none=True) if body.network else {},
        },
    )
    return json_no_store(StartSessionResponse(**{
        "id": rec["id"],
        "title_id": rec["title_id"],
        "user_id": rec.get("user_id"),
        "anon_id": rec.get("anon_id"),
        "created_at": rec["created_at"],
        "status": rec["status"],
    }).dict(), status_code=201)


@router.post("/{session_id}/heartbeat", status_code=202)
def heartbeat(session_id: str = Path(...), body: HeartbeatInput = ..., _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Send playback heartbeat with QoE metrics. Returns 202."""
    repo = get_player_repository()
    if not repo.heartbeat(session_id, body.dict(exclude_none=True)):
        raise HTTPException(status_code=404, detail="Session not found")
    return Response(status_code=202)


@router.post("/{session_id}/pause", status_code=202)
def pause(session_id: str = Path(...), body: HeartbeatInput = ..., _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Record a pause event (with position). Returns 202."""
    repo = get_player_repository()
    payload: Dict = body.dict(exclude_none=True)
    payload["event"] = "pause"
    payload["playing"] = False
    if not repo.append_event(session_id, "pause", payload):
        raise HTTPException(status_code=404, detail="Session not found")
    return Response(status_code=202)


@router.post("/{session_id}/resume", status_code=202)
def resume(session_id: str = Path(...), body: HeartbeatInput = ..., _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Record a resume event (with position). Returns 202."""
    repo = get_player_repository()
    payload: Dict = body.dict(exclude_none=True)
    payload["event"] = "resume"
    payload["playing"] = True
    if not repo.append_event(session_id, "resume", payload):
        raise HTTPException(status_code=404, detail="Session not found")
    return Response(status_code=202)


@router.post("/{session_id}/seek", status_code=202)
def seek(session_id: str = Path(...), body: SeekInput = ..., _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Record a seek event."""
    repo = get_player_repository()
    if not repo.append_event(session_id, "seek", body.dict(exclude_none=True)):
        raise HTTPException(status_code=404, detail="Session not found")
    return Response(status_code=202)


@router.post("/{session_id}/complete", status_code=202)
def complete(session_id: str = Path(...), body: CompleteInput = ..., _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Mark a playback session as completed (aggregates final stats)."""
    repo = get_player_repository()
    if not repo.complete(session_id, body.dict(exclude_none=True)):
        raise HTTPException(status_code=404, detail="Session not found")
    return Response(status_code=202)


@router.post("/{session_id}/error", status_code=202)
def error(session_id: str = Path(...), body: ErrorInput = ..., _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Report a player error (kept on session as last_error). Returns 202."""
    repo = get_player_repository()
    if not repo.append_event(session_id, "error", body.dict(exclude_none=True)):
        raise HTTPException(status_code=404, detail="Session not found")
    return Response(status_code=202)


@router.get("/{session_id}", response_model=SessionSummary)
def get_session(session_id: str = Path(...), _rl=Depends(rate_limit), _key=Depends(enforce_public_api_key)):
    """Return a playback session summary (no-store)."""
    repo = get_player_repository()
    rec = repo.get_session(session_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Session not found")
    return json_no_store(SessionSummary(**rec).dict())

