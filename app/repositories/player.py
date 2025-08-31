from __future__ import annotations
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


class PlayerRepositoryProtocol:
    def start_session(self, *, user_id: Optional[str], anon_id: Optional[str], title_id: str, quality: str, device: Dict[str, Any], playback: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def append_event(self, session_id: str, event_type: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def heartbeat(self, session_id: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def complete(self, session_id: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raise NotImplementedError


@dataclass
class _PlayerSession:
    id: str
    user_id: Optional[str] = None
    anon_id: Optional[str] = None
    title_id: str = ""
    quality: str = "auto"
    created_at: int = 0
    updated_at: int = 0
    status: str = "started"  # started|playing|paused|completed|error
    last_position_sec: float = 0.0
    last_bitrate_kbps: Optional[int] = None
    rebuffer_count: int = 0
    rebuffer_ms_total: int = 0
    dropped_frames_total: int = 0
    watched_sec: float = 0.0
    last_error: Optional[Dict[str, Any]] = None
    device: Dict[str, Any] = field(default_factory=dict)
    playback: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)


class MemoryPlayerRepository(PlayerRepositoryProtocol):
    def __init__(self) -> None:
        self._sessions: Dict[str, _PlayerSession] = {}

    def _now(self) -> int:
        return int(time.time())

    def _ensure(self, session_id: str) -> Optional[_PlayerSession]:
        return self._sessions.get(session_id)

    def start_session(self, *, user_id: Optional[str], anon_id: Optional[str], title_id: str, quality: str, device: Dict[str, Any], playback: Dict[str, Any]) -> Dict[str, Any]:
        sid = uuid.uuid4().hex
        now = self._now()
        sess = _PlayerSession(
            id=sid,
            user_id=user_id,
            anon_id=anon_id,
            title_id=title_id,
            quality=quality,
            created_at=now,
            updated_at=now,
            status="started",
            device=device,
            playback=playback,
        )
        sess.events.append({"type": "start", "at": now, "payload": {"quality": quality}})
        self._sessions[sid] = sess
        return self._to_dict(sess)

    def _to_dict(self, s: _PlayerSession) -> Dict[str, Any]:
        return {
            "id": s.id,
            "user_id": s.user_id,
            "anon_id": s.anon_id,
            "title_id": s.title_id,
            "quality": s.quality,
            "created_at": s.created_at,
            "updated_at": s.updated_at,
            "status": s.status,
            "last_position_sec": s.last_position_sec,
            "last_bitrate_kbps": s.last_bitrate_kbps,
            "rebuffer_count": s.rebuffer_count,
            "rebuffer_ms_total": s.rebuffer_ms_total,
            "dropped_frames_total": s.dropped_frames_total,
            "watched_sec": s.watched_sec,
            "last_error": s.last_error,
            "device": s.device,
            "playback": s.playback,
            "events": list(s.events[-200:]),  # cap
        }

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        s = self._ensure(session_id)
        return self._to_dict(s) if s else None

    def append_event(self, session_id: str, event_type: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        s = self._ensure(session_id)
        if not s:
            return None
        now = self._now()
        s.updated_at = now
        s.events.append({"type": event_type, "at": now, "payload": payload})
        # Cap events list
        if len(s.events) > 500:
            s.events = s.events[-400:]
        return self._to_dict(s)

    def heartbeat(self, session_id: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        s = self._ensure(session_id)
        if not s:
            return None
        now = self._now()
        s.updated_at = now
        s.status = "playing" if payload.get("playing", True) else s.status
        # Aggregate stats
        pos = float(payload.get("position_sec", s.last_position_sec))
        if pos >= s.last_position_sec:
            s.watched_sec += (pos - s.last_position_sec)
        s.last_position_sec = pos
        if payload.get("bitrate_kbps") is not None:
            s.last_bitrate_kbps = int(payload["bitrate_kbps"])  # type: ignore
        s.dropped_frames_total += int(payload.get("dropped_frames", 0))
        s.rebuffer_count += int(payload.get("stall_count", 0))
        s.rebuffer_ms_total += int(payload.get("rebuffer_duration_ms", 0))
        s.events.append({"type": "heartbeat", "at": now, "payload": payload})
        if len(s.events) > 500:
            s.events = s.events[-400:]
        return self._to_dict(s)

    def complete(self, session_id: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        s = self._ensure(session_id)
        if not s:
            return None
        now = self._now()
        s.updated_at = now
        s.status = "completed"
        # Final position and watched time
        pos = float(payload.get("position_sec", s.last_position_sec))
        if pos >= s.last_position_sec:
            s.watched_sec += (pos - s.last_position_sec)
        s.last_position_sec = pos
        s.events.append({"type": "complete", "at": now, "payload": payload})
        if len(s.events) > 500:
            s.events = s.events[-400:]
        return self._to_dict(s)


def _import_string(path: str):
    module_path, _, class_name = path.partition(":")
    if not module_path or not class_name:
        raise ValueError("PLAYER_REPOSITORY_IMPL must be 'module.sub:ClassName'")
    module = __import__(module_path, fromlist=[class_name])
    return getattr(module, class_name)


def get_player_repository() -> PlayerRepositoryProtocol:
    impl_path = os.environ.get("PLAYER_REPOSITORY_IMPL")
    if impl_path:
        cls = _import_string(impl_path)
        return cls()  # type: ignore
    return MemoryPlayerRepository()

