from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, conint, confloat, constr
from app.services.signing import QualityEnum


class DeviceInfo(BaseModel):
    platform: Optional[constr(strip_whitespace=True, max_length=32)] = None
    os_name: Optional[constr(strip_whitespace=True, max_length=32)] = None
    os_version: Optional[constr(strip_whitespace=True, max_length=64)] = None
    model: Optional[constr(strip_whitespace=True, max_length=64)] = None
    app_version: Optional[constr(strip_whitespace=True, max_length=64)] = None
    sdk_version: Optional[constr(strip_whitespace=True, max_length=64)] = None


class NetworkInfo(BaseModel):
    type: Optional[constr(strip_whitespace=True, max_length=16)] = Field(None, description="wifi|cellular|ethernet|unknown")
    down_kbps: Optional[conint(ge=0)] = None
    up_kbps: Optional[conint(ge=0)] = None
    rtt_ms: Optional[conint(ge=0)] = None


class StartSessionInput(BaseModel):
    title_id: constr(strip_whitespace=True, min_length=1, max_length=128)
    quality: QualityEnum = QualityEnum.auto
    playback_type: Optional[constr(strip_whitespace=True, max_length=16)] = Field("stream", description="stream|download")
    position_sec: Optional[confloat(ge=0.0)] = 0.0
    device: Optional[DeviceInfo] = None
    network: Optional[NetworkInfo] = None


class StartSessionResponse(BaseModel):
    id: str
    title_id: str
    user_id: Optional[str] = None
    anon_id: Optional[str] = None
    created_at: int
    status: str


class HeartbeatInput(BaseModel):
    position_sec: confloat(ge=0.0)
    buffered_sec: Optional[confloat(ge=0.0)] = None
    bitrate_kbps: Optional[conint(ge=0)] = None
    dropped_frames: Optional[conint(ge=0)] = 0
    playing: Optional[bool] = True
    volume: Optional[confloat(ge=0.0, le=1.0)] = None
    muted: Optional[bool] = None
    fullscreen: Optional[bool] = None
    width: Optional[conint(ge=1, le=16384)] = None
    height: Optional[conint(ge=1, le=16384)] = None
    stall_count: Optional[conint(ge=0)] = 0
    rebuffer_duration_ms: Optional[conint(ge=0)] = 0
    cdn_node: Optional[constr(strip_whitespace=True, max_length=128)] = None


class SeekInput(BaseModel):
    from_sec: confloat(ge=0.0)
    to_sec: confloat(ge=0.0)


class CompleteInput(BaseModel):
    position_sec: confloat(ge=0.0)
    duration_sec: Optional[confloat(ge=0.0)] = None
    watched_sec: Optional[confloat(ge=0.0)] = None


class ErrorInput(BaseModel):
    code: constr(strip_whitespace=True, min_length=1, max_length=64)
    message: constr(strip_whitespace=True, min_length=1, max_length=2000)
    fatal: Optional[bool] = False
    position_sec: Optional[confloat(ge=0.0)] = None


class SessionSummary(BaseModel):
    id: str
    title_id: str
    user_id: Optional[str] = None
    anon_id: Optional[str] = None
    created_at: int
    updated_at: int
    status: str
    last_position_sec: float
    last_bitrate_kbps: Optional[int] = None
    rebuffer_count: int
    rebuffer_ms_total: int
    dropped_frames_total: int
    watched_sec: float
    last_error: Optional[Dict[str, Any]] = None
    device: Optional[Dict[str, Any]] = None
    playback: Optional[Dict[str, Any]] = None

